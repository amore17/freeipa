from __future__ import absolute_import

import time
import pytest
import re
import uuid
import base64
import hashlib

import textwrap
import requests
from datetime import datetime, timedelta, timezone
from msal import ConfidentialClientApplication
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks, create_keycloak

GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
USER_READ_ALL_ROLE_ID = "df021288-bdef-4463-88db-98f22de89214"

IDP_PROVIDER_CONFIGS = [
    ('google', 'googleidp', [], {
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
        'dev_auth_uri': 'https://oauth2.googleapis.com/device/code',
        'token_uri': 'https://oauth2.googleapis.com/token',
    }),
    ('github', 'githubidp', [], {
        'auth_uri': 'https://github.com/login/oauth/authorize',
        'dev_auth_uri': 'https://github.com/login/device/code',
        'token_uri': 'https://github.com/login/oauth/access_token',
    }),
    ('microsoft', 'microsoftidp', ['--org=common'], {
        'auth_uri': 'https://login.microsoftonline.com/common/oauth2/v2.0/'
                    'authorize',
        'dev_auth_uri': 'https://login.microsoftonline.com/common/oauth2/'
                        'v2.0/devicecode',
        'token_uri': 'https://login.microsoftonline.com/common/oauth2/v2.0/'
                     'token',
    }),
    ('okta', 'oktaidp', ['--base-url=okta.example.com'], {
        'auth_uri': 'https://okta.example.com/oauth2/v1/authorize',
        'dev_auth_uri': 'https://okta.example.com/oauth2/v1/device/authorize',
        'token_uri': 'https://okta.example.com/oauth2/v1/token',
    }),
]

user_code_script = textwrap.dedent("""
from selenium import webdriver
from datetime import datetime
from packaging.version import parse as parse_version
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
options = Options()
if  parse_version(webdriver.__version__) < parse_version('4.10.0'):
    options.headless = True
    driver = webdriver.Firefox(executable_path="/opt/geckodriver",
                               options=options)
else:
    options.add_argument('-headless')
    service = webdriver.FirefoxService(
        executable_path="/opt/geckodriver")
    driver = webdriver.Firefox(options=options, service=service)

verification_uri = "{uri}"
driver.get(verification_uri)
try:
    element = WebDriverWait(driver, 90).until(
        EC.presence_of_element_located((By.ID, "username")))
    driver.find_element(By.ID, "username").send_keys("testuser1")
    driver.find_element(By.ID, "password").send_keys("{passwd}")
    driver.find_element(By.ID, "kc-login").click()
    element = WebDriverWait(driver, 90).until(
        EC.presence_of_element_located((By.ID, "kc-login")))
    driver.find_element(By.ID, "kc-login").click()
    assert "Device Login Successful" in driver.page_source
finally:
    now = datetime.now().strftime("%M-%S")
    driver.get_screenshot_as_file("/var/log/httpd/screenshot-%s.png" % now)
    driver.quit()
""")

azure_user_code_script = textwrap.dedent("""
from selenium import webdriver
from datetime import datetime
from packaging.version import parse as parse_version
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
options = Options()
if  parse_version(webdriver.__version__) < parse_version('4.10.0'):
    options.headless = True
    driver = webdriver.Firefox(executable_path="/opt/geckodriver",
                               options=options)
else:
    options.add_argument('-headless')
    service = webdriver.FirefoxService(
        executable_path="/opt/geckodriver")
    driver = webdriver.Firefox(options=options, service=service)

verification_uri = "{uri}"
driver.get(verification_uri)
try:
    # Click through the device code confirmation page if present
    try:
        btn = WebDriverWait(driver, 15).until(
            EC.element_to_be_clickable((By.ID, "idSIButton9")))
        btn.click()
    except Exception:
        pass
    # Enter email/username on Microsoft login page
    element = WebDriverWait(driver, 90).until(
        EC.presence_of_element_located((By.NAME, "loginfmt")))
    driver.find_element(By.NAME, "loginfmt").send_keys("{username}")
    driver.find_element(By.ID, "idSIButton9").click()
    # Enter password
    element = WebDriverWait(driver, 90).until(
        EC.element_to_be_clickable((By.NAME, "passwd")))
    driver.find_element(By.NAME, "passwd").send_keys("{password}")
    driver.find_element(By.ID, "idSIButton9").click()
    # Handle remaining prompts (consent / stay signed in)
    for _ in range(3):
        try:
            btn = WebDriverWait(driver, 15).until(
                EC.element_to_be_clickable((By.ID, "idSIButton9")))
            btn.click()
            time.sleep(2)
        except Exception:
            break
    time.sleep(5)
finally:
    now = datetime.now().strftime("%M-%S")
    driver.get_screenshot_as_file("/var/log/httpd/scrnshot-azure-%s.png" % now)
    driver.quit()
""")


def add_user_code(host, verification_uri):
    contents = user_code_script.format(uri=verification_uri,
                                       passwd=host.config.admin_password)
    try:
        host.put_file_contents("/tmp/add_user_code.py", contents)
        tasks.run_repeatedly(
            host, ['python3', '/tmp/add_user_code.py'])
    finally:
        host.run_command(["rm", "-f", "/tmp/add_user_code.py"])


def kinit_idp(host, user, keycloak_server):
    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    host.run_command(["kinit", "-n", "-c", ARMOR])
    cmd = ["kinit", "-T", ARMOR, user]

    with host.spawn_expect(cmd, default_timeout=100) as e:
        e.expect('Authenticate at (.+) and press ENTER.:')
        prompt = e.get_last_output()
        uri = re.search(r'Authenticate at (.*?) and press ENTER.:', prompt
                        ).group(1)
        time.sleep(15)
        if uri:
            add_user_code(keycloak_server, uri)
        e.sendline('\n')
        e.expect_exit()

    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


def add_azure_user_code(host, verification_uri, username, password):
    contents = azure_user_code_script.format(
        uri=verification_uri,
        username=username,
        password=password,
    )
    try:
        host.put_file_contents("/tmp/add_azure_user_code.py", contents)
        tasks.run_repeatedly(
            host, ['python3', '/tmp/add_azure_user_code.py'])
    finally:
        host.run_command(["rm", "-f", "/tmp/add_azure_user_code.py"])


def kinit_azure_idp(host, user, azure_email, azure_password):
    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    host.run_command(["kinit", "-n", "-c", ARMOR])
    cmd = ["kinit", "-T", ARMOR, user]

    with host.spawn_expect(cmd, default_timeout=100) as e:
        e.expect('Authenticate at (.+) and press ENTER.:')
        prompt = e.get_last_output()
        uri = re.search(
            r'Authenticate at (.*?) and press ENTER.:', prompt
        ).group(1)
        time.sleep(15)
        if uri:
            add_azure_user_code(host, uri, azure_email, azure_password)
        e.sendline('\n')
        e.expect_exit()

    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


class TestIDPKeycloak(IntegrationTest):

    num_replicas = 2
    topology = 'line'

    AZURE_IDP_NAME = "amoreidp"
    AZURE_IPA_USERNAME = "testazure"

    @classmethod
    def install(cls, mh):
        cls.client = cls.replicas[0]
        cls.replica = cls.replicas[1]
        tasks.install_master(cls.master, extra_args=['--no-dnssec-validation'])
        tasks.install_client(cls.master, cls.replicas[0],
                             extra_args=["--mkhomedir"])
        tasks.install_replica(cls.master, cls.replicas[1])
        for host in [cls.master, cls.replicas[0], cls.replicas[1]]:
            content = host.get_file_contents(paths.IPA_DEFAULT_CONF,
                                             encoding='utf-8')
            new_content = content + "\noidc_child_debug_level = 10"
            host.put_file_contents(paths.IPA_DEFAULT_CONF, new_content)
        with tasks.remote_sssd_config(cls.master) as sssd_config:
            sssd_config.edit_domain(
                cls.master.domain, 'krb5_auth_timeout', 1100)
        tasks.clear_sssd_cache(cls.master)
        tasks.clear_sssd_cache(cls.replicas[0])
        tasks.kinit_admin(cls.master)
        cls.master.run_command(["ipa", "config-mod", "--user-auth-type=idp",
                                "--user-auth-type=password"])
        xvfb = ("nohup /usr/bin/Xvfb :99 -ac -noreset -screen 0 1400x1200x8 "
                "</dev/null &>/dev/null &")
        cls.replicas[0].run_command(xvfb)
        cls.setup_azure()

    @classmethod
    def setup_azure(cls):
        cfg = cls.master.config
        cls.azure_tenant_id = cfg.azure_tenant_id
        cls.azure_admin_client_id = cfg.azure_admin_client_id
        cls.azure_admin_client_secret = cfg.azure_admin_client_secret
        cls.azure_domain = cfg.azure_domain
        cls.authority = (
            f"https://login.microsoftonline.com/{cls.azure_tenant_id}"
        )

        cls.admin_token = cls._azure_get_admin_token()
        cls.azure_username, cls.azure_password = (
            cls._azure_create_user(cls.admin_token)
        )
        cls.group_id = cls._azure_get_or_create_group(
            cls.admin_token, "automation"
        )
        cls._azure_add_user_to_group(
            cls.admin_token, cls.azure_username, cls.group_id
        )
        cls.app_data = cls._azure_create_app(cls.admin_token)
        cls.sp_data = cls._azure_create_service_principal(
            cls.admin_token, cls.app_data["appId"]
        )
        cls.private_key_pem, cls.cert_der_bytes, cls.thumbprint = (
            cls._azure_generate_certificate()
        )
        cls._azure_upload_certificate(
            cls.admin_token, cls.app_data["id"], cls.cert_der_bytes
        )
        cls.sp_token = cls._azure_authenticate_sp(
            cls.app_data["appId"], cls.private_key_pem, cls.thumbprint
        )

    @classmethod
    def _azure_get_admin_token(cls):
        app = ConfidentialClientApplication(
            client_id=cls.azure_admin_client_id,
            client_credential=cls.azure_admin_client_secret,
            authority=cls.authority,
        )
        token = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        if "access_token" not in token:
            raise Exception(f"Failed to get admin token: {token}")
        return token["access_token"]

    @classmethod
    def _azure_create_user(cls, access_token):
        url = "https://graph.microsoft.com/v1.0/users"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        unique_id = uuid.uuid4().hex[:6]
        user_principal_name = f"user{unique_id}@{cls.azure_domain}"
        password = "TempPassword123!"

        payload = {
            "accountEnabled": True,
            "displayName": f"Automation User {unique_id}",
            "mailNickname": f"user{unique_id}",
            "userPrincipalName": user_principal_name,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": password,
            },
        }

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return user_principal_name, password

    @staticmethod
    def _azure_get_or_create_group(access_token, group_name="automation"):
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        url = (
            "https://graph.microsoft.com/v1.0/groups"
            f"?$filter=displayName eq '{group_name}'"
        )
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data["value"]:
            return data["value"][0]["id"]

        payload = {
            "displayName": group_name,
            "mailNickname": group_name.replace(" ", ""),
            "mailEnabled": False,
            "securityEnabled": True,
        }

        response = requests.post(
            "https://graph.microsoft.com/v1.0/groups",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()["id"]

    @staticmethod
    def _azure_add_user_to_group(access_token, user_principal_name, group_id):
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }


        url = f"https://graph.microsoft.com/v1.0/users/{user_principal_name}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        user_id = response.json()["id"]

        url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
        payload = {
            "@odata.id": (
                f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
            )
        }

        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 204:
            return
        if (
            response.status_code == 400
            and "added object references already exist" in response.text
        ):
            return
        response.raise_for_status()

    @staticmethod
    def _azure_create_app(access_token):
        url = "https://graph.microsoft.com/v1.0/applications"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        display_name = f"auto-app-{uuid.uuid4().hex[:6]}"
        payload = {"displayName": display_name, "signInAudience": "AzureADMyOrg"}

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _azure_create_service_principal(access_token, app_id):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        payload = {"appId": app_id}

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _azure_generate_certificate():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "auto-app-cert")]
        )

        now = datetime.now(timezone.utc) - timedelta(minutes=5)
        end = now + timedelta(days=365)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(uuid.uuid4().int >> 64)
            .not_valid_before(now)
            .not_valid_after(end)
            .sign(key, hashes.SHA256())
        )

        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        cert_der_bytes = cert.public_bytes(serialization.Encoding.DER)
        thumbprint = hashlib.sha1(cert_der_bytes).digest().hex()

        return private_key_pem, cert_der_bytes, thumbprint

    @staticmethod
    def _azure_upload_certificate(access_token, app_object_id, cert_der_bytes):
        # PATCH keyCredentials instead of /addKey because the latter requires
        # a proof-of-possession JWT signed with an existing key.
        url = f"https://graph.microsoft.com/v1.0/applications/{app_object_id}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "keyCredentials": [
                {
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "key": base64.b64encode(cert_der_bytes).decode(),
                    "displayName": "auto-app-cert",
                }
            ]
        }

        response = requests.patch(url, json=payload, headers=headers)
        response.raise_for_status()

    @staticmethod
    def _azure_grant_api_permissions(access_token, sp_object_id):
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"?$filter=appId eq '{MS_GRAPH_APP_ID}'"
        )
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        graph_sp = response.json()["value"][0]

        url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"/{sp_object_id}/appRoleAssignments"
        )
        payload = {
            "principalId": sp_object_id,
            "resourceId": graph_sp["id"],
            "appRoleId": USER_READ_ALL_ROLE_ID,
        }
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()

    @classmethod
    def _azure_authenticate_sp(cls, client_id, private_key_pem, thumbprint):
        app = ConfidentialClientApplication(
            client_id=client_id,
            authority=cls.authority,
            client_credential={
                "private_key": private_key_pem,
                "thumbprint": thumbprint,
            },
        )
        token = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        if "access_token" not in token:
            raise Exception(f"Failed to authenticate SP: {token}")
        return token["access_token"]

    def test_auth_keycloak_idp(self):
        """
        Test case to check that OAuth 2.0 Device
        Authorization Grant is working as
        expected for user configured with external idp.
        """
        create_keycloak.setup_keycloakserver(self.client)
        time.sleep(60)
        create_keycloak.setup_keycloak_client(self.client)
        tasks.kinit_admin(self.master)
        cmd = ["ipa", "idp-add", "keycloakidp", "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))
        tasks.user_add(self.master, 'keycloakuser',
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user-id=testuser1@ipa.test",
                                   "--idp=keycloakidp"]
                       )
        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test"]
        )
        assert "keycloakuser" in list_user.stdout_text
        list_by_idp = self.master.run_command(["ipa", "user-find",
                                               "--idp=keycloakidp"]
                                              )
        assert "keycloakuser" in list_by_idp.stdout_text
        list_by_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test", "--all"]
        )
        assert "keycloakidp" in list_by_user.stdout_text
        tasks.clear_sssd_cache(self.master)
        kinit_idp(self.master, 'keycloakuser', keycloak_server=self.client)

    @pytest.fixture
    def hbac_setup_teardown(self):
        # allow sshd only on given host
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-add", "rule1"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule1",
                                 "--users=keycloakuser"]
                                )
        self.master.run_command(["ipa", "hbacrule-add-host", "rule1",
                                 "--hosts", self.replica.hostname])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule1",
                                 "--hbacsvcs=sshd"]
                                )
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.replica)
        yield

        # cleanup
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-enable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-del", "rule1"])

    def test_auth_hbac(self, hbac_setup_teardown):
        """
        Test case to check that hbacrule is working as
        expected for user configured with external idp.
        """
        kinit_idp(self.master, 'keycloakuser', keycloak_server=self.client)
        ssh_cmd = "ssh -q -K -l keycloakuser {0} whoami"
        valid_ssh = self.master.run_command(
            ssh_cmd.format(self.replica.hostname))
        assert "keycloakuser" in valid_ssh.stdout_text
        negative_ssh = self.master.run_command(
            ssh_cmd.format(self.master.hostname), raiseonerr=False
        )
        assert negative_ssh.returncode == 255

    def test_auth_sudo_idp(self):
        """
        Test case to check that sudorule is working as
        expected for user configured with external idp.
        """
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)
        #  rule: keycloakuser are allowed to execute yum on
        #  the client machine as root.
        cmdlist = [
            ["ipa", "sudocmd-add", "/usr/bin/yum"],
            ["ipa", "sudorule-add", "sudorule"],
            ['ipa', 'sudorule-add-user', '--users=keycloakuser',
             'sudorule'],
            ['ipa', 'sudorule-add-host', '--hosts',
             self.client.hostname, 'sudorule'],
            ['ipa', 'sudorule-add-runasuser',
             '--users=root', 'sudorule'],
            ['ipa', 'sudorule-add-allow-command',
             '--sudocmds=/usr/bin/yum', 'sudorule'],
            ['ipa', 'sudorule-show', 'sudorule', '--all'],
            ['ipa', 'sudorule-add-option',
             'sudorule', '--sudooption', "!authenticate"]
        ]
        for cmd in cmdlist:
            self.master.run_command(cmd)
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.client)
        try:
            cmd = 'sudo -ll -U keycloakuser'
            test = self.client.run_command(cmd).stdout_text
            assert "User keycloakuser may run the following commands" in test
            assert "/usr/bin/yum" in test
            kinit_idp(self.client, 'keycloakuser', self.client)
            test_sudo = 'su -c "sudo yum list sssd-client" keycloakuser'
            self.client.run_command(test_sudo)
            list_fail = self.master.run_command(cmd).stdout_text
            assert "User keycloakuser is not allowed to run sudo" in list_fail
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'sudorule-del', 'sudorule'])
            self.master.run_command(["ipa", "sudocmd-del", "/usr/bin/yum"])

    def test_auth_replica(self):
        """
        Test case to check that OAuth 2.0 Device
        Authorization is working as expected on replica.
        """
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.replica)
        tasks.kinit_admin(self.replica)
        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test"]
        )
        assert "keycloakuser" in list_user.stdout_text
        list_by_idp = self.replica.run_command(["ipa", "user-find",
                                                "--idp=keycloakidp"]
                                               )
        assert "keycloakuser" in list_by_idp.stdout_text
        list_by_user = self.replica.run_command(
            ["ipa", "user-find", "--idp-user-id=testuser1@ipa.test", "--all"]
        )
        assert "keycloakidp" in list_by_user.stdout_text
        kinit_idp(self.replica, 'keycloakuser', keycloak_server=self.client)

    def test_idp_with_services(self):
        """
        Test case to check that services can be configured
        auth indicator as idp.
        """
        tasks.clear_sssd_cache(self.master)
        tasks.kinit_admin(self.master)
        domain = self.master.domain.name.upper()
        services = [
            "DNS/{0}@{1}".format(self.master.hostname, domain),
            "HTTP/{0}@{1}".format(self.client.hostname, domain),
            "dogtag/{0}@{1}".format(self.master.hostname, domain),
            "ipa-dnskeysyncd/{0}@{1}".format(self.master.hostname, domain)
        ]
        try:
            for service in services:
                test = self.master.run_command(["ipa", "service-mod", service,
                                                "--auth-ind=idp"]
                                               )
                assert "Authentication Indicators: idp" in test.stdout_text
        finally:
            for service in services:
                self.master.run_command(["ipa", "service-mod", service,
                                         "--auth-ind="])

    def test_idp_backup_restore(self):
        """
        Test case to check that after restore data is retrieved
        with related idp configuration.
        """
        tasks.kinit_admin(self.master)
        user = "backupuser"
        cmd = ["ipa", "idp-add", "testidp", "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))

        tasks.user_add(self.master, user,
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user-id=testuser1@ipa.test",
                                   "--idp=testidp"]
                       )

        backup_path = tasks.get_backup_dir(self.master)
        # change data after backup
        self.master.run_command(['ipa', 'user-del', user])
        self.master.run_command(['ipa', 'idp-del', 'testidp'])
        dirman_password = self.master.config.dirman_password
        self.master.run_command(['ipa-restore', backup_path],
                                stdin_text=dirman_password + '\nyes')
        try:
            list_user = self.master.run_command(
                ['ipa', 'user-show', 'backupuser', '--all']
            ).stdout_text
            assert "External IdP configuration: testidp" in list_user
            assert "User authentication types: idp" in list_user
            assert ("External IdP user identifier: "
                    "testuser1@ipa.test") in list_user
            list_idp = self.master.run_command(['ipa', 'idp-find', 'testidp'])
            assert "testidp" in list_idp.stdout_text
            kinit_idp(self.master, user, self.client)
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(["rm", "-rf", backup_path])
            self.master.run_command(["ipa", "idp-del", "testidp"])

    def test_azure_idp_add_and_user(self):
        """
        Add Azure IDP with Microsoft provider and associate user with mail id.

        Uses ipa idp-add with --provider microsoft, --organization (tenant ID),
        --client-id, and --secret from stdin. Then adds IPA user linked to
        the IdP with idp-user-id set to the user's email.
        """
        tasks.kinit_admin(self.master)
        idp_add_cmd = [
            "ipa", "idp-add", self.AZURE_IDP_NAME,
            "--provider", "microsoft",
            "--organization", self.azure_tenant_id,
            "--client-id", self.azure_admin_client_id,
            "--secret",
        ]
        self.master.run_command(
            idp_add_cmd,
            stdin_text=self.azure_admin_client_secret + "\n"
        )

        result = self.master.run_command(
            ["ipa", "idp-show", self.AZURE_IDP_NAME]
        )
        assert self.AZURE_IDP_NAME in result.stdout_text
        assert "login.microsoftonline.com" in result.stdout_text

        tasks.user_add(
            self.master,
            self.AZURE_IPA_USERNAME,
            first="Amore",
            last="User",
            extra_args=[
                "--user-auth-type=idp",
                "--idp-user-id=" + self.azure_username,
                "--idp=" + self.AZURE_IDP_NAME,
            ],
        )

        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=" + self.azure_username]
        )
        assert self.AZURE_IPA_USERNAME in list_user.stdout_text

        list_by_idp = self.master.run_command(
            ["ipa", "user-find", "--idp=" + self.AZURE_IDP_NAME]
        )
        assert self.AZURE_IPA_USERNAME in list_by_idp.stdout_text

        user_show = self.master.run_command(
            ["ipa", "user-show", self.AZURE_IPA_USERNAME, "--all"]
        )
        assert self.AZURE_IDP_NAME in user_show.stdout_text
        assert self.azure_username in user_show.stdout_text

    def test_azure_idp_kinit(self):
        """
        Full OAuth 2.0 Device Authorization Grant kinit with Azure IdP.

        Performs kinit with FAST armor for the IdP-configured user and
        automates the Microsoft login page via headless Selenium to
        complete the device code flow end-to-end.  Verifies the
        resulting ticket carries the IdP authentication indicator (152).
        """
        tasks.clear_sssd_cache(self.master)
        kinit_azure_idp(
            self.master,
            self.AZURE_IPA_USERNAME,
            self.azure_username,
            self.azure_password,
        )

    @pytest.mark.parametrize("provider,name,extra_args,expected_endpoints",
                            IDP_PROVIDER_CONFIGS)
    def test_idp_provider_config(self, provider, name, extra_args,
                                 expected_endpoints):
        """
        Verify that each provider template creates correct IdP configuration
        and users can be associated with the IdP.
        """
        # Provider templates that can be tested without external OAuth credentials.
        # Keycloak is tested separately in TestIDPKeycloak with full authentication.
        # Google, GitHub, Microsoft, Okta require external services - we only verify
        # that the IdP configuration is correctly created from provider templates.

        tasks.kinit_admin(self.master)
        idp_add_cmd = ["ipa", "idp-add", name, "--provider=" + provider,
                       "--client-id=test_client_id"]
        idp_add_cmd.extend(extra_args)
        self.master.run_command(idp_add_cmd, stdin_text="secret\nsecret")

        try:
            result = self.master.run_command(["ipa", "idp-show", name])
            stdout = result.stdout_text
            for key, expected in expected_endpoints.items():
                assert expected in stdout, (
                    "Expected {} in idp-show output: {}".format(expected, key)
                )

            # Verify user can be associated with this IdP
            user_name = "{}user".format(provider)
            idp_user_id = "user1@{}".format(provider)
            tasks.user_add(self.master, user_name,
                           extra_args=["--user-auth-type=idp",
                                       "--idp-user-id=" + idp_user_id,
                                       "--idp=" + name])

            list_user = self.master.run_command(
                ["ipa", "user-find", "--idp-user-id=" + idp_user_id])
            assert user_name in list_user.stdout_text

            list_by_idp = self.master.run_command(
                ["ipa", "user-find", "--idp=" + name])
            assert user_name in list_by_idp.stdout_text

            # Cleanup user
            self.master.run_command(["ipa", "user-del", user_name])
        finally:
            self.master.run_command(["ipa", "idp-del", name])




