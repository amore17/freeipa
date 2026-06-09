from __future__ import absolute_import

import os
import random
import re
import subprocess
import time
from datetime import datetime, timedelta

import pytest
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks, create_keycloak
from ipatests.pytest_ipa.integration.create_keycloak import (
    keycloak_create_cert_oidc_client,
    keycloak_delete_client,
    keycloak_ensure_kcadm_credentials,
    keycloak_openssl_cert_subject_dn,
    keycloak_pem_cert_der_b64,
    keycloak_set_https_client_auth,
    keycloak_truststore_delete_cert,
    keycloak_truststore_import_cert,
    keycloak_user_code_script,
)
from ipatests.pytest_ipa.integration import entraid_helpers
from ipatests.pytest_ipa.integration.entraid_helpers import (
    azure_acquire_graph_token,
    azure_graph_application_object_id,
    azure_multihost_config_missing_attrs,
    calling_test_name,
    entra_delete_uploaded_certs,
    entra_upload_client_cert,
    microsoft_issuer_url,
    new_idp_client_graph_cert_display_name,
    purge_entra_idp_test_client_certs,
    upload_idp_client_crt_to_entra_app,
)

DEVICE_AUTH_PROMPT_RE = re.compile(
    r'Authenticate(?:\s+with\s+PIN\s+(\S+))?'
    r'\s+at\s+(.+?)\s+and\s+press\s+ENTER\.:',
    re.DOTALL,
)


def wait_for_ipa_user_lookup_id(host, username, timeout=120):
    """
    Poll ``id <username>`` on *host* until NSS/SSSD resolves the IPA user
    (exit 0). Use before ``kinit`` on a replica/client where the principal
    may not be visible immediately after ``ipa user-add`` / cache refresh.
    """
    tasks.run_repeatedly(
        host,
        ["id", username],
        timeout=timeout,
    )


# Directory and openssl artifacts for Azure app-registration certificate tests.
IDP_CLIENT_OPENSSL_WORKDIR = "/tmp/idp-client-openssl"
IDP_CLIENT_P12_PASSWORD = "MyP12Password"
# Installed on master for ``ipa idp-add --client-cert-p12=...`` (JWT client).
IDP_CLIENT_P12_IPA_PATH = "/etc/ipa/idp-client.p12"
IDP_CLIENT_TLS_P12_IPA_PATH = "/etc/ipa/idp-client-tls.p12"
IDP_CLIENT_P12_NOPASS_IPA_PATH = "/etc/ipa/idp-client-nopass.p12"
IDP_CLIENT_AUTH_AUX_OC = "ipaidpclientauth"
# PR #8308 ``ipaserver/plugins/idp.py`` managed_permissions (ACI.txt).
IDP_PERM_READ_SERVER = "System: Read External IdP server"
IDP_PERM_READ_CLIENT_SECRET = (
    "System: Read External IdP server client secret"
)
# Custom privileges wrapping those permissions (``role-add-privilege`` names).
IDP_PRIV_READ_SERVER = "IdP integration read server"
IDP_PRIV_READ_CLIENT_SECRET = "IdP integration read client secret"
# Built-in privilege (Add/Mod/Del IdP, not full IPA admin).
IDP_PRIV_EXTERNAL_IDP_ADMIN = "External IdP server Administrators"
IDP_PERM_MODIFY_USER = "idpmodify"
IDP_PERM_ROLE_MODIFY = "idp-modify-admin"
IDP_PERM_USER_PASSWORD = "Secret123"
IDP_CLI_MUTUALLY_EXCLUSIVE_P12 = (
    "cannot use client_secret authentication and client-cert-p12-file"
)


def assert_idp_cli_error(stderr_text, *patterns):
    """Assert CLI stderr contains one of *patterns* (case-insensitive)."""
    text = (stderr_text or "").lower()
    for pattern in patterns:
        if pattern.lower() in text:
            return
    pytest.fail(
        "CLI stderr did not match any of %r:\n%s" % (patterns, stderr_text))


def ldap_output_has_attribute_value(ldap_text, attribute):
    """True if LDAP LDIF has a value line for *attribute*.

    Ignores ``# requesting`` comment lines.
    """
    attr_lower = attribute.lower()
    for line in ldap_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith(attr_lower + ":"):
            return True
    return False


def idp_ldap_dn(host, idp_name):
    """LDAP DN of an IdP reference entry."""
    return "cn=%s,cn=idp,%s" % (idp_name, host.domain.basedn)


def idp_ldap_entry_text(host, idp_name, ldap_host=None):
    """Directory Manager ldapsearch of an IdP entry.

    Optionally run on *ldap_host* instead of *host*.
    """
    ldap_host = ldap_host or host
    return tasks.ldapsearch_dm(
        ldap_host,
        idp_ldap_dn(host, idp_name),
        ["objectClass", "userPKCS12", "userCertificate;binary"],
        scope="base",
    ).stdout_text


def p12_passphrase_stdin(password=IDP_CLIENT_P12_PASSWORD):
    return "%s\n%s\n" % (password, password)


def generate_idp_client_openssl_bundle(
    host,
    workdir=IDP_CLIENT_OPENSSL_WORKDIR,
    *,
    p12_password=IDP_CLIENT_P12_PASSWORD,
):
    """
    On *host*, generate RSA key, CSR, self-signed certificate, and PKCS#12
    bundle using openssl (same steps as the Azure IdP client-cert workflows).

    The CSR/Cert subject CN defaults to
    ``ipa-oauth-client.<host.domain.name>`` (from *host*'s multihost domain).

    Produces ``idp-client.key``, ``idp-client.csr``, ``idp-client.crt``,
    ``idp-client.p12`` under *workdir*.

    Pass ``p12_password=""`` to create a PKCS#12 whose MAC and encryption
    passwords are empty (``openssl`` ``-passout pass:``).
    """
    cn = "ipa-oauth-client.%s" % host.domain.name
    host.run_command(["mkdir", "-p", workdir])
    key = os.path.join(workdir, "idp-client.key")
    csr = os.path.join(workdir, "idp-client.csr")
    crt = os.path.join(workdir, "idp-client.crt")
    p12 = os.path.join(workdir, "idp-client.p12")
    subj = "/CN=%s" % cn

    host.run_command(
        ["openssl", "genrsa", "-out", key, "2048"],
        cwd=workdir,
    )
    host.run_command(
        ["openssl", "req", "-new", "-key", key, "-out", csr, "-subj", subj],
        cwd=workdir,
    )
    host.run_command(
        [
            "openssl", "x509", "-req", "-days", "365",
            "-in", csr, "-signkey", key, "-out", crt,
        ],
        cwd=workdir,
    )
    if p12_password == "":
        passout_arg = ["-passout", "pass:"]
    else:
        passout_arg = ["-passout", "pass:%s" % p12_password]
    host.run_command(
        [
            "openssl", "pkcs12", "-export", "-out", p12,
            "-inkey", key, "-in", crt,
        ] + passout_arg,
        cwd=workdir,
    )
    return workdir


class TestIDP(IntegrationTest):
    """Common IdP integration test setup and helpers."""

    num_replicas = 2
    topology = 'line'

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

    @staticmethod
    def parse_device_auth_prompt(prompt):
        match = DEVICE_AUTH_PROMPT_RE.search(prompt)
        assert match is not None, prompt
        user_code = match.group(1)
        uri = match.group(2).strip()
        if user_code is not None:
            user_code = user_code.strip()
        return uri, user_code

    @staticmethod
    def run_remote_selenium(host, script, remote_basename, timeout=30):
        path = "/tmp/%s" % remote_basename
        try:
            host.put_file_contents(path, script)
            # run_repeatedly only times out between attempts; wrap the
            # script so a hung browser cannot block the test indefinitely.
            cmd = [
                "timeout", "--kill-after=15", str(timeout),
                "python3", path,
            ]
            tasks.run_repeatedly(host, cmd, timeout=timeout + 30)
        finally:
            host.run_command(["rm", "-f", path])

    @staticmethod
    def kinit_idp_device_flow(
        host, user, complete_device_auth, *, pre_complete_delay=15,
        expect_timeout=100,
    ):
        """
        kinit for users with --user-auth-type=idp: complete OAuth2 device
        code flow in a browser via ``complete_device_auth(uri, user_code)``.
        """
        armor = "/tmp/armor"
        tasks.kdestroy_all(host)
        host.run_command(["kinit", "-n", "-c", armor])
        cmd = ["kinit", "-T", armor, user]

        with host.spawn_expect(cmd, default_timeout=expect_timeout) as e:
            e.expect(DEVICE_AUTH_PROMPT_RE)
            prompt = e.get_last_output()
            uri, device_user_code = TestIDP.parse_device_auth_prompt(prompt)
            time.sleep(pre_complete_delay)
            if uri:
                complete_device_auth(uri, device_user_code)
            e.sendline('\n')
            e.expect_exit()

        test_idp = host.run_command(["klist", "-C"])
        assert "152" in test_idp.stdout_text


class TestIDPKeycloak(TestIDP):
    """Keycloak IdP integration tests."""

    KEYCLOAK_IDP_NAME = "keycloakidp"
    KEYCLOAK_USER = "keycloakuser"
    KEYCLOAK_IDP_USER_ID = "testuser1@ipa.test"
    BACKUP_RESTORE_USER = "backupmultiuser"
    # (cn, provider, extra ipa CLI args, substring expected in idp-show)
    BUILTIN_IDP_PROVIDER_SPECS = (
        ("idp-google", "google", [], "googleapis.com"),
        ("idp-github", "github", [], "github.com"),
        (
            "idp-microsoft", "microsoft",
            ["--organization", "00000000-0000-0000-0000-000000000001"],
            "microsoftonline.com",
        ),
        (
            "idp-okta", "okta",
            ["--org", "testorg", "--base-url", "dev-12345.okta.com"],
            "okta.com",
        ),
    )

    KEYCLOAK_JWT_IDP_NAME = "keycloakjwtidp"
    KEYCLOAK_TLS_IDP_NAME = "keycloaktlsidp"
    KEYCLOAK_JWT_USER = "keycloakjwtuser"
    KEYCLOAK_TLS_USER = "keycloaktlsuser"
    KEYCLOAK_JWT_CLIENT_ID = "ipa_oidc_jwt_client"
    KEYCLOAK_TLS_CLIENT_ID = "ipa_oidc_tls_client"
    KEYCLOAK_MTLS_TRUSTSTORE_ALIAS = "idp-client-mtls"
    XFAIL_SSSD_OIDC_CERT_AUTH = (
        "SSSD PR #8708: oidc_child private_key_jwt client auth "
        "https://github.com/SSSD/sssd/pull/8708"
    )

    def _ensure_keycloak_for_cert_tests(self):
        """Ensure Keycloak is running and ``kcadm`` is authenticated."""
        result = self.client.run_command(
            ["systemctl", "is-active", "keycloak"], raiseonerr=False)
        if result.returncode != 0:
            create_keycloak.setup_keycloakserver(self.client)
            tasks.run_repeatedly(
                self.client,
                ["systemctl", "is-active", "keycloak"],
                timeout=120,
            )
            create_keycloak.setup_keycloak_client(self.client)
        keycloak_ensure_kcadm_credentials(self.client)

    @staticmethod
    def add_keycloak_user_code(host, verification_uri):
        contents = keycloak_user_code_script.format(
            uri=verification_uri,
            passwd=host.config.admin_password,
        )
        TestIDP.run_remote_selenium(
            host, contents, "add_keycloak_user_code.py", timeout=120)

    @staticmethod
    def kinit_idp_keycloak(host, user, keycloak_server):
        """kinit via Keycloak device authorization flow."""
        def complete(uri, _device_user_code):
            TestIDPKeycloak.add_keycloak_user_code(keycloak_server, uri)

        TestIDP.kinit_idp_device_flow(host, user, complete)

    def secret_stdin(self):
        secret = self.client.config.admin_password
        return "%s\n%s\n" % (secret, secret)

    def _add_builtin_provider_idp(self, cn, provider, extra_cli_args=None):
        cmd = [
            "ipa", "idp-add", cn,
            "--provider", provider,
            "--client-id", "idp-backup-restore-client",
        ]
        if extra_cli_args:
            cmd.extend(extra_cli_args)
        self.master.run_command(cmd, stdin_text=self.secret_stdin())

    def test_auth_keycloak_idp(self):
        """
        Test case to check that OAuth 2.0 Device
        Authorization Grant is working as
        expected for user configured with external idp.
        """
        create_keycloak.setup_keycloakserver(self.client)
        tasks.run_repeatedly(
            self.client,
            ["systemctl", "is-active", "keycloak"],
            timeout=120,
        )
        create_keycloak.setup_keycloak_client(self.client)
        tasks.kinit_admin(self.master)
        cmd = ["ipa", "idp-add", self.KEYCLOAK_IDP_NAME,
               "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))
        tasks.user_add(
            self.master, self.KEYCLOAK_USER,
            extra_args=["--user-auth-type=idp",
                        "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                        "--idp=" + self.KEYCLOAK_IDP_NAME]
        )
        list_user = self.master.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID]
        )
        assert self.KEYCLOAK_USER in list_user.stdout_text
        list_by_idp = self.master.run_command(
            ["ipa", "user-find", "--idp=" + self.KEYCLOAK_IDP_NAME])
        assert self.KEYCLOAK_USER in list_by_idp.stdout_text
        list_by_user = self.master.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID, "--all"]
        )
        assert self.KEYCLOAK_IDP_NAME in list_by_user.stdout_text
        tasks.clear_sssd_cache(self.master)
        self.kinit_idp_keycloak(self.master, self.KEYCLOAK_USER,
                                keycloak_server=self.client)

    @pytest.fixture
    def hbac_setup_teardown(self):
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-disable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-add", "rule1"])
        self.master.run_command(["ipa", "hbacrule-add-user", "rule1",
                                 "--users=" + self.KEYCLOAK_USER])
        self.master.run_command(["ipa", "hbacrule-add-host", "rule1",
                                 "--hosts", self.replica.hostname])
        self.master.run_command(["ipa", "hbacrule-add-service", "rule1",
                                 "--hbacsvcs=sshd"])
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(self.replica)
        yield

        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "hbacrule-enable", "allow_all"])
        self.master.run_command(["ipa", "hbacrule-del", "rule1"])

    def test_auth_hbac(self, hbac_setup_teardown):
        """
        Test case to check that hbacrule is working as
        expected for user configured with external idp.
        """
        self.kinit_idp_keycloak(self.master, self.KEYCLOAK_USER,
                                keycloak_server=self.client)
        ssh_cmd = "ssh -q -K -l {0} {{0}} whoami".format(self.KEYCLOAK_USER)
        valid_ssh = self.master.run_command(
            ssh_cmd.format(self.replica.hostname))
        assert self.KEYCLOAK_USER in valid_ssh.stdout_text
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
        cmdlist = [
            ["ipa", "sudocmd-add", "/usr/bin/yum"],
            ["ipa", "sudorule-add", "sudorule"],
            ['ipa', 'sudorule-add-user',
             '--users=' + self.KEYCLOAK_USER, 'sudorule'],
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
            cmd = 'sudo -ll -U ' + self.KEYCLOAK_USER
            test = self.client.run_command(cmd).stdout_text
            msg = ("User %s may run the following commands"
                   % self.KEYCLOAK_USER)
            assert msg in test
            assert "/usr/bin/yum" in test
            self.kinit_idp_keycloak(self.client, self.KEYCLOAK_USER,
                                    keycloak_server=self.client)
            test_sudo = ('su -c "sudo yum list sssd-client" %s'
                         % self.KEYCLOAK_USER)
            self.client.run_command(test_sudo)
            list_fail = self.master.run_command(cmd).stdout_text
            msg = "User %s is not allowed to run sudo" % self.KEYCLOAK_USER
            assert msg in list_fail
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
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID]
        )
        assert self.KEYCLOAK_USER in list_user.stdout_text
        list_by_idp = self.replica.run_command(
            ["ipa", "user-find", "--idp=" + self.KEYCLOAK_IDP_NAME])
        assert self.KEYCLOAK_USER in list_by_idp.stdout_text
        list_by_user = self.replica.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID, "--all"]
        )
        assert self.KEYCLOAK_IDP_NAME in list_by_user.stdout_text
        self.kinit_idp_keycloak(self.replica, self.KEYCLOAK_USER,
                                keycloak_server=self.client)

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
                                                "--auth-ind=idp"])
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
        idp_name = "testidp"
        cmd = ["ipa", "idp-add", idp_name, "--provider=keycloak",
               "--client-id=ipa_oidc_client", "--org=master",
               "--base-url={0}:8443".format(self.client.hostname)]
        self.master.run_command(cmd, stdin_text="{0}\n{0}".format(
            self.client.config.admin_password))

        tasks.user_add(
            self.master, user,
            extra_args=["--user-auth-type=idp",
                        "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                        "--idp=" + idp_name]
        )

        backup_path = tasks.get_backup_dir(self.master)
        self.master.run_command(['ipa', 'user-del', user])
        self.master.run_command(['ipa', 'idp-del', idp_name])
        dirman_password = self.master.config.dirman_password
        self.master.run_command(['ipa-restore', backup_path],
                                stdin_text=dirman_password + '\nyes')
        try:
            list_user = self.master.run_command(
                ['ipa', 'user-show', 'backupuser', '--all']
            ).stdout_text
            assert "External IdP configuration: testidp" in list_user
            assert "User authentication types: idp" in list_user
            msg = ("External IdP user identifier: %s"
                   % self.KEYCLOAK_IDP_USER_ID)
            assert msg in list_user
            list_idp = self.master.run_command(['ipa', 'idp-find', idp_name])
            assert idp_name in list_idp.stdout_text
            self.kinit_idp_keycloak(self.master, user,
                                    keycloak_server=self.client)
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(["rm", "-rf", backup_path])
            self.master.run_command(["ipa", "idp-del", idp_name])

    def test_idp_providers_backup_restore(self):
        """
        Builtin provider IdPs survive ``ipa-backup`` / ``ipa-restore``.

        Adds google, github, microsoft, and okta templates, takes a backup,
        removes the IdP entries and a linked user, restores, and verifies each
        provider reference and user linkage are present again.
        """
        tasks.kinit_admin(self.master)
        idp_names = []
        backup_path = None
        try:
            for cn, provider, extra_args, _marker in (
                    self.BUILTIN_IDP_PROVIDER_SPECS):
                self._add_builtin_provider_idp(cn, provider, extra_args)
                idp_names.append(cn)

            tasks.user_add(
                self.master, self.BACKUP_RESTORE_USER,
                extra_args=["--user-auth-type=idp",
                            "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                            "--idp=idp-google"],
            )

            backup_path = tasks.get_backup_dir(self.master)
            for cn in idp_names:
                self.master.run_command(["ipa", "idp-del", cn])
            self.master.run_command(
                ["ipa", "user-del", self.BACKUP_RESTORE_USER])

            dirman_password = self.master.config.dirman_password
            self.master.run_command(
                ["ipa-restore", backup_path],
                stdin_text=dirman_password + "\nyes",
            )

            for cn, provider, _extra_args, marker in (
                    self.BUILTIN_IDP_PROVIDER_SPECS):
                show = self.master.run_command(["ipa", "idp-show", cn])
                assert cn in show.stdout_text
                assert marker in show.stdout_text
                find = self.master.run_command(["ipa", "idp-find", cn])
                assert cn in find.stdout_text

            user_show = self.master.run_command(
                ["ipa", "user-show", self.BACKUP_RESTORE_USER, "--all"],
            ).stdout_text
            assert "External IdP configuration: idp-google" in user_show
            assert "User authentication types: idp" in user_show
            assert ("External IdP user identifier: %s"
                    % self.KEYCLOAK_IDP_USER_ID) in user_show
        finally:
            tasks.kinit_admin(self.master)
            for cn, _provider, _extra_args, _marker in (
                    self.BUILTIN_IDP_PROVIDER_SPECS):
                self.master.run_command(["ipa", "idp-del", cn])
            self.master.run_command(
                ["ipa", "user-del", self.BACKUP_RESTORE_USER])
            if backup_path:
                self.master.run_command(
                    ["rm", "-rf", backup_path])

    def test_idp_with_service_user(self):
        """
        HTTP service with ``idp`` auth indicator requires an IdP TGT.

        A user configured for external IdP authentication can obtain a
        service ticket only after completing the device authorization flow.
        """
        domain = self.master.domain.name.upper()
        service = "HTTP/{0}@{1}".format(self.client.hostname, domain)
        keytab = "/tmp/idp-http-service.keytab"
        tasks.kinit_admin(self.master)
        try:
            if self.master.run_command(["ipa", "service-show", service],
                                       raiseonerr=False
                                       ).returncode != 0:
                self.master.run_command(
                    ["ipa", "service-add", service, "--auth-ind=idp"])
            else:
                self.master.run_command(
                    ["ipa", "service-mod", service, "--auth-ind=idp"])
            show = self.master.run_command(["ipa", "service-show", service])
            assert "Authentication Indicators: idp" in show.stdout_text

            self.master.run_command(
                ["ipa-getkeytab", "-p", service, "-k", keytab])

            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            denied = self.master.run_command(
                ["kvno", service], raiseonerr=False)
            assert denied.returncode != 0
            assert "rejects" in (
                denied.stderr_text + denied.stdout_text).lower()

            self.kinit_idp_keycloak(
                self.master, self.KEYCLOAK_USER,
                keycloak_server=self.client)
            self.master.run_command(["kvno", service])
            klist = self.master.run_command(["klist"])
            assert service in klist.stdout_text
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "service-mod", service, "--auth-ind="])
            self.master.run_command(["rm", "-f", keytab])

    def _kinit_idp_keycloak_mtls(self, host, user):
        """
        ``kinit`` for ``tls_client_auth`` with Keycloak HTTPS client auth
        in ``request`` mode for the token exchange only.

        Device-flow Selenium must run while ``KC_HTTPS_CLIENT_AUTH=none``;
        otherwise headless Firefox hangs on the TLS client-cert prompt.
        """
        def complete(uri, _device_user_code):
            TestIDPKeycloak.add_keycloak_user_code(self.client, uri)
            keycloak_set_https_client_auth(self.client, "request")

        TestIDP.kinit_idp_device_flow(
            host, user, complete,
            pre_complete_delay=5,
            expect_timeout=300,
        )

    @pytest.mark.xfail(reason=XFAIL_SSSD_OIDC_CERT_AUTH, strict=True)
    def test_idp_jwt_keycloak(self):
        """
        Test CERT keycloak private_key_jwt certificate authorization grant.

        Generate client certificate material with openssl on the IPA master,
        upload ``idp-client.crt`` to the keycloak used for IdP
        and run ``ipa idp-add`` for JWT client
        auth (``private_key_jwt``) against keycloak.
        """
        self._ensure_keycloak_for_cert_tests()

        workdir = generate_idp_client_openssl_bundle(self.master)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)
        cert_b64 = keycloak_pem_cert_der_b64(pem_bytes)

        kc_client_added = False
        p12_on_master = False
        jwt_idp_added = False
        jwt_user_added = False
        try:
            keycloak_delete_client(self.client, self.KEYCLOAK_JWT_CLIENT_ID)
            keycloak_create_cert_oidc_client(
                self.client,
                self.master.domain.name,
                self.KEYCLOAK_JWT_CLIENT_ID,
                auth_method="private_key_jwt",
                extra_attrs={"jwt.credential.certificate": cert_b64},
            )
            kc_client_added = True

            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_P12_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_P12_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=10)).timetuple(),
            )
            idp_add_cmd = [
                "ipa", "idp-add", self.KEYCLOAK_JWT_IDP_NAME,
                "--provider=keycloak",
                "--org=master",
                "--base-url=%s:8443" % self.client.hostname,
                "--client-id=%s" % self.KEYCLOAK_JWT_CLIENT_ID,
                "--client-auth-method=private_key_jwt",
                "--client-cert-p12-file=%s" % IDP_CLIENT_P12_IPA_PATH,
            ]
            self.master.run_command(
                idp_add_cmd, stdin_text=p12_passphrase_stdin())
            show_out = self.master.run_command(
                ["ipa", "idp-show", self.KEYCLOAK_JWT_IDP_NAME, "--all"])
            assert "private_key_jwt" in show_out.stdout_text.lower()
            journal = self.master.run_command(
                ["journalctl", "-g", "IPA.API", "--since=%s" % since])
            assert '"userpkcs12": "********"' in journal.stdout_text
            jwt_idp_added = True

            tasks.user_add(
                self.master,
                self.KEYCLOAK_JWT_USER,
                first="keycloakjwt",
                last="UserJwt",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                    "--idp=" + self.KEYCLOAK_JWT_IDP_NAME,
                ],
            )
            jwt_user_added = True
            tasks.clear_sssd_cache(self.master)
            tasks.wait_for_sssd_domain_status_online(self.master)
            wait_for_ipa_user_lookup_id(self.master, self.KEYCLOAK_JWT_USER)
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=30)).timetuple(),
            )
            self.kinit_idp_keycloak(
                self.master, self.KEYCLOAK_JWT_USER,
                keycloak_server=self.client,
            )
            test_idp = self.master.run_command(["klist", "-C"])
            assert "152" in test_idp.stdout_text
            journal = self.master.run_command(
                ["journalctl", "-u", "ipa-otpd", "--since=%s" % since],
                raiseonerr=False,
            )
            text = (journal.stdout_text + journal.stderr_text).lower()
            jwt_markers = (
                "client_assertion",
                "private_key_jwt",
                "jwt-bearer",
                "client-assertion-type",
            )
            assert any(marker in text for marker in jwt_markers)
        finally:
            if kc_client_added:
                keycloak_delete_client(
                    self.client, self.KEYCLOAK_JWT_CLIENT_ID)
            if jwt_idp_added:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "idp-del", self.KEYCLOAK_JWT_IDP_NAME],
                    raiseonerr=False,
                )
            if jwt_user_added:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "user-del", self.KEYCLOAK_JWT_USER],
                    raiseonerr=False,
                )
            if p12_on_master:
                self.master.run_command(
                    ["rm", "-f", IDP_CLIENT_P12_IPA_PATH],
                    raiseonerr=False,
                )
            self.master.run_command(
                ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_tls_keycloak(self):
        """
        Test CERT keycloak tls_client_auth certificate authorization grant.

        Generate client certificate material with openssl on the IPA master,
        upload ``idp-client.crt`` to the keycloak used for IdP
        and run ``ipa idp-add`` for TLS client
        auth (``tls_client_auth``) against keycloak.
        """
        self._ensure_keycloak_for_cert_tests()

        workdir = generate_idp_client_openssl_bundle(self.master)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)
        subject_dn = keycloak_openssl_cert_subject_dn(self.master, crt_path)
        crt_on_keycloak = "/tmp/idp-client.crt"

        kc_client_added = False
        truststore_imported = False
        p12_on_master = False
        tls_idp_added = False
        tls_user_added = False
        try:
            pem_text = (
                pem_bytes.decode("ascii")
                if isinstance(pem_bytes, bytes) else pem_bytes
            )
            self.client.put_file_contents(crt_on_keycloak, pem_text)
            keycloak_truststore_delete_cert(
                self.client, self.KEYCLOAK_MTLS_TRUSTSTORE_ALIAS)
            keycloak_truststore_import_cert(
                self.client, crt_on_keycloak,
                self.KEYCLOAK_MTLS_TRUSTSTORE_ALIAS)
            truststore_imported = True
            keycloak_ensure_kcadm_credentials(self.client)

            keycloak_delete_client(self.client, self.KEYCLOAK_TLS_CLIENT_ID)
            keycloak_create_cert_oidc_client(
                self.client,
                self.master.domain.name,
                self.KEYCLOAK_TLS_CLIENT_ID,
                auth_method="tls_client_auth",
                extra_attrs={"x509.subjectdn": subject_dn},
            )
            kc_client_added = True

            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_TLS_P12_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_TLS_P12_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=10)).timetuple(),
            )
            idp_add_cmd = [
                "ipa", "idp-add", self.KEYCLOAK_TLS_IDP_NAME,
                "--provider=keycloak",
                "--org=master",
                "--base-url=%s:8443" % self.client.hostname,
                "--client-id=%s" % self.KEYCLOAK_TLS_CLIENT_ID,
                "--client-auth-method=tls_client_auth",
                "--client-cert-p12-file=%s" % IDP_CLIENT_TLS_P12_IPA_PATH,
            ]
            self.master.run_command(
                idp_add_cmd, stdin_text=p12_passphrase_stdin())
            journal = self.master.run_command(
                ["journalctl", "-g", "IPA.API", "--since=%s" % since])
            assert '"userpkcs12": "********"' in journal.stdout_text
            show_out = self.master.run_command(
                ["ipa", "idp-show", self.KEYCLOAK_TLS_IDP_NAME, "--all"])
            assert "tls_client_auth" in show_out.stdout_text.lower()
            tls_idp_added = True

            tasks.user_add(
                self.master,
                self.KEYCLOAK_TLS_USER,
                first="keycloaktls",
                last="UserTls",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.KEYCLOAK_IDP_USER_ID,
                    "--idp=" + self.KEYCLOAK_TLS_IDP_NAME,
                ],
            )
            tls_user_added = True
            tasks.clear_sssd_cache(self.master)
            tasks.wait_for_sssd_domain_status_online(self.master)
            wait_for_ipa_user_lookup_id(self.master, self.KEYCLOAK_TLS_USER)
            self._kinit_idp_keycloak_mtls(
                self.master, self.KEYCLOAK_TLS_USER)
        finally:
            if kc_client_added:
                keycloak_delete_client(
                    self.client, self.KEYCLOAK_TLS_CLIENT_ID)
            if truststore_imported:
                keycloak_truststore_delete_cert(
                    self.client, self.KEYCLOAK_MTLS_TRUSTSTORE_ALIAS)
            keycloak_set_https_client_auth(self.client, "none")
            if tls_idp_added:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "idp-del", self.KEYCLOAK_TLS_IDP_NAME],
                    raiseonerr=False,
                )
            if tls_user_added:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "user-del", self.KEYCLOAK_TLS_USER],
                    raiseonerr=False,
                )
            if p12_on_master:
                self.master.run_command(
                    ["rm", "-f", IDP_CLIENT_TLS_P12_IPA_PATH],
                    raiseonerr=False,
                )
            self.client.run_command(
                ["rm", "-f", crt_on_keycloak], raiseonerr=False)
            self.master.run_command(
                ["rm", "-rf", workdir], raiseonerr=False)


class TestIDPAzure(TestIDP):
    """
    Microsoft Entra (Azure) IdP integration tests.

    Requires Microsoft Entra ID configured for Device Flow with client
    credentials and a preconfigured user account.  Multihost YAML keys:

    ``azure_tenant_id``
        Tenant ID.
    ``azure_admin_client_id``
        Application (client) ID.
    ``azure_admin_client_secret``
        Client secret.
    ``azure_username``
        Entra user principal name.
    ``azure_user_password``
        Entra user password.
    """

    AZURE_IDP_NAME = "azureidp"
    AZURE_IPA_USERNAME = "testazure"
    AZURE_JWT_IPA_USERNAME = "testazurejwt"
    AZURE_JWT_IDP_NAME = "Azure-JWT"
    AZURE_TLS_IPA_USERNAME = "testazuretls"
    AZURE_TLS_IDP_NAME = "Azure-TLS"
    AZURE_NOPASS_IPA_USERNAME = "testazurenopass"
    AZURE_NOPASS_IDP_NAME = "Azure-NOPASS"
    AZURE_MIGRATE_IDP_NAME = "azure-migrate"
    AZURE_MIGRATE_IPA_USERNAME = "testazuremigrate"
    AZURE_ROTATE_IDP_NAME = "Azure-ROTATE"
    AZURE_ROTATE_IPA_USERNAME = "testazurerotate"
    IDP_PERM_NONE_USER = "idpnoperm"
    IDP_PERM_READ_USER = "idpread"
    IDP_PERM_SECRET_USER = "idpsecretread"
    IDP_PERM_ROLE_READ = "idp-read-only"
    IDP_PERM_ROLE_SECRET = "idp-secret-read"

    @classmethod
    def install(cls, mh):
        """Install IPA topology and provision Azure IdP test objects."""
        cls.require_azure_multihost_config()
        super(TestIDPAzure, cls).install(mh)
        cls.ensure_azure_idp_and_user()

    @staticmethod
    def add_azure_user_code(host, verification_uri, username, password,
                            device_user_code=None):
        contents = entraid_helpers.azure_user_code_script(
            create_keycloak.SELENIUM_REMOTE_HEAD,
            create_keycloak.selenium_remote_finally(
                "/var/log/httpd/screenshot-azure-%s.png"),
        ).format(
            uri=verification_uri,
            username=username,
            password=password,
            device_user_code=device_user_code or "",
        )
        TestIDP.run_remote_selenium(
            host, contents, "add_azure_user_code.py", timeout=180)

    @staticmethod
    def kinit_idp_azure(host, user, azure_email, azure_password):
        """kinit via Microsoft Entra device authorization flow."""
        def complete(uri, device_user_code):
            TestIDPAzure.add_azure_user_code(
                host, uri, azure_email, azure_password,
                device_user_code=device_user_code,
            )

        TestIDP.kinit_idp_device_flow(host, user, complete)

    @classmethod
    def require_azure_multihost_config(cls):
        """
        Skip the class when Azure multihost configuration is incomplete.

        All of ``azure_username``, ``azure_user_password``,
        ``azure_tenant_id``, ``azure_admin_client_id``, and
        ``azure_admin_client_secret`` must be set in the test config.
        """
        cls.cfg = cls.master.config
        if not all((
                cls.cfg.azure_username,
                cls.cfg.azure_user_password,
                cls.cfg.azure_tenant_id,
                cls.cfg.azure_admin_client_id,
                cls.cfg.azure_admin_client_secret,
        )):
            pytest.skip(
                "Azure IdP tests require Azure multihost configuration")

    @classmethod
    def ensure_azure_idp_and_user(cls):
        """Create Microsoft IdP and linked IPA user if absent."""
        host = cls.master
        tasks.kinit_admin(host)
        idp_show = host.run_command(
            ["ipa", "idp-show", cls.AZURE_IDP_NAME], raiseonerr=False)
        if idp_show.returncode != 0:
            host.run_command(
                [
                    "ipa", "idp-add", cls.AZURE_IDP_NAME,
                    "--provider", "microsoft",
                    "--organization", cls.cfg.azure_tenant_id,
                    "--client-id", cls.cfg.azure_admin_client_id,
                    "--secret",
                ],
                stdin_text=cls.cfg.azure_admin_client_secret + "\n",
            )

        user_show = host.run_command(
            ["ipa", "user-show", cls.AZURE_IPA_USERNAME], raiseonerr=False)
        if user_show.returncode != 0:
            tasks.user_add(
                host,
                cls.AZURE_IPA_USERNAME,
                first="azure",
                last="User",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + cls.cfg.azure_username,
                    "--idp=" + cls.AZURE_IDP_NAME,
                ],
            )

    def _ensure_idp_user(self, idp_name, ipa_user, first, last):
        tasks.kinit_admin(self.master)
        user_show = self.master.run_command(
            ["ipa", "user-show", ipa_user], raiseonerr=False)
        if user_show.returncode != 0:
            tasks.user_add(
                self.master,
                ipa_user,
                first=first,
                last=last,
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.cfg.azure_username,
                    "--idp=" + idp_name,
                ],
            )

    def _azure_device_kinit(self, ipa_user, host=None, retries=5):
        """
        Device-flow kinit on *host* (default client); retry on Entra/UI flake.

        ``kinit: Pre-authentication failed: Invalid argument`` often means the
        device prompt never completed (Selenium/timing), not a PKCS#12 bug.
        """
        host = host or self.client
        last_error = None
        for attempt in range(retries):
            try:
                tasks.kdestroy_all(host)
                tasks.clear_sssd_cache(host)
                tasks.wait_for_sssd_domain_status_online(host)
                wait_for_ipa_user_lookup_id(host, ipa_user)
                self.kinit_idp_azure(
                    host, ipa_user,
                    self.cfg.azure_username,
                    self.cfg.azure_user_password,
                )
                klist = host.run_command(["klist", "-C"])
                assert "152" in klist.stdout_text
                return
            except (AssertionError, subprocess.CalledProcessError) as err:
                last_error = err
                if attempt + 1 < retries:
                    time.sleep(5)
        raise last_error

    def _assert_idp_ldap_client_auth_present(self, idp_name, ldap_host=None):
        entry = idp_ldap_entry_text(self.master, idp_name, ldap_host=ldap_host)
        entry_lower = entry.lower()
        assert IDP_CLIENT_AUTH_AUX_OC in entry_lower
        assert "userpkcs12" in entry_lower
        assert "usercertificate" in entry_lower

    def _assert_idp_ldap_client_auth_absent(self, idp_name, ldap_host=None):
        entry = idp_ldap_entry_text(self.master, idp_name, ldap_host=ldap_host)
        entry_lower = entry.lower()
        assert IDP_CLIENT_AUTH_AUX_OC not in entry_lower
        assert "userpkcs12" not in entry_lower

    def _add_azure_secret_idp(self, idp_name):
        tasks.kinit_admin(self.master)
        if self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"],
                raiseonerr=False,
        ).returncode == 0:
            return
        self.master.run_command(
            [
                "ipa", "idp-add", idp_name,
                "--provider", "microsoft",
                "--organization", self.cfg.azure_tenant_id,
                "--client-id", self.cfg.azure_admin_client_id,
                "--secret",
            ],
            stdin_text=self.cfg.azure_admin_client_secret + "\n",
        )

    def _add_azure_cert_idp(
        self,
        idp_name,
        ipa_user,
        p12_ipa_path,
        *,
        auth_method="private_key_jwt",
        p12_password=IDP_CLIENT_P12_PASSWORD,
        first="azurecert",
        last="UserCert",
        workdir=None,
    ):
        """
        Upload a client cert to Entra, ``ipa idp-add`` with PKCS#12, add user.
        Returns (token, app_object_id, pem_bytes, workdir).
        """
        workdir = workdir or generate_idp_client_openssl_bundle(
            self.master, p12_password=p12_password)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)
        token, app_object_id = entra_upload_client_cert(
                self.cfg, pem_bytes)
        p12_src = os.path.join(workdir, "idp-client.p12")
        self.master.run_command(["cp", p12_src, p12_ipa_path])
        self.master.run_command(["chmod", "600", p12_ipa_path])
        tasks.kinit_admin(self.master)
        self.master.run_command(
            [
                "ipa", "idp-add", idp_name,
                "--provider=microsoft",
                "--organization=%s" % self.cfg.azure_tenant_id,
                "--issuer=%s" % microsoft_issuer_url(self.cfg),
                "--client-id=%s" % self.cfg.azure_admin_client_id,
                "--client-auth-method=%s" % auth_method,
                "--client-cert-p12-file=%s" % p12_ipa_path,
            ],
            stdin_text=p12_passphrase_stdin(p12_password),
        )
        self._ensure_idp_user(idp_name, ipa_user, first, last)
        return token, app_object_id, pem_bytes, workdir

    def _teardown_azure_entra_certs(
        self, app_object_id, *pem_certificates, token=None,
    ):
        entra_delete_uploaded_certs(
            self.cfg, app_object_id, *pem_certificates, token=token)

    def _teardown_azure_idp_user(self, idp_name=None, ipa_user=None):
        tasks.kinit_admin(self.master)
        if ipa_user:
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
        if idp_name:
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)

    def _teardown_azure_test_artifacts(
        self, *p12_paths, workdirs=(), extra_paths=(), backup_paths=(),
    ):
        for path in extra_paths:
            if path:
                self.master.run_command(["rm", "-f", path], raiseonerr=False)
        for path in p12_paths:
            if path:
                self.master.run_command(["rm", "-f", path], raiseonerr=False)
        for wd in workdirs:
            if wd:
                self.master.run_command(["rm", "-rf", wd], raiseonerr=False)
        for path in backup_paths:
            if path:
                self.master.run_command(["rm", "-rf", path], raiseonerr=False)

    def _teardown_azure_cert_idp_test(
        self,
        *,
        app_object_id=None,
        pem_certificates=(),
        token=None,
        idp_name=None,
        ipa_user=None,
        p12_paths=(),
        workdirs=(),
        extra_paths=(),
        backup_paths=(),
        perm_users=(),
        modify_admin=False,
    ):
        """Common finally cleanup for Azure cert-based IdP tests."""
        if app_object_id is not None or pem_certificates:
            self._teardown_azure_entra_certs(
                app_object_id, *pem_certificates, token=token)
        tasks.kinit_admin(self.master)
        if perm_users:
            self._teardown_idp_permission_users(*perm_users)
        elif modify_admin:
            self._teardown_idp_modify_admin()
        elif ipa_user:
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
        if idp_name:
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
        self._teardown_azure_test_artifacts(
            *p12_paths,
            workdirs=workdirs,
            extra_paths=extra_paths,
            backup_paths=backup_paths,
        )

    def _teardown_azure_installed_cert_idp(
        self,
        *,
        app_object_id,
        pem_bytes,
        token,
        idp_name,
        idp_added=False,
        p12_path=None,
        p12_on_master=False,
        workdir=None,
    ):
        """Finally cleanup when IdP/P12 install may be skipped on failure."""
        self._teardown_azure_entra_certs(
            app_object_id, pem_bytes, token=token)
        if idp_added:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
        if p12_on_master and p12_path:
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
        if workdir:
            self.master.run_command(["rm", "-rf", workdir], raiseonerr=False)

    def _teardown_azure_secret_idp_test(
        self,
        idp_name,
        ipa_user=None,
        p12_paths=(),
        workdirs=(),
        extra_paths=(),
    ):
        """Finally cleanup for client_secret IdP tests (no Entra certs)."""
        self._teardown_azure_idp_user(idp_name, ipa_user)
        self._teardown_azure_test_artifacts(
            *p12_paths, workdirs=workdirs, extra_paths=extra_paths)

    def test_azure_idp_add_and_user(self):
        """
        Add Azure IDP with Microsoft provider and associate user with mail id.

        Uses ipa idp-add with --provider microsoft, --organization (tenant ID),
        --client-id, and --secret from stdin. Then adds IPA user linked to
        the IdP with idp-user-id set to the user's email.
        """
        result = self.master.run_command(
            ["ipa", "idp-show", self.AZURE_IDP_NAME])
        assert self.AZURE_IDP_NAME in result.stdout_text
        assert "login.microsoftonline.com" in result.stdout_text

        list_user = self.master.run_command(
            ["ipa", "user-find",
             "--idp-user-id=" + self.cfg.azure_username]
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
        assert self.cfg.azure_username in user_show.stdout_text

    def test_azure_idp_kinit(self):
        """
        Full OAuth 2.0 Device Authorization Grant kinit with Azure IdP.

        Performs kinit with FAST armor for the IdP-configured user and
        automates the Microsoft login page via headless Selenium to
        complete the device code flow end-to-end.  Verifies the
        resulting ticket carries the IdP authentication indicator (152).
        """
        tasks.clear_sssd_cache(self.client)
        self.kinit_idp_azure(
            self.client,
            self.AZURE_IPA_USERNAME,
            self.cfg.azure_username,
            self.cfg.azure_user_password,
        )

    def test_azure_private_key_jwt(self):
        """
        Test CERT AZURE certificate authorization grant.

        Generate client certificate material with openssl on the IPA master,
        upload ``idp-client.crt`` to the Entra app registration used for IdP
        (same ``azure_admin_client_id`` as ``ipa idp-add``), then install the
        PKCS#12 bundle on the master and run ``ipa idp-add`` for JWT client
        auth (``private_key_jwt``) against Microsoft OIDC issuer v2.0.
        """

        workdir = generate_idp_client_openssl_bundle(self.master)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)

        token = None
        app_object_id = None
        p12_on_master = False
        jwt_idp_added = False
        try:
            token = azure_acquire_graph_token(
                self.cfg.azure_tenant_id,
                self.cfg.azure_admin_client_id,
                self.cfg.azure_admin_client_secret,
            )
            app_object_id = azure_graph_application_object_id(
                token,
                self.cfg.azure_admin_client_id,
            )
            cert_display_name = new_idp_client_graph_cert_display_name(
                calling_test_name())
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes,
                display_name=cert_display_name,
            )

            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_P12_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_P12_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            issuer = (
                "https://login.microsoftonline.com/%s/v2.0"
                % self.cfg.azure_tenant_id
            )
            # ``idp_add`` requires ``--provider`` or explicit OAuth endpoints;
            # JWT/P12 options do not replace provider. Use Microsoft template
            # device/authorize/token/userinfo URLs (same tenant as issuer).
            # Note the time to parse the journal
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=10)).timetuple()
            )
            idp_add_cmd = [
                "ipa", "idp-add", self.AZURE_JWT_IDP_NAME,
                "--provider=microsoft",
                "--organization=%s" % self.cfg.azure_tenant_id,
                "--issuer=%s" % issuer,
                "--client-id=%s" % self.cfg.azure_admin_client_id,
                "--client-auth-method=private_key_jwt",
                "--client-cert-p12-file=%s" % IDP_CLIENT_P12_IPA_PATH,
            ]
            # PKCS#12 passphrase (and confirm) when ``ipa`` prompts.
            p12_stdin = "%s\n%s\n" % (
                IDP_CLIENT_P12_PASSWORD,
                IDP_CLIENT_P12_PASSWORD,
            )
            self.master.run_command(idp_add_cmd, stdin_text=p12_stdin)
            show_out = self.master.run_command(
                ["ipa", "idp-show", self.AZURE_JWT_IDP_NAME, "--all"])
            assert "private_key_jwt" in show_out.stdout_text.lower()

            # Ensure that the PKCS12 content is obfuscated in the logs
            cmd = ["journalctl", "-g", "IPA.API", f"--since={since}"]
            journal = self.master.run_command(cmd)
            assert '"userpkcs12": "********"' in journal.stdout_text
            jwt_idp_added = True
            tasks.user_add(
                self.master,
                self.AZURE_JWT_IPA_USERNAME,
                first="azurejwt",
                last="UserJwt",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.cfg.azure_username,
                    "--idp=" + self.AZURE_JWT_IDP_NAME,
                ],
            )
            tasks.clear_sssd_cache(self.client)
            tasks.wait_for_sssd_domain_status_online(self.client)
            wait_for_ipa_user_lookup_id(
                self.client, self.AZURE_JWT_IPA_USERNAME)
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=30)).timetuple(),
            )
            self.kinit_idp_azure(
                self.client, self.AZURE_JWT_IPA_USERNAME,
                self.cfg.azure_username,
                self.cfg.azure_user_password,
            )
            test_idp = self.client.run_command(["klist", "-C"])
            assert "152" in test_idp.stdout_text
            journal = self.master.run_command(
                ["journalctl", "-u", "ipa-otpd", "--since=%s" % since],
                raiseonerr=False,
            )
            text = (journal.stdout_text + journal.stderr_text).lower()
            jwt_markers = (
                "client_assertion",
                "private_key_jwt",
                "jwt-bearer",
                "client-assertion-type",
            )
            assert any(marker in text for marker in jwt_markers)
        finally:
            self._teardown_azure_installed_cert_idp(
                app_object_id=app_object_id,
                pem_bytes=pem_bytes,
                token=token,
                idp_name=self.AZURE_JWT_IDP_NAME,
                idp_added=jwt_idp_added,
                p12_path=IDP_CLIENT_P12_IPA_PATH,
                p12_on_master=p12_on_master,
                workdir=workdir,
            )

    def test_azure_tls_client_auth(self):
        """
        Test Azure IdP using mTLS client authentication (RFC 8705).

        Same Entra app-registration certificate upload as ``test_azure_cert``,
        but ``ipa idp-add`` uses ``--client-auth-method=tls_client_auth`` so
        token exchange presents the client certificate at the TLS layer.
        """

        workdir = generate_idp_client_openssl_bundle(self.master)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)

        token = None
        app_object_id = None
        p12_on_master = False
        tls_idp_added = False
        try:
            token = azure_acquire_graph_token(
                self.cfg.azure_tenant_id,
                self.cfg.azure_admin_client_id,
                self.cfg.azure_admin_client_secret,
            )
            app_object_id = azure_graph_application_object_id(
                token,
                self.cfg.azure_admin_client_id,
            )
            cert_display_name = new_idp_client_graph_cert_display_name(
                calling_test_name())
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes,
                display_name=cert_display_name,
            )

            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_TLS_P12_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_TLS_P12_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            issuer = (
                "https://login.microsoftonline.com/%s/v2.0"
                % self.cfg.azure_tenant_id
            )
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=10)).timetuple()
            )
            idp_add_cmd = [
                "ipa", "idp-add", self.AZURE_TLS_IDP_NAME,
                "--provider=microsoft",
                "--organization=%s" % self.cfg.azure_tenant_id,
                "--issuer=%s" % issuer,
                "--client-id=%s" % self.cfg.azure_admin_client_id,
                "--client-auth-method=tls_client_auth",
                "--client-cert-p12-file=%s" % IDP_CLIENT_TLS_P12_IPA_PATH,
            ]
            p12_stdin = "%s\n%s\n" % (
                IDP_CLIENT_P12_PASSWORD,
                IDP_CLIENT_P12_PASSWORD,
            )
            self.master.run_command(idp_add_cmd, stdin_text=p12_stdin)
            cmd = ["journalctl", "-g", "IPA.API", f"--since={since}"]
            journal = self.master.run_command(cmd)
            assert '"userpkcs12": "********"' in journal.stdout_text
            show_out = self.master.run_command(
                ["ipa", "idp-show", self.AZURE_TLS_IDP_NAME, "--all"])
            assert "tls_client_auth" in show_out.stdout_text.lower()
            tls_idp_added = True
            tasks.user_add(
                self.master,
                self.AZURE_TLS_IPA_USERNAME,
                first="azuretls",
                last="UserTls",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.cfg.azure_username,
                    "--idp=" + self.AZURE_TLS_IDP_NAME,
                ],
            )
            tasks.clear_sssd_cache(self.client)
            tasks.wait_for_sssd_domain_status_online(self.client)
            wait_for_ipa_user_lookup_id(
                self.client, self.AZURE_TLS_IPA_USERNAME)
            self.kinit_idp_azure(
                self.client, self.AZURE_TLS_IPA_USERNAME,
                self.cfg.azure_username,
                self.cfg.azure_user_password,
            )
            test_idp = self.client.run_command(["klist", "-C"])
            assert "152" in test_idp.stdout_text
        finally:
            self._teardown_azure_installed_cert_idp(
                app_object_id=app_object_id,
                pem_bytes=pem_bytes,
                token=token,
                idp_name=self.AZURE_TLS_IDP_NAME,
                idp_added=tls_idp_added,
                p12_path=IDP_CLIENT_TLS_P12_IPA_PATH,
                p12_on_master=p12_on_master,
                workdir=workdir,
            )

    def test_idp_add_pkcs12_empty_passphrase_succeeds(self):
        """
        ``ipa idp-add`` accepts a PKCS#12 bundle with an empty MAC password.

        Generates client cert material with ``p12_password=""``, uploads the
        certificate to the Entra app registration, imports the bundle via
        ``--client-cert-p12-file`` against Microsoft OIDC, and confirms the IdP
        is created when only newlines are supplied at the PKCS#12 passphrase
        prompts.  Completes device-flow kinit end-to-end.
        """

        workdir = "/tmp/idp-openssl-nopass-%06d" % random.randint(0, 999999)
        generate_idp_client_openssl_bundle(
            self.master, workdir=workdir, p12_password="")
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)
        p12_src = os.path.join(workdir, "idp-client.p12")
        self.master.run_command(
            [
                "openssl", "pkcs12", "-in", p12_src, "-nodes",
                "-passin", "pass:", "-noout",
            ],
            cwd=workdir,
        )

        token = None
        app_object_id = None
        p12_on_master = False
        nopass_idp_added = False
        try:
            token = azure_acquire_graph_token(
                self.cfg.azure_tenant_id,
                self.cfg.azure_admin_client_id,
                self.cfg.azure_admin_client_secret,
            )
            app_object_id = azure_graph_application_object_id(
                token,
                self.cfg.azure_admin_client_id,
            )
            cert_display_name = new_idp_client_graph_cert_display_name(
                calling_test_name())
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes,
                display_name=cert_display_name,
            )

            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_P12_NOPASS_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_P12_NOPASS_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            issuer = (
                "https://login.microsoftonline.com/%s/v2.0"
                % self.cfg.azure_tenant_id
            )
            self.master.run_command(
                [
                    "ipa", "idp-add", self.AZURE_NOPASS_IDP_NAME,
                    "--provider=microsoft",
                    "--organization=%s" % self.cfg.azure_tenant_id,
                    "--issuer=%s" % issuer,
                    "--client-id=%s" % self.cfg.azure_admin_client_id,
                    "--client-auth-method=private_key_jwt",
                    "--client-cert-p12-file=%s"
                    % IDP_CLIENT_P12_NOPASS_IPA_PATH,
                ],
                stdin_text="\n\n",
            )
            show_out = self.master.run_command(
                ["ipa", "idp-show", self.AZURE_NOPASS_IDP_NAME, "--all"])
            assert self.AZURE_NOPASS_IDP_NAME in show_out.stdout_text
            assert "private_key_jwt" in show_out.stdout_text.lower()
            nopass_idp_added = True

            self._ensure_idp_user(
                self.AZURE_NOPASS_IDP_NAME,
                self.AZURE_NOPASS_IPA_USERNAME,
                "azurenopass",
                "UserNopass",
            )
            self._azure_device_kinit(self.AZURE_NOPASS_IPA_USERNAME)
        finally:
            self._teardown_azure_installed_cert_idp(
                app_object_id=app_object_id,
                pem_bytes=pem_bytes,
                token=token,
                idp_name=self.AZURE_NOPASS_IDP_NAME,
                idp_added=nopass_idp_added,
                p12_path=IDP_CLIENT_P12_NOPASS_IPA_PATH,
                p12_on_master=p12_on_master,
                workdir=workdir,
            )

    def test_idp_add_defaults_to_client_secret(self):
        """TC-A03: ``idp-add`` without auth method uses client secret."""
        idp_name = "azure-tc-a03"
        try:
            self._add_azure_secret_idp(idp_name)
            show = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            assert "secret:" in show.stdout_text.lower()
            assert "private_key_jwt" not in show.stdout_text.lower()
            assert "tls_client_auth" not in show.stdout_text.lower()
            self._assert_idp_ldap_client_auth_absent(idp_name)
            self._ensure_idp_user(idp_name, "testazurea03", "azure", "A03")
            self._azure_device_kinit("testazurea03")
        finally:
            self._teardown_azure_secret_idp_test(
                idp_name, ipa_user="testazurea03")

    def test_export_public_certificate(self):
        """
        TC-A05: ``ipa idp-show <name> --out=<file>`` exports the public cert.

        Writes PEM from ``userCertificate`` only (no private key),
        as in https://github.com/freeipa/freeipa/pull/8308. Users with
        ``System: Read External IdP server`` may export; users without IdP
        read permission cannot.
        """
        idp_name = "azure-tc-a05"
        out_admin = "/tmp/idp-tc-a05-export.crt"
        out_read = "/tmp/idp-tc-a05-export-read.crt"
        out_noperm = "/tmp/idp-tc-a05-export-noperm.crt"
        token = app_object_id = pem_bytes = workdir = None
        perm_setup = False
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name,
                "testazurea05",
                "/tmp/idp-tc-a05.p12",
                first="azure",
                last="A05",
            )

            orig_cert = os.path.join(workdir, "idp-client.crt")
            orig_fp = self.master.run_command(
                ["openssl", "x509", "-in", orig_cert,
                 "-noout", "-fingerprint", "-sha256"])

            self.master.run_command(
                ["ipa", "idp-show", idp_name, "--out=%s" % out_admin])
            exported = self.master.get_file_contents(out_admin)
            self.master.run_command(
                ["openssl", "x509", "-in", out_admin, "-text", "-noout"])
            assert b"BEGIN CERTIFICATE" in exported
            assert b"BEGIN PRIVATE KEY" not in exported
            assert b"BEGIN RSA PRIVATE KEY" not in exported
            exp_fp = self.master.run_command(
                ["openssl", "x509", "-in", out_admin,
                 "-noout", "-fingerprint", "-sha256"])
            assert exp_fp.stdout_text.strip() == orig_fp.stdout_text.strip()

            self._setup_idp_permission_users()
            perm_setup = True
            tasks.kinit_as_user(
                self.master, self.IDP_PERM_READ_USER, "Secret123")
            self.master.run_command(
                ["ipa", "idp-show", idp_name, "--out=%s" % out_read])
            read_fp = self.master.run_command(
                ["openssl", "x509", "-in", out_read,
                 "-noout", "-fingerprint", "-sha256"])
            assert read_fp.stdout_text.strip() == orig_fp.stdout_text.strip()

            tasks.kinit_as_user(
                self.master, self.IDP_PERM_NONE_USER, "Secret123")
            denied = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--out=%s" % out_noperm],
                raiseonerr=False,
            )
            assert denied.returncode != 0
            assert "insufficient access" in denied.stderr_text
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user="testazurea05" if not perm_setup else None,
                p12_paths=("/tmp/idp-tc-a05.p12",),
                workdirs=(workdir,),
                extra_paths=(out_admin, out_read, out_noperm),
                perm_users=("testazurea05",) if perm_setup else (),
            )

    def test_migrate_secret_to_private_key_jwt(self):
        """
        TC-C01 / Story S3: migrate client_secret IdP to ``private_key_jwt``.

        ``ipaIdpClientAuth`` and cert attributes appear; secret stores P12
        passphrase; device-flow kinit still works.
        """
        idp_name = self.AZURE_MIGRATE_IDP_NAME
        ipa_user = self.AZURE_MIGRATE_IPA_USERNAME
        workdir = token = app_object_id = pem_bytes = None
        try:
            self._add_azure_secret_idp(idp_name)
            self._ensure_idp_user(idp_name, ipa_user, "azure", "Migrate")
            self._azure_device_kinit(ipa_user)

            workdir = generate_idp_client_openssl_bundle(self.master)
            pem_bytes = self.master.get_file_contents(
                os.path.join(workdir, "idp-client.crt"))
            token, app_object_id = entra_upload_client_cert(
                self.cfg, pem_bytes)
            p12_src = os.path.join(workdir, "idp-client.p12")
            rotate_path = "/tmp/idp-migrate-tc-c01.p12"
            self.master.run_command(["cp", p12_src, rotate_path])
            self.master.run_command(["chmod", "600", rotate_path])

            tasks.kinit_admin(self.master)
            self.master.run_command(
                [
                    "ipa", "idp-mod", idp_name,
                    "--client-auth-method=private_key_jwt",
                    "--client-cert-p12-file=%s" % rotate_path,
                ],
                stdin_text=p12_passphrase_stdin(),
            )
            show = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            assert "private_key_jwt" in show.stdout_text.lower()
            self._assert_idp_ldap_client_auth_present(idp_name)
            self._azure_device_kinit(ipa_user, retries=10)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=("/tmp/idp-migrate-tc-c01.p12",),
                workdirs=(workdir,),
            )

    def test_migrate_cert_to_client_secret(self):
        """TC-C02: migrate certificate IdP back to ``client_secret``."""
        idp_name = "azure-tc-c02"
        ipa_user = "testazurec02"
        new_secret = "NewSecretForC02!"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name,
                ipa_user,
                "/tmp/idp-tc-c02.p12",
                first="azure",
                last="C02",
            )

            self._azure_device_kinit(ipa_user)

            tasks.kinit_admin(self.master)
            self.master.run_command(
                [
                    "ipa", "idp-mod", idp_name,
                    "--client-auth-method=client_secret",
                    "--secret",
                ],
                stdin_text="%s\n%s\n" % (new_secret, new_secret),
            )
            show = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            show_lower = show.stdout_text.lower()
            assert "secret:" in show_lower
            assert "private_key_jwt" not in show_lower
            self._assert_idp_ldap_client_auth_absent(idp_name)
            self._azure_device_kinit(ipa_user)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=("/tmp/idp-tc-c02.p12",),
                workdirs=(workdir,),
            )

    def test_certificate_rotation(self):
        """Story S5: ``idp-mod`` replaces PKCS#12; auth uses the new key."""
        idp_name = self.AZURE_ROTATE_IDP_NAME
        ipa_user = self.AZURE_ROTATE_IPA_USERNAME
        p12_path = "/tmp/idp-rotate-story-s5.p12"
        token = app_object_id = pem_bytes1 = pem_bytes2 = None
        workdir1 = workdir2 = None
        try:
            workdir1 = generate_idp_client_openssl_bundle(self.master)
            pem_bytes1 = self.master.get_file_contents(
                os.path.join(workdir1, "idp-client.crt"))
            token, app_object_id = entra_upload_client_cert(
                self.cfg, pem_bytes1,
                test_method_name=calling_test_name("-v1"))
            p12_src = os.path.join(workdir1, "idp-client.p12")
            self.master.run_command(["cp", p12_src, p12_path])
            self.master.run_command(["chmod", "600", p12_path])
            tasks.kinit_admin(self.master)
            self.master.run_command(
                [
                    "ipa", "idp-add", idp_name,
                    "--provider=microsoft",
                    "--organization=%s" % self.cfg.azure_tenant_id,
                    "--issuer=%s" % microsoft_issuer_url(self.cfg),
                    "--client-id=%s" % self.cfg.azure_admin_client_id,
                    "--client-auth-method=private_key_jwt",
                    "--client-cert-p12-file=%s" % p12_path,
                ],
                stdin_text=p12_passphrase_stdin(),
            )
            self._ensure_idp_user(idp_name, ipa_user, "azure", "Rotate")
            show_v1 = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            assert "private_key_jwt" in show_v1.stdout_text.lower()

            workdir2 = generate_idp_client_openssl_bundle(
                self.master,
                workdir="/tmp/idp-openssl-rotate-%06d"
                % random.randint(0, 999999),
            )
            pem_bytes2 = self.master.get_file_contents(
                os.path.join(workdir2, "idp-client.crt"))
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes2,
                display_name=new_idp_client_graph_cert_display_name(
                    calling_test_name("-v2")),
            )
            p12_src2 = os.path.join(workdir2, "idp-client.p12")
            self.master.run_command(["cp", p12_src2, p12_path])
            tasks.kinit_admin(self.master)
            self.master.run_command(
                [
                    "ipa", "idp-mod", idp_name,
                    "--client-cert-p12-file=%s" % p12_path,
                ],
                stdin_text=p12_passphrase_stdin(),
            )
            show_v2 = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            assert show_v2.stdout_text != show_v1.stdout_text
            self._assert_idp_ldap_client_auth_present(idp_name)
            self._azure_device_kinit(ipa_user)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes1, pem_bytes2),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir1, workdir2),
            )

    def test_idp_cert_replication(self):
        """TC-E01: cert IdP data replicates; kinit from client succeeds."""
        idp_name = "azure-tc-e01"
        ipa_user = "testazuree01"
        p12_path = "/tmp/idp-tc-e01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="E01",
            )

            tasks.wait_for_replication(self.master.ldap_connect())
            tasks.wait_for_replication(self.replica.ldap_connect())
            self._assert_idp_ldap_client_auth_present(
                idp_name, ldap_host=self.replica)
            replica_show = self.replica.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            assert "private_key_jwt" in replica_show.stdout_text.lower()
            self._azure_device_kinit(ipa_user)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
            )

    def _ensure_idp_test_privilege(self, privilege_name, permission_name):
        """
        Create a test privilege that includes a PR #8308 managed *permission*.

        ``ipa role-add-privilege`` expects privilege names, not permissions.
        """
        self.master.run_command(
            ["ipa", "privilege-del", privilege_name], raiseonerr=False)
        self.master.run_command(["ipa", "privilege-add", privilege_name])
        add_perm = self.master.run_command(
            [
                "ipa", "privilege-add-permission", privilege_name,
                "--permissions=%s" % permission_name,
            ],
            raiseonerr=False,
        )
        if add_perm.returncode != 0:
            combined = add_perm.stderr_text + add_perm.stdout_text
            pytest.skip(
                "IdP permission %r unavailable (need PR #8308): %s"
                % (permission_name, combined.strip()))

    def _teardown_idp_permission_users(self, *extra_users):
        """Remove IdP permission test users, roles, and custom privileges."""
        tasks.kinit_admin(self.master)
        perm_users = (
            self.IDP_PERM_NONE_USER,
            self.IDP_PERM_READ_USER,
            self.IDP_PERM_SECRET_USER,
        ) + tuple(extra_users)
        for role in (self.IDP_PERM_ROLE_READ, self.IDP_PERM_ROLE_SECRET):
            self.master.run_command(
                ["ipa", "role-del", role], raiseonerr=False)
        for priv in (IDP_PRIV_READ_SERVER, IDP_PRIV_READ_CLIENT_SECRET):
            self.master.run_command(
                ["ipa", "privilege-del", priv], raiseonerr=False)
        for user in perm_users:
            self.master.run_command(
                ["ipa", "user-del", user], raiseonerr=False)

    def _setup_idp_permission_users(self):
        """
        Create users/roles for PR #8308 IdP permission tests.

        ``idpread`` → privilege with ``System: Read External IdP server`` only;
        ``idpsecretread`` → that plus
        ``System: Read External IdP server client secret``.
        """
        tasks.kinit_admin(self.master)
        self._ensure_idp_test_privilege(
            IDP_PRIV_READ_SERVER, IDP_PERM_READ_SERVER)
        self._ensure_idp_test_privilege(
            IDP_PRIV_READ_CLIENT_SECRET, IDP_PERM_READ_CLIENT_SECRET)
        perm_users = (
            self.IDP_PERM_NONE_USER,
            self.IDP_PERM_READ_USER,
            self.IDP_PERM_SECRET_USER,
        )
        for user in perm_users:
            self.master.run_command(
                ["ipa", "user-del", user], raiseonerr=False)
        for user in perm_users:
            tasks.create_active_user(
                self.master, user, "Secret123", first="idp", last="perm")
        role_configs = (
            (self.IDP_PERM_ROLE_READ,
             [IDP_PRIV_READ_SERVER],
             self.IDP_PERM_READ_USER),
            (self.IDP_PERM_ROLE_SECRET,
             [IDP_PRIV_READ_SERVER, IDP_PRIV_READ_CLIENT_SECRET],
             self.IDP_PERM_SECRET_USER),
        )
        for role, privs, member_user in role_configs:
            # Refresh admin ticket after user creation above.
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "role-del", role], raiseonerr=False)
            self.master.run_command(
                ["ipa", "role-add", role], raiseonerr=False)
            for user in perm_users:
                self.master.run_command(
                    ["ipa", "role-remove-member", role,
                     "--users=%s" % user],
                    raiseonerr=False,
                )
            for priv in privs:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "role-add-privilege", role,
                     "--privileges=%s" % priv],
                    raiseonerr=False,
                )
            self.master.run_command(
                ["ipa", "role-add-member", role,
                 "--users=%s" % member_user],
                raiseonerr=False,
            )

    def _setup_idp_modify_admin(self):
        """
        User with ``External IdP server Administrators`` only (TC-PERM).

        Not a member of the IPA admins role; can Add/Mod/Del IdP references.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "user-del", IDP_PERM_MODIFY_USER], raiseonerr=False)
        tasks.create_active_user(
            self.master,
            IDP_PERM_MODIFY_USER,
            IDP_PERM_USER_PASSWORD,
            first="idp",
            last="modify",
        )
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "role-del", IDP_PERM_ROLE_MODIFY], raiseonerr=False)
        self.master.run_command(["ipa", "role-add", IDP_PERM_ROLE_MODIFY])
        self.master.run_command(
            [
                "ipa", "role-add-privilege", IDP_PERM_ROLE_MODIFY,
                "--privileges=%s" % IDP_PRIV_EXTERNAL_IDP_ADMIN,
            ],
            raiseonerr=False,
        )
        self.master.run_command(
            [
                "ipa", "role-add-member", IDP_PERM_ROLE_MODIFY,
                "--users=%s" % IDP_PERM_MODIFY_USER,
            ],
        )

    def _teardown_idp_modify_admin(self):
        """Remove modify-admin test user and role."""
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "role-del", IDP_PERM_ROLE_MODIFY], raiseonerr=False)
        self.master.run_command(
            ["ipa", "user-del", IDP_PERM_MODIFY_USER], raiseonerr=False)

    def test_idp_show_no_permission(self):
        """TC-D01: user without IdP permissions cannot ``idp-show``."""
        idp_name = "azure-tc-d01"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, "testazured01", "/tmp/idp-tc-d01.p12",
                first="azure", last="D01",
            )

            self._setup_idp_permission_users()
            tasks.kinit_as_user(
                self.master, self.IDP_PERM_NONE_USER, "Secret123")
            result = self.master.run_command(
                ["ipa", "idp-show", idp_name], raiseonerr=False)
            assert result.returncode != 0
            assert "insufficient access" in result.stderr_text
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                p12_paths=("/tmp/idp-tc-d01.p12",),
                workdirs=(workdir,),
                perm_users=("testazured01",),
            )

    def test_idp_read_permission_hides_secrets(self):
        """
        TC-D02: ``System: Read External IdP server`` sees metadata only.

        Per PR #8308, this permission includes ``usercertificate`` and
        ``ipaidpclientauthmethod`` but not ``userpkcs12`` / secret attrs.
        ``idp-show --all`` is not used (it requests protected attributes).
        """
        idp_name = "azure-tc-d02"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, "testazured02", "/tmp/idp-tc-d02.p12",
                first="azure", last="D02",
            )

            self._setup_idp_permission_users()
            tasks.kinit_as_user(
                self.master, self.IDP_PERM_READ_USER, "Secret123")
            show = self.master.run_command(["ipa", "idp-show", idp_name])
            show_lower = show.stdout_text.lower()
            assert "private_key_jwt" in show_lower
            assert IDP_CLIENT_P12_PASSWORD not in show.stdout_text
            basedn = self.master.domain.basedn
            bind_dn = "uid=%s,cn=users,cn=accounts,%s" % (
                self.IDP_PERM_READ_USER, basedn)
            ldap_result = tasks.run_ldapsearch(
                self.master,
                bind_dn,
                "Secret123",
                idp_ldap_dn(self.master, idp_name),
                ["userPKCS12", "ipaidpclientsecret"],
                scope="base",
                raiseonerr=False,
            )
            ldap_text = ldap_result.stdout_text + ldap_result.stderr_text
            assert not ldap_output_has_attribute_value(ldap_text, "userPKCS12")
            assert not ldap_output_has_attribute_value(
                ldap_text, "ipaidpclientsecret")
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                p12_paths=("/tmp/idp-tc-d02.p12",),
                workdirs=(workdir,),
                perm_users=("testazured02",),
            )

    def test_idp_read_secret_permission(self):
        """
        TC-D03: ``System: Read External IdP server client secret`` may use
        ``idp-show --all`` (sensitive fields still masked in CLI output).
        """
        idp_name = "azure-tc-d03"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, "testazured03", "/tmp/idp-tc-d03.p12",
                first="azure", last="D03",
            )

            self._setup_idp_permission_users()
            tasks.kinit_as_user(
                self.master, self.IDP_PERM_SECRET_USER, "Secret123")
            show = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            assert show.returncode == 0
            show_lower = show.stdout_text.lower()
            assert "private_key_jwt" in show_lower
            assert IDP_CLIENT_P12_PASSWORD not in show.stdout_text
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                p12_paths=("/tmp/idp-tc-d03.p12",),
                workdirs=(workdir,),
                perm_users=("testazured03",),
            )

    def test_ldap_cannot_read_userpkcs12(self):
        """TC-D04: non-privileged LDAP bind cannot read ``userPKCS12``."""
        idp_name = "azure-tc-d04"
        basedn = self.master.domain.basedn
        bind_dn = "uid=%s,cn=users,cn=accounts,%s" % (
            self.IDP_PERM_NONE_USER, basedn)
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, "testazured04", "/tmp/idp-tc-d04.p12",
                first="azure", last="D04",
            )

            self._setup_idp_permission_users()
            result = tasks.run_ldapsearch(
                self.master,
                bind_dn,
                "Secret123",
                idp_ldap_dn(self.master, idp_name),
                ["userPKCS12"],
                scope="base",
                raiseonerr=False,
            )
            ldap_text = result.stdout_text + result.stderr_text
            assert not ldap_output_has_attribute_value(ldap_text, "userPKCS12")
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                p12_paths=("/tmp/idp-tc-d04.p12",),
                workdirs=(workdir,),
                perm_users=("testazured04",),
            )

    def test_logging_does_not_leak_secrets(self):
        """TC-D06: debug/API logs redact PKCS#12 and private key material."""
        idp_name = "azure-tc-d06"
        ipa_user = "testazured06"
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple(),
        )
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, "/tmp/idp-tc-d06.p12",
                first="azure", last="D06",
            )

            journal = self.master.run_command(
                ["journalctl", "-g", "IPA.API", "--since=%s" % since])
            assert '"userpkcs12": "********"' in journal.stdout_text
            self._azure_device_kinit(ipa_user)
            log_scan = self.master.run_command(
                ["journalctl", "--since=%s" % since], raiseonerr=False)
            text = log_scan.stdout_text + log_scan.stderr_text
            assert IDP_CLIENT_P12_PASSWORD not in text
            assert "BEGIN PRIVATE KEY" not in text
            assert "BEGIN RSA PRIVATE KEY" not in text
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=("/tmp/idp-tc-d06.p12",),
                workdirs=(workdir,),
            )

    def test_idp_modify_admin_can_add_cert_idp(self):
        """TC-PERM-01: External IdP admin can ``idp-add`` with PKCS#12."""
        idp_name = "azure-tc-perm01"
        ipa_user = "testazureperm01"
        p12_path = "/tmp/idp-tc-perm01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            workdir = generate_idp_client_openssl_bundle(self.master)
            pem_bytes = self.master.get_file_contents(
                os.path.join(workdir, "idp-client.crt"))
            token, app_object_id = entra_upload_client_cert(
                self.cfg, pem_bytes)
            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(["cp", p12_src, p12_path])
            self.master.run_command(["chmod", "600", p12_path])
            self._setup_idp_modify_admin()
            tasks.kinit_as_user(
                self.master, IDP_PERM_MODIFY_USER, IDP_PERM_USER_PASSWORD)
            result = self.master.run_command(
                [
                    "ipa", "idp-add", idp_name,
                    "--provider=microsoft",
                    "--organization=%s" % self.cfg.azure_tenant_id,
                    "--issuer=%s" % microsoft_issuer_url(self.cfg),
                    "--client-id=%s" % self.cfg.azure_admin_client_id,
                    "--client-auth-method=private_key_jwt",
                    "--client-cert-p12-file=%s" % p12_path,
                ],
                stdin_text=p12_passphrase_stdin(),
                raiseonerr=False,
            )
            assert result.returncode == 0, (
                "idp-add with PKCS#12 failed for External IdP admin "
                "(check userpkcs12 on Modify permission): %s"
                % result.stderr_text)
            tasks.kinit_admin(self.master)
            self._assert_idp_ldap_client_auth_present(idp_name)
            self._ensure_idp_user(
                idp_name, ipa_user, "azure", "Perm01")
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
                modify_admin=True,
            )

    def test_idp_modify_admin_can_rotate_pkcs12(self):
        """TC-PERM-02: External IdP admin can ``idp-mod`` PKCS#12 bundle."""
        idp_name = "azure-tc-perm02"
        ipa_user = "testazureperm02"
        p12_path = "/tmp/idp-tc-perm02.p12"
        token = app_object_id = pem_bytes1 = pem_bytes2 = None
        workdir1 = workdir2 = None
        try:
            token, app_object_id, pem_bytes1, workdir1 = (
                self._add_azure_cert_idp(
                    idp_name, ipa_user, p12_path,
                    first="azure", last="Perm02",
                )
            )

            workdir2 = generate_idp_client_openssl_bundle(
                self.master,
                workdir="/tmp/idp-openssl-perm02-%06d"
                % random.randint(0, 999999),
            )
            pem_bytes2 = self.master.get_file_contents(
                os.path.join(workdir2, "idp-client.crt"))
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes2,
                display_name=new_idp_client_graph_cert_display_name(
                    calling_test_name("-rotate")),
            )
            p12_src2 = os.path.join(workdir2, "idp-client.p12")
            self.master.run_command(["cp", p12_src2, p12_path])
            self._setup_idp_modify_admin()
            tasks.kinit_as_user(
                self.master, IDP_PERM_MODIFY_USER, IDP_PERM_USER_PASSWORD)
            result = self.master.run_command(
                [
                    "ipa", "idp-mod", idp_name,
                    "--client-cert-p12-file=%s" % p12_path,
                ],
                stdin_text=p12_passphrase_stdin(),
                raiseonerr=False,
            )
            assert result.returncode == 0, (
                "idp-mod PKCS#12 failed for External IdP admin: %s"
                % result.stderr_text)
            tasks.kinit_admin(self.master)
            self._assert_idp_ldap_client_auth_present(idp_name)
            # test idp-del
            tasks.kinit_as_user(
                self.master, IDP_PERM_MODIFY_USER, IDP_PERM_USER_PASSWORD)
            result_del = self.master.run_command(
                [
                    "ipa", "idp-del", idp_name
                ],
                raiseonerr=False
            )
            assert result_del.returncode == 0
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes1, pem_bytes2),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir1, workdir2),
                modify_admin=True,
            )

    def test_idp_mod_wrong_secret_only_fails(self):
        """TC-SEC-01: ``idp-mod --secret`` must not break cert auth."""
        idp_name = "azure-tc-sec01"
        ipa_user = "testazuresec01"
        p12_path = "/tmp/idp-tc-sec01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="Sec01",
            )

            self._azure_device_kinit(ipa_user)
            tasks.kinit_admin(self.master)
            mod = self.master.run_command(
                ["ipa", "idp-mod", idp_name, "--secret"],
                stdin_text="WrongPassword\nWrongPassword\n",
                raiseonerr=False,
            )
            if mod.returncode != 0:
                assert_idp_cli_error(
                    mod.stderr_text,
                    "validation",
                    "cannot decode",
                    "pkcs12",
                )
            else:
                self._azure_device_kinit(ipa_user)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
            )

    def test_idp_mod_secret_only_without_p12_rejected(self):
        """TC-SEC-02: changing passphrase without P12 should fail."""
        idp_name = "azure-tc-sec02"
        ipa_user = "testazuresec02"
        p12_path = "/tmp/idp-tc-sec02.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="Sec02",
            )

            tasks.kinit_admin(self.master)
            mod = self.master.run_command(
                ["ipa", "idp-mod", idp_name, "--secret"],
                stdin_text=p12_passphrase_stdin(),
                raiseonerr=False,
            )
            assert mod.returncode != 0
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
            )

    def test_idp_mod_p12_on_client_secret_idp_rejected(self):
        """TC-MOD-01: P12 on ``client_secret`` IdP needs method change."""
        idp_name = "azure-tc-mod01"
        p12_path = "/tmp/idp-tc-mod01.p12"
        workdir = None
        try:
            self._add_azure_secret_idp(idp_name)
            workdir = generate_idp_client_openssl_bundle(self.master)
            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(["cp", p12_src, p12_path])
            self.master.run_command(["chmod", "600", p12_path])
            tasks.kinit_admin(self.master)
            result = self.master.run_command(
                [
                    "ipa", "idp-mod", idp_name,
                    "--client-cert-p12-file=%s" % p12_path,
                ],
                stdin_text=p12_passphrase_stdin(),
                raiseonerr=False,
            )
            assert result.returncode != 0
            assert_idp_cli_error(
                result.stderr_text,
                IDP_CLI_MUTUALLY_EXCLUSIVE_P12,
                "mutually exclusive",
            )
            self._assert_idp_ldap_client_auth_absent(idp_name)
        finally:
            self._teardown_azure_secret_idp_test(
                idp_name, p12_paths=(p12_path,), workdirs=(workdir,))

    def test_idp_mod_client_secret_and_p12_rejected(self):
        """TC-MOD-03: ``client_secret`` + P12 in one ``idp-mod`` rejected."""
        idp_name = "azure-tc-mod03"
        ipa_user = "testazuremod03"
        p12_path = "/tmp/idp-tc-mod03.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="Mod03",
            )

            tasks.kinit_admin(self.master)
            result = self.master.run_command(
                [
                    "ipa", "idp-mod", idp_name,
                    "--client-auth-method=client_secret",
                    "--client-cert-p12-file=%s" % p12_path,
                ],
                stdin_text=p12_passphrase_stdin(),
                raiseonerr=False,
            )
            assert result.returncode != 0
            assert_idp_cli_error(
                result.stderr_text,
                IDP_CLI_MUTUALLY_EXCLUSIVE_P12,
                "mutually exclusive",
            )
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
            )

    def test_migrate_cert_to_client_secret_without_secret(self):
        """TC-MIG-01: revert to ``client_secret`` without ``--secret``."""
        idp_name = "azure-tc-mig01"
        ipa_user = "testazuremig01"
        p12_path = "/tmp/idp-tc-mig01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="Mig01",
            )

            self._azure_device_kinit(ipa_user)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "idp-mod", idp_name,
                 "--client-auth-method=client_secret"],
            )
            self._assert_idp_ldap_client_auth_absent(idp_name)
            self._azure_device_kinit(ipa_user)
            self.master.run_command(
                ["ipa", "idp-mod", idp_name, "--secret"],
                stdin_text="%s\n%s\n"
                % (self.cfg.azure_admin_client_secret,
                   self.cfg.azure_admin_client_secret),
            )
            self._azure_device_kinit(ipa_user)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
            )

    def test_idp_show_out_on_client_secret_idp(self):
        """TC-OUT-02: ``--out`` on ``client_secret``."""
        idp_name = "azure-tc-out02"
        out_path = "/tmp/idp-tc-out02-no-cert.pem"
        try:
            self._add_azure_secret_idp(idp_name)
            tasks.kinit_admin(self.master)
            self.master.run_command(["rm", "-f", out_path], raiseonerr=False)
            result = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--out=%s" % out_path],
                raiseonerr=False,
            )
            combined = result.stdout_text + result.stderr_text
            assert result.returncode == 0 and (
                "ignoring --out" in combined.lower())
        finally:
            self._teardown_azure_secret_idp_test(
                idp_name, extra_paths=(out_path,))

    def test_idp_cert_backup_restore(self):
        """TC-BKP-01: backup/restore preserve cert-based IdP data."""
        idp_name = "azure-tc-bkp"
        ipa_user = "testazurebkp"
        p12_path = "/tmp/idp-tc-bkp.p12"
        token = app_object_id = pem_bytes = workdir = None
        backup_path = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="Bkp",
            )

            self._azure_device_kinit(ipa_user)
            backup_path = tasks.get_backup_dir(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(["ipa", "user-del", ipa_user])
            self.master.run_command(["ipa", "idp-del", idp_name])
            self.master.run_command(
                ["ipa-restore", backup_path],
                stdin_text=self.master.config.dirman_password + "\nyes",
            )
            tasks.kinit_admin(self.master)
            self._assert_idp_ldap_client_auth_present(idp_name)
            show = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--all"])
            assert "private_key_jwt" in show.stdout_text.lower()
            tasks.clear_sssd_cache(self.master)
            tasks.wait_for_sssd_domain_status_online(self.master)
            wait_for_ipa_user_lookup_id(self.master, ipa_user)
            self._azure_device_kinit(ipa_user)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
                backup_paths=(backup_path,),
            )

    def test_idp_show_not_displays_cert_metadata(self):
        """
        TC-DISP-01: ``idp-show`` not displays certificate subject/issuer/dates.

        Certificate metadata comes from ``usercertificate`` and is visible to
        principals with ``System: Read External IdP server`` (see idp-client-
        authentication design); it is not shown without that permission.
        """
        idp_name = "azure-tc-disp01"
        ipa_user = "testazuredisp01"
        p12_path = "/tmp/idp-tc-disp01.p12"
        token = app_object_id = pem_bytes = workdir = None
        perm_setup = False
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="Disp01",
            )

            crt_path = os.path.join(workdir, "idp-client.crt")
            openssl_out = self.master.run_command(
                [
                    "openssl", "x509", "-in", crt_path,
                    "-noout", "-subject", "-issuer",
                ],
            ).stdout_text
            self._setup_idp_permission_users()
            perm_setup = True
            tasks.kinit_as_user(
                self.master, self.IDP_PERM_READ_USER, "Secret123")
            show = self.master.run_command(["ipa", "idp-show", idp_name])
            show_text = show.stdout_text
            show_lower = show_text.lower()
            assert "certificate subject" not in show_lower
            assert "certificate issuer" not in show_lower
            assert "certificate expiration" not in show_lower
            for line in openssl_out.splitlines():
                if line.startswith("subject="):
                    cn_fragment = line.split("CN = ", 1)[-1].strip()
                    if cn_fragment:
                        assert cn_fragment not in show_text
                elif line.startswith("issuer="):
                    issuer_fragment = line.split("CN = ", 1)[-1].strip()
                    if issuer_fragment:
                        assert issuer_fragment not in show_text
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user if not perm_setup else None,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
                perm_users=(ipa_user,) if perm_setup else (),
            )

    def test_switch_jwt_tls_without_reupload_p12(self):
        """TC-MOD-04: switch tls/jwt auth methods without new P12."""
        idp_name = "azure-tc-mod04"
        ipa_user = "testazuremod04"
        p12_path = "/tmp/idp-tc-mod04.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name,
                ipa_user,
                p12_path,
                auth_method="tls_client_auth",
                first="azure",
                last="Mod04",
            )

            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "idp-mod", idp_name,
                 "--client-auth-method=private_key_jwt"],
            )
            self.master.run_command(
                ["ipa", "idp-mod", idp_name,
                 "--client-auth-method=tls_client_auth"],
            )
            show = self.master.run_command(["ipa", "idp-show", idp_name])
            assert "tls_client_auth" in show.stdout_text.lower()
            self._assert_idp_ldap_client_auth_present(idp_name)
            self._azure_device_kinit(ipa_user)
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                ipa_user=ipa_user,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
            )

    def test_ldap_modify_userpkcs12_denied_without_secret_perm(self):
        """TC-PERM-03: ``idpread`` cannot LDAP-modify ``userPKCS12``."""
        idp_name = "azure-tc-ldap03"
        ipa_user = "testazureldap03"
        p12_path = "/tmp/idp-tc-ldap03.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            (
                token, app_object_id, pem_bytes, workdir,
            ) = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path,
                first="azure", last="Ldap03",
            )

            self._setup_idp_permission_users()
            basedn = self.master.domain.basedn
            bind_dn = "uid=%s,cn=users,cn=accounts,%s" % (
                self.IDP_PERM_READ_USER, basedn)
            dn = idp_ldap_dn(self.master, idp_name)
            ldif = "\n".join([
                "dn: %s" % dn,
                "changetype: modify",
                "add: userPKCS12",
                "userPKCS12:: dmFsdWU=",
                "",
            ])
            result = self.master.run_command(
                [
                    "ldapmodify", "-x",
                    "-D", bind_dn,
                    "-w", IDP_PERM_USER_PASSWORD,
                ],
                stdin_text=ldif,
                raiseonerr=False,
            )
            ldap_text = result.stdout_text + result.stderr_text
            assert result.returncode != 0 or (
                "insufficient access" in ldap_text.lower()
                or "no such attribute" in ldap_text.lower()
                or "constraint violation" in ldap_text.lower()
            )
        finally:
            self._teardown_azure_cert_idp_test(
                app_object_id=app_object_id,
                pem_certificates=(pem_bytes,),
                token=token,
                idp_name=idp_name,
                p12_paths=(p12_path,),
                workdirs=(workdir,),
                perm_users=(ipa_user,),
            )
