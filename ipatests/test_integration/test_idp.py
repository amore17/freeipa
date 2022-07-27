from __future__ import absolute_import

import time
import pytest
import re
import os

import textwrap
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks, create_quarkus

user_code_script = textwrap.dedent("""
from selenium import webdriver
from datetime import datetime
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
options = Options()
options.headless = True
driver = webdriver.Firefox(executable_path="/opt/geckodriver", options=options)
verification_uri = "{uri}"
driver.get(verification_uri)
try:
    element = WebDriverWait(driver, 90).until(
        EC.presence_of_element_located((By.ID, "ipausername")))
    driver.find_element(By.ID, "ipausername").send_keys("testuser1")
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


idps = {
    'github': {
        'provider': 'github',
        'idp_name': 'testgithub',
        'ipausername': 'testusergithub',
        'user_id': os.environ['github_user_id'],
        'client_id': os.environ['github_client_id'],
        'client_secret': os.environ['github_secret'],
    },
    'azure': {
        'provider': 'microsoft',
        'idp_name': 'testazure',
        'ipausername': 'testuserazure',
        'user_id': os.environ['azure_user_id'],
        'client_id': os.environ['azure_client_id'],
        'client_secret': os.environ['azure_secret'],
        'client_org': os.environ['azure_org'],
    },
    'google': {
        'provider': 'google',
        'idp_name': 'testgoogle',
        'ipausername': 'testusergoogle',
        'user_id': os.environ['google_user_id'],
        'client_id': os.environ['google_client_id'],
        'client_secret': os.environ['google_secret'],
    },
    'okta': {
        'provider': 'okta',
        'idp_name': 'testokta',
        'ipausername': 'testuserokta',
        'user_id': os.environ['okta_user_id'],
        'client_id': os.environ['okta_client_id'],
        'client_secret': os.environ['okta_secret'],
        'base_url': os.environ['okta_base_url'],
    },
}


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
    # create armor for FAST
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


def kinit_prompt_idp(host, user):
    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    cmd = ["KRB5_TRACE=/dev/stdout", "kinit", "-T", ARMOR, user]

    with host.spawn_expect(cmd, default_timeout=100) as e:
        e.expect('Authenticate (.+) and press ENTER.:')
        e.sendline('\n')
        e.expect_exit(ok_returncode=1, ignore_remaining_output=True)
        output = e.get_last_output()
    preauth_failed = "kinit: Preauthentication failed while getting initial credentials"
    assert preauth_failed in output


def add_idp(host, idp_name, provider, client_id,
            user_id, ipausername,
            secret=None, org=None,
            base_url=None):
    tasks.kdestroy_all(host)
    tasks.kinit_admin(host)
    cmd = ["ipa", "idp-add", idp_name, "--provider", provider,
           "--client-id", client_id]

    if org:
        cmd.extend(["--organization", org])

    if base_url:
        cmd.extend(["--base-url", base_url])

    if secret:
        cmd.append('--secret')
        stdin_text = '{0}\n{0}\n'.format(secret)
    else:
        stdin_text = None

    host.run_command(cmd, stdin_text=stdin_text)

    if user_id:
        tasks.user_add(host, ipausername,
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user-id=" + user_id,
                                   "--idp=" + idp_name]
                       )


class TestIDPKeycloak(IntegrationTest):

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

    @classmethod
    def uninstall(cls, mh):
        pass

    def cleanupidp(self, idp):
        """Fixture to remove any users and idp added as part of the tests.
           It isn't necessary to remove user and idp
           Ignore all errors.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-del', idps[idp]['ipausername']],
                                raiseonerr=False)
        self.master.run_command(["ipa", "idp-del", idps[idp]['idp_name']],
                                raiseonerr=False)

    @pytest.mark.skipif(
        idps['github']['client_id'] is None,
        reason="Test requires environment variables idp_name, provider,"
               "client_id, user_id, client_secret"
    )
    @pytest.mark.parametrize('idp', ['github', 'google'])
    def test_kinit_prompt(self, idp):
        """
        Test case to check that for kinit prompt is
        given for authentication with github, google idp
        """
        try:
            add_idp(self.master,
                    idp_name=idps[idp]['idp_name'],
                    provider=idps[idp]['provider'],
                    client_id=idps[idp]['client_id'],
                    user_id=idps[idp]['user_id'],
                    secret=idps[idp]['client_secret'],
                    ipausername=idps[idp]['ipausername']
                    )
            kinit_prompt_idp(self.master, idps[idp]['ipausername'])
        finally:
            self.cleanupidp(idp)

    @pytest.mark.skipif(
        idps['azure']['client_id'] is None,
        reason="Test requires environment variables idp_name, provider,"
               "client_id, user_id, client_secret, client_org"
    )
    def test_kinit_prompt_azure(self):
        """
        Test case to check that for kinit prompt is
        given for authentication with azure idp
        """
        try:
            add_idp(self.master,
                    idp_name=idps['azure']['idp_name'],
                    provider=idps['azure']['provider'],
                    client_id=idps['azure']['client_id'],
                    user_id=idps['azure']['user_id'],
                    ipausername=idps['azure']['ipausername'],
                    secret=idps['azure']['client_secret'],
                    org=idps['azure']['client_org']
                    )
            kinit_prompt_idp(self.master, idps['azure']['ipausername'])
        finally:
            self.cleanupidp('azure')

    @pytest.mark.skipif(
        idps['okta']['client_id'] is None,
        reason="Test requires environment variables idp_name, provider,"
               "client_id, user_id, base_url"
    )
    def test_kinit_prompt_okta(self):
        """
        Test case to check that for kinit prompt is
        given for authentication with okta idp without secret
        """
        try:
            add_idp(self.master,
                    idp_name=idps['okta']['idp_name'],
                    provider=idps['okta']['provider'],
                    client_id=os.environ['okta_client_id_no_secret'],
                    user_id=idps['okta']['user_id'],
                    ipausername=idps['okta']['ipausername'],
                    base_url=idps['okta']['base_url']
                    )
            kinit_prompt_idp(self.master, idps['okta']['ipausername'])
        finally:
            self.cleanupidp('okta')

    @pytest.mark.skipif(
        idps['okta']['client_id'] is None,
        reason="Test requires environment variables idp_name, provider,"
               "client_id, user_id, base_url, client_secret"
    )
    def test_kinit_prompt_okta_secret(self):
        """
        Test case to check that for kinit prompt is
        given for authentication with okta idp with secret
        """
        try:
            add_idp(self.master,
                    idp_name=idps['okta']['idp_name'],
                    provider=idps['okta']['provider'],
                    client_id=idps['okta']['client_id'],
                    user_id=idps['okta']['user_id'],
                    ipausername=idps['okta']['ipausername'],
                    base_url=idps['okta']['base_url'],
                    secret=idps['okta']['client_secret']
                    )
            kinit_prompt_idp(self.master, idps['okta']['ipausername'])
            self.master.run_command(["ipa", "idp-mod",
                                     idps[idp]['idp_name'],
                                     "--secret"],
                                    stdin_text='{0}\n{0}\n'.format(
                                        idps[idp]['client_secret'])
                                    )
            kinit_prompt_idp(self.master, idps['okta']['ipausername'])
        finally:
            self.cleanupidp('okta')
