# Copyright (C) 2025 FreeIPA Contributors see COPYING for license

"""
Integration tests for Azure (Microsoft) Identity Provider.

Adds an Azure IDP with Microsoft provider and associates users with mail id.
Configuration via environment: AZURE_ORGANIZATION, AZURE_CLIENT_ID,
AZURE_CLIENT_SECRET.
"""

from __future__ import absolute_import

import os
import re
import time
import textwrap

import pytest

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

# Azure IDP configuration - from environment
# organization is the Azure AD tenant ID
AZURE_IDP_NAME = "my-azure-idp"
AZURE_ORGANIZATION = os.environ.get(
    "AZURE_ORGANIZATION", "xxxxxxxx"
)
AZURE_CLIENT_ID = os.environ.get(
    "AZURE_CLIENT_ID", "xxxxxxxx"
)
AZURE_CLIENT_SECRET = os.environ.get(
    "AZURE_CLIENT_SECRET", "xxxxxxxx"
)
AZURE_IDP_USER_EMAIL = os.environ.get("AZURE_IDP_USER_EMAIL", "testingamore@ipaqe1.onmicrosoft.com")
AZURE_USER_PASSWORD = os.environ.get("AZURE_USER_PASSWORD", "Wodo4504165")
AZURE_IPA_USERNAME = "amore"

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
    driver.get_screenshot_as_file("/var/log/httpd/screenshot-azure-%s.png" % now)
    driver.quit()
""")


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


class TestIDPAzure(IntegrationTest):
    """
    Test Azure (Microsoft) Identity Provider configuration.

    Adds an Azure IDP with Microsoft provider template and verifies
    that users can be associated with the IdP using email as idp-user-id.
    """

    topology = "line"

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, extra_args=["--no-dnssec-validation"])
        content = cls.master.get_file_contents(
            paths.IPA_DEFAULT_CONF, encoding='utf-8')
        new_content = content + "\noidc_child_debug_level = 10"
        cls.master.put_file_contents(paths.IPA_DEFAULT_CONF, new_content)
        with tasks.remote_sssd_config(cls.master) as sssd_config:
            sssd_config.edit_domain(
                cls.master.domain, 'krb5_auth_timeout', 1100)
        tasks.clear_sssd_cache(cls.master)
        tasks.kinit_admin(cls.master)
        cls.master.run_command(
            ["ipa", "config-mod", "--user-auth-type=idp", "--user-auth-type=password"]
        )

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_azure_idp_add_and_user(self):
        """
        Add Azure IDP with Microsoft provider and associate user with mail id.

        Uses ipa idp-add with --provider microsoft, --organization (tenant ID),
        --client-id, and --secret from stdin. Then adds IPA user linked to
        the IdP with idp-user-id set to the user's email.
        """
        # Add Azure IDP - secret from stdin (echo or stdin_text)
        idp_add_cmd = [
            "ipa", "idp-add", AZURE_IDP_NAME,
            "--provider", "microsoft",
            "--organization", AZURE_ORGANIZATION,
            "--client-id", AZURE_CLIENT_ID,
            "--secret",
        ]
        self.master.run_command(
            idp_add_cmd,
            stdin_text=AZURE_CLIENT_SECRET + "\n"
        )

        # Verify IDP was created
        result = self.master.run_command(["ipa", "idp-show", AZURE_IDP_NAME])
        assert AZURE_IDP_NAME in result.stdout_text
        assert "login.microsoftonline.com" in result.stdout_text

        # Add user with idp-user-id as email (mail id)
        tasks.user_add(
            self.master,
            AZURE_IPA_USERNAME,
            first="Amore",
            last="User",
            extra_args=[
                "--user-auth-type=idp",
                "--idp-user-id=" + AZURE_IDP_USER_EMAIL,
                "--idp=" + AZURE_IDP_NAME,
            ],
        )

        # Verify user can be found by idp-user-id
        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=" + AZURE_IDP_USER_EMAIL]
        )
        assert AZURE_IPA_USERNAME in list_user.stdout_text

        # Verify user can be found by idp name
        list_by_idp = self.master.run_command(
            ["ipa", "user-find", "--idp=" + AZURE_IDP_NAME]
        )
        assert AZURE_IPA_USERNAME in list_by_idp.stdout_text

        # Verify full user show includes IdP configuration
        user_show = self.master.run_command(
            ["ipa", "user-show", AZURE_IPA_USERNAME, "--all"]
        )
        assert AZURE_IDP_NAME in user_show.stdout_text
        assert AZURE_IDP_USER_EMAIL in user_show.stdout_text

    def test_azure_idp_kinit_prompt(self):
        """
        Verify kinit with IdP user triggers OAuth 2.0 Device Authorization flow.

        Per the external IdP design (OAuth 2.0 Device Authorization Grant over
        Kerberos FAST channel), kinit for an IdP-configured user should display
        the "Authenticate at <verification_uri> and press ENTER" prompt with
        the Azure verification URL. Full authentication cannot be automated
        against Microsoft's cloud, so we verify the prompt appears and
        terminate. See: https://freeipa.readthedocs.io/en/latest/designs/
        external-idp/external-idp.html
        """
        # Setup: add Azure IDP and user (same as test_azure_idp_add_and_user)
        idp_add_cmd = [
            "ipa", "idp-add", AZURE_IDP_NAME,
            "--provider", "microsoft",
            "--organization", AZURE_ORGANIZATION,
            "--client-id", AZURE_CLIENT_ID,
            "--secret",
        ]
        self.master.run_command(
            idp_add_cmd,
            stdin_text=AZURE_CLIENT_SECRET + "\n"
        )
        tasks.user_add(
            self.master,
            AZURE_IPA_USERNAME,
            first="Amore",
            last="User",
            extra_args=[
                "--user-auth-type=idp",
                "--idp-user-id=" + AZURE_IDP_USER_EMAIL,
                "--idp=" + AZURE_IDP_NAME,
            ],
        )

        # kinit with IdP user: create FAST armor, then kinit via IdP pre-auth
        # Per design: kinit -n -c ARMOR; kinit -T ARMOR idpuser
        tasks.kdestroy_all(self.master)
        armor = "/tmp/armor_azure_idp"
        self.master.run_command(["kinit", "-n", "-c", armor])

        cmd = ["kinit", "-T", armor, AZURE_IPA_USERNAME]
        with self.master.spawn_expect(cmd, default_timeout=30) as e:
            # Expect OAuth 2.0 Device Authorization prompt
            # Format: "Authenticate at <uri> and press ENTER." or "ENTER.:"
            e.expect(r'Authenticate at (.+) and press ENTER[.:]?', timeout=15)
            prompt = e.get_last_output()
            # Verify Azure verification URL is shown
            match = re.search(
                r'Authenticate at (.*?) and press ENTER[.:]?', prompt
            )
            assert match, "Expected device auth prompt"
            uri = match.group(1)
            assert "login.microsoftonline.com" in uri, (
                f"Expected Azure URL in prompt, got: {uri}"
            )
            # Cannot complete Azure auth without manual browser login;
            # terminate to end the test
            e.sendcontrol('c')
            e.expect_exit(ignore_remaining_output=True, raiseonerr=False)

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
            AZURE_IPA_USERNAME,
            AZURE_IDP_USER_EMAIL,
            AZURE_USER_PASSWORD,
        )
