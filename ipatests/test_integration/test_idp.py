from __future__ import absolute_import

import re

import pytest
import subprocess
import textwrap
import time
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

from ipatests.test_webui.ui_driver import screenshot


# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL
AMOREIDP_CODES = ["7c06c-f946c", "78956-1369b", "8b41f-61913", "2742f-73930",
                  "f3cd7-fe08d", "ac3fb-c4012", "7b792-37522", "9deb6-1691d",
                  "6702d-5193f", "b7b20-88909", "50935-72920", "49334-f6b51",
                  "71eb8-f92af", "18d4a-7bccb", "1c1fc-e0e50", "4a9a5-e78c6"]
AMOREIDP_PASSWD = "vivA8v8Lz45Nx5J"


def add_devicecode_script(host, device_code, github_account, github_passwd):
    host.run_command("export DISPLAY=:99")
    host.run_command("nohup /usr/bin/Xvfb $DISPLAY -ac -noreset -screen 0 1400x1200x8 </dev/null &>/dev/null &")
    if host.transport.file_exists("/opt/selenium.jar"):
        host.run_command("nohup java -jar /opt/selenium.jar </dev/null &>/dev/null &")

    contents = textwrap.dedent('''
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    def add_device(device_code, github_account, github_passwd):
        options = Options()
        options.headless = True
        driver = webdriver.Firefox(executable_path="/opt/geckodriver", options=options)
        driver.get("https://github.com/login/device")
        driver.find_element_by_id("login_field").send_keys(github_account)
        driver.find_element_by_id("password").send_keys(github_passwd)
        driver.find_element_by_name("commit").click()
        driver.get_screenshot_as_file("/var/log/httpd/device1.png")
        driver.find_element_by_link_text("Use a recovery code or request a reset").click()
        driver.get_screenshot_as_file("/var/log/httpd/device2.png") 
        try:
            driver.find_element_by_id('recovery_code').send_keys('50935-72920')           
            driver.get_screenshot_as_file("/var/log/httpd/device3.png")
            xpath = '//*[@id="login"]/form/div[3]/div[2]/button'
            full_xpath = '/html/body/div[3]/main/div/div/form/div[3]/div[2]/button'
            report1 = driver.find_element_by_xpath(xpath)
            report1.click()
            driver.get_screenshot_as_file("/var/log/httpd/device3_1.png")
            driver.get("https://github.com/login/device")
            driver.get_screenshot_as_file("/var/log/httpd/device3_2.png")  
            driver.find_element_by_name('user-code-0').send_keys(device_code[0])
            driver.get_screenshot_as_file("/var/log/httpd/device4.png")
            driver.find_element_by_name('user-code-1').send_keys(device_code[1])
            driver.find_element_by_name('user-code-2').send_keys(device_code[2])
            driver.find_element_by_name('user-code-3').send_keys(device_code[3])
            driver.find_element_by_name('user-code-5').send_keys(device_code[4])
            driver.find_element_by_name('user-code-6').send_keys(device_code[5])
            driver.find_element_by_name('user-code-7').send_keys(device_code[6])
            driver.find_element_by_name('user-code-8').send_keys(device_code[7])
            driver.get_screenshot_as_file("/var/log/httpd/device5.png")
            driver.find_element_by_name("commit").click()
            driver.get_screenshot_as_file("/var/log/httpd/device6.png")
            driver.get_screenshot_as_file("/var/log/httpd/device7.png")                              
            driver.find_element_by_name("authorize").click()
            driver.get_screenshot_as_file("/var/log/httpd/device8.png")                
        finally:
            driver.quit()        
    add_device(device_code='{0}', github_account='{1}', github_passwd='{2}')
    ''').format(device_code, github_account, github_passwd)

    host.put_file_contents("/tmp/add_login.py", contents, encoding='utf-8')
    host.run_command(["cat", "/tmp/add_login.py"])
    host.run_command(["python", "/tmp/add_login.py"])


def setup_set_auth(host):

    tasks.kinit_admin(host)
    host.run_command(["ipa", "config-mod", "--user-auth-type=idp",
                      "--user-auth-type=password"])


def add_idp(host, name, provider, client_id, org_id=None,
            scope=None):
    cmd = ["ipa", "idp-add", name, "--provider=" + provider,
           "--client-id=" + client_id]
    if provider == 'microsoft' and org_id:
        cmd.extend("--organization=" + org_id)
    if scope:
        cmd.extend("--scope" + scope)
    host.run_command(cmd)


def get_github_code(host, since):
    command = textwrap.dedent("""
    journalctl -u ipa-otpd\* --since="%s" | grep "user_code:" | awk '{ print substr($7,2,9) }'
    """ % since)
    device_code = host.run_command(command).stdout_text
    code = re.sub("[\W_]", "", str(device_code))
    return code


def kinit_idp(host, user):
    #gh_user = host.config.github_user_name
    #gh_password = host.config.github_user_password
    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    cmd = ["kinit", "-T", ARMOR, user]
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    with host.spawn_expect(cmd) as e:
        e.expect('Authenticate with .+: ')
        code = get_github_code(host, since)
        if code:
            add_devicecode_script(host,
                                  device_code=code,
                                  github_account='amoreidp',
                                  github_passwd='vivA8v8Lz45Nx5J'
                                  )
        e.sendline('\n')
    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


class TestIDP(IntegrationTest):
    topology = 'line'

    @classmethod
    def install(cls, mh):
        for pkg in ('firefox', 'xorg-x11-server-Xvfb'):
            assert tasks.is_package_installed(cls.master, pkg)
        cls.master.run_command(["dnf", "copr", "enable", "-y", "abbra/oauth2-support"])
        cls.master.run_command(["dnf", "update", "-y", "--nogpgcheck",
                                "freeipa-server*", "sssd-idp"])
        tasks.install_master(cls.master)
        content = cls.master.get_file_contents(paths.IPA_DEFAULT_CONF,
                                         encoding='utf-8')
        new_content = content + "\noidc_child_debug_level = 10"
        cls.master.put_file_contents(paths.IPA_DEFAULT_CONF, new_content)
        sssd_conf_backup = tasks.FileBackup(cls.master, paths.SSSD_CONF)
        with tasks.remote_sssd_config(cls.master) as sssd_config:
            sssd_config.edit_domain(
                cls.master.domain, 'krb5_auth_timeout', 190)

    @classmethod
    def uninstall(cls, mh):
        pass

    def test_github_kinit(self):
        setup_set_auth(self.master)
        add_idp(self.master, name='amoreidp',
                provider='github',
                client_id="cf8153b8695db63a4965",
                scope='user'
                )
        tasks.user_add(self.master, login='amoreidp',
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user=amoreidp",
                                   "--idp=amoreidp"]
                       )
        tasks.clear_sssd_cache(self.master)
        kinit_idp(self.master, user='amoreidp')

