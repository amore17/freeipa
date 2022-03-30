from __future__ import absolute_import

import os
import re
import time

import pytest
import textwrap
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
# from selenium import webdriver


# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL


def add_devicecode_script(host, device_url, device_code, login_url):
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
        driver.get(login_url)
        driver.get_screenshot_as_file("/var/log/httpd/device1.png")
        login_xpath = '//*[@id="landingSignInButton"]'
        login_report1 = driver.find_element_by_xpath(login_xpath)
        login_report1.click()
        driver.get_screenshot_as_file("/var/log/httpd/device2.png")
        driver.find_element_by_id("username").send_keys('testuser1')
        driver.get_screenshot_as_file("/var/log/httpd/device3.png")        
        driver.find_element_by_id("password").send_keys('Secret123')
        driver.get_screenshot_as_file("/var/log/httpd/device4.png")        
        sign_in_xpath = '//*[@id="kc-login"]'
        sign_report1 = driver.find_element_by_xpath(sign_in_xpath)
        sign_report1.click()
        driver.get_screenshot_as_file("/var/log/httpd/device5.png") 
        try:
            driver.get(device_url)
            driver.find_element_by_id('device-user-code').send_keys(device_code)           
            driver.get_screenshot_as_file("/var/log/httpd/device6.png")
            xpath = '//*[@id="kc-form-buttons"]/div/input'
            report1 = driver.find_element_by_xpath(xpath)
            report1.click()
            driver.get_screenshot_as_file("/var/log/httpd/device7.png")
        finally:
            driver.quit()        
    add_device(device_code='{0}', device_url='{1}', login_url='{2}')
    ''').format(device_code, device_url, login_url)

    host.put_file_contents("/tmp/add_login.py", contents, encoding='utf-8')
    host.run_command(["cat", "/tmp/add_login.py"])
    host.run_command(["python", "/tmp/add_login.py"])

def setup_set_auth(host):
    tasks.kinit_admin(host)
    host.run_command(["ipa", "config-mod", "--user-auth-type=idp",
                      "--user-auth-type=password"])


def add_idp(host, name, provider, client_id, org_id=None,
            scope=None, secret=None, extra_args=()):
    cmd = ["ipa", "idp-add", name, "--provider=" + provider,
           "--client-id=" + client_id]
    if provider == 'microsoft' and org_id:
        cmd.extend("--organization=" + org_id)
    if scope:
        cmd.extend(["--scope", scope])
    if secret:
        cmd.extend([])
    cmd.extend(extra_args)
    if secret:
        host.run_command(cmd, stdin_text="{0}\n{1}".format(secret, secret))
    else:
        host.run_command(cmd)


def get_keycloak_code(host, since):
    command = textwrap.dedent("""
    journalctl -u ipa-otpd\* --since="%s" | grep "user_code:" | awk '{ print substr($7,2,9) }'
    """ % since)
    device_code = host.run_command(command).stdout_text
    code = re.sub("[\W_]", "", str(device_code))
    return code


def kinit_idp(host, user, device_url, login_url):
    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    cmd = ["kinit", "-T", ARMOR, user]
    since = time.strftime('%Y-%m-%d %H:%M:%S')
    with host.spawn_expect(cmd) as e:
        e.expect('Authenticate with .+: ')
        devicecode = get_keycloak_code(host, since)
        if devicecode:
            add_devicecode_script(host, device_url, devicecode, login_url)
        e.sendline('\n')
    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


def setup_keycloakserver(host):
    host.run_command(["setenforce", "0"])
    tasks.install_packages(host, ["unzip", "java-11-openjdk-headless",
                                  "openssl", "maven", "wget"])
    keycloak_path = "/opt/keycloak"
    kcreg = "/opt/keycloak/bin/kcreg.sh"
    kcadmin_path = "/opt/keycloak/bin/kcadm.sh"
    kcsh_path = "/opt/keycloak/bin/kc.sh"

    # add keycloak system user/group directory
    keycloak_url = "https://github.com/keycloak/keycloak/releases/download/18.0.0/keycloak-18.0.0.zip"
    justin_plugin = "https://github.com/justin-stephenson/scim-keycloak-user-storage-spi/archive/main.zip"

    host.run_command(["wget", keycloak_url, "-O", keycloak_path + "-18.0.0.zip"])
    host.run_command(["unzip", keycloak_path + "-18.0.0.zip", "-d", "/opt/"])
    host.run_command(["mv", keycloak_path + "-18.0.0", keycloak_path])
    host.run_command(["groupadd", "keycloak"])
    host.run_command(["useradd", "-r", "-g", "keycloak", "-d", keycloak_path, "keycloak"])
    host.run_command(["chown", "-R", "keycloak:", keycloak_path])
    host.run_command(["chmod", "o+x", keycloak_path + "/bin/"])

    # deploy Justin's plugin
    deploy_plugin = textwrap.dedent("""
    wget {0} -O /opt/main.zip
    unzip /opt/main.zip -d /opt
    cd /opt/scim-keycloak-user-storage-spi-main
    KEYCLOAK_PATH={1} ./redeploy-plugin.sh
    """).format(justin_plugin, keycloak_path)
    host.put_file_contents("/tmp/deploy.sh", deploy_plugin)
    # host.run_command(["sh", "/tmp/deploy.sh"])
    host.run_command(["restorecon", "-R", keycloak_path])
    host.run_command(["kinit", "-k"])
    host.run_command(["ipa", "service-add", "HTTP/{0}".format(host.hostname)])
    host.run_command(["ipa-getcert", "request", "-K", "HTTP/{0}".format(host.hostname),
                      "-D", host.hostname, "-o", "keycloak", "-O", "keycloak",
                      "-m", "0600", "-M", "0644",
                      "-k", "/etc/pki/tls/private/keycloak.key",
                      "-f", "/etc/pki/tls/certs/keycloak.crt", "-w"]
                     )
    host.run_command(["keytool", "-import", "-keystore", "/etc/pki/tls/private/keycloak.store",
                      "-file", "/etc/ipa/ca.crt", "-alias", "ipa_ca",
                      "-trustcacerts", "-storepass", "Secret123", "-noprompt"
                      ])
    host.run_command(["chown", "keycloak:keycloak", "/etc/pki/tls/private/keycloak.store"])

    contents = textwrap.dedent("""
    KEYCLOAK_ADMIN=admin
    KEYCLOAK_ADMIN_PASSWORD=Secret123
    #KC_LOG_LEVEL=debug
    KC_HOSTNAME=$(hostname):8443
    KC_HTTPS_CERTIFICATE_FILE=/etc/pki/tls/certs/keycloak.crt
    KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/pki/tls/private/keycloak.key
    KC_HTTPS_TRUST_STORE_FILE=/etc/pki/tls/private/keycloak.store
    KC_HTTPS_TRUST_STORE_PASSWORD=Secret123
    KC_HTTP_RELATIVE_PATH=/auth
    """)
    host.put_file_contents("/etc/sysconfig/keycloak", contents)

    # configure keycloak service
    conf_service = textwrap.dedent("""
    [Unit]
    Description=Keycloak Server
    After=network.target
    [Service]
    Type=idle
    EnvironmentFile=/etc/sysconfig/keycloak
    User=keycloak
    Group=keycloak
    ExecStart={0} start
    TimeoutStartSec=600
    TimeoutStopSec=600
    [Install]
    WantedBy=multi-user.target
    """).format(kcsh_path)
    host.put_file_contents("/etc/systemd/system/keycloak.service", conf_service)
    host.run_command(["systemctl", "daemon-reload"])

    build = textwrap.dedent("""
    su - keycloak -c '''
    export KEYCLOAK_ADMIN=admin
    export KEYCLOAK_ADMIN_PASSWORD=Secret123
    export KC_HOSTNAME={0}:8443
    export KC_HTTPS_CERTIFICATE_FILE=/etc/pki/tls/certs/keycloak.crt
    export KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/pki/tls/private/keycloak.key
    export KC_HTTPS_TRUST_STORE_FILE=/etc/pki/tls/private/keycloak.store
    export KC_HTTPS_TRUST_STORE_PASSWORD=Secret123
    export KC_HTTP_RELATIVE_PATH=/auth
    {1} build   
    '''
    """).format(host.hostname, kcsh_path)

    host.put_file_contents("/tmp/build.sh", build)
    host.run_command(["sh", "/tmp/build.sh"])

    host.run_command(["systemctl", "start", "keycloak"])

    status = host.run_command(["systemctl", "status", "keycloak"])
    assert "running" in status.stdout_text

    host.run_command([kcadmin_path, "config", "truststore", "--trustpass",
                      "Secret123", "/etc/pki/tls/private/keycloak.store"])

    kcadmin = [kcadmin_path, "config", "credentials", "--server",
               "https://{0}:8443/auth/".format(host.hostname),
               "--realm", "master", "--user", "admin",
               "--password", "Secret123"
               ]
    tasks.run_repeatedly(
        host, kcadmin, timeout=60)
    host.run_command([kcadmin_path, "create", "users",
                      "-r", "master", "-s", "username=testuser1",
                      "-s", "enabled=true", "-s",
                      "email=testuser1@{0}".format(host.domain.name)]
                     )
    host.run_command([kcadmin_path, "set-password", "-r",
                      "master", "--username",
                      "testuser1", "--new-password",
                      "Secret123"]
                     )

    # Setup OIDC client for IPA tests
    host.run_command([kcreg, "config", "credentials", "--server",
                      "https://{0}:8443/auth/".format(host.hostname),
                      "--realm", "master", "--user", "admin",
                      "--password", "Secret123"]
                     )
    client_json = textwrap.dedent("""
    {{
      "enabled" : true,
      "clientAuthenticatorType" : "client-secret",
      "redirectUris" : [ "https://ipa-ca.{redirect}/ipa/idp/*" ],
      "webOrigins" : [ "https://ipa-ca.{web}" ],
      "protocol" : "openid-connect",
      "attributes" : {{
      "oauth2.device.authorization.grant.enabled" : "true"
      }}
    }}
    """).format(redirect=host.domain.name, web=host.domain.name)
    host.put_file_contents("/tmp/ipa_client.json", client_json)
    host.run_command([kcreg, "create", "-f", "/tmp/ipa_client.json",
                      "-s", "clientId=ipa_oidc_client",
                      "-s", "secret=Secret123"]
                     )


class TestIDPKeycloak(IntegrationTest):

    num_replicas = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        # for pkg in ('firefox', 'xorg-x11-server-Xvfb'):
        #    tasks.install_packages(cls.master, pkg)

        cls.master.run_command(["dnf", "copr", "enable", "-y", "abbra/oauth2-support"])
        cls.master.run_command(["dnf", "update", "-y", "--nogpgcheck",
                                "freeipa-server*", "sssd-idp"])
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.replicas[0])
        content = cls.master.get_file_contents(paths.IPA_DEFAULT_CONF,
                                         encoding='utf-8')
        new_content = content + "\noidc_child_debug_level = 10"
        cls.master.put_file_contents(paths.IPA_DEFAULT_CONF, new_content)
        tasks.FileBackup(cls.master, paths.SSSD_CONF)
        with tasks.remote_sssd_config(cls.master) as sssd_config:
            sssd_config.edit_domain(
                cls.master.domain, 'krb5_auth_timeout', 190)
        setup_set_auth(cls.master)

    @classmethod
    def uninstall(cls, mh):
        # Uninstall method is empty for debugging
        pass

    def test_setup_keycloak(self):
        keycloak_srv = self.replicas[0]
        tasks.kinit_admin(keycloak_srv)
        setup_keycloakserver(keycloak_srv)
        add_idp(self.master, name='keycloak',
                provider='keycloak', client_id='ipa_oidc_client',
                secret='Secret123',
                extra_args=["--org=master",
                            "--base-url={0}:8443/auth".format(keycloak_srv.hostname)
                            ])
        tasks.user_add(self.master, 'keycloakuser',
                       extra_args=["--user-auth-type=idp",
                                   "--idp-user-id=testuser1@{0}".format(keycloak_srv.domain.name),
                                   "--idp=keycloak"]
                       )
        tasks.clear_sssd_cache(self.master)
        device_url = "https://{0}:8443/auth/realms/master/device".format(keycloak_srv.hostname)
        login_url = "https://{0}:8443/auth/realms/master/account/#/".format(keycloak_srv.hostname)
        kinit_idp(self.master, 'keycloakuser', device_url, login_url)