from __future__ import absolute_import

import os
import re
import time

import pytest
import textwrap
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
from ipatests.pytest_ipa.integration import tasks
from selenium import webdriver


# give some time for units to stabilize
# otherwise we get transient errors
WAIT_AFTER_INSTALL = 5
WAIT_AFTER_UNINSTALL = WAIT_AFTER_INSTALL


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
            dev_code = code
            # add code in web idp
        e.sendline('\n')
    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


def setup_keycloakserver(host, cert_path, key_path):
    """
    :param host:
    :return:
    """
    tasks.install_packages(host, ["unzip", "java-11-openjdk-headless",
                                  "openssl", "maven"])
    keycloak_path = "/opt/keycloak"

    # add keycloak system user/group directory
    keycloak_url = "https://github.com/keycloak/keycloak/releases/download/17.0.0/keycloak-17.0.0.zip"
    justin_plugin = "https://github.com/justin-stephenson/scim-keycloak-user-storage-spi/archive/main.zip"

    host.run_command(["wget", keycloak_url, "-O", keycloak_path + "-17.0.0.zip"])
    host.run_command(["unzip", keycloak_path + "-17.0.0.zip", "-d", "/opt/"])
    host.run_command(["mv", keycloak_path + "-17.0.0", keycloak_path])
    host.run_command(["groupadd", "keycloak"])
    host.run_command(["useradd", "-r", "-g", "keycloak", "-d", keycloak_path, "keycloak"])
    host.run_command(["chown", "-R", "keycloak:", keycloak_path])
    host.run_command(["chmod", "o+x", keycloak_path + "/bin/"])
    host.run_command(["chown", "keycloak:keycloak", cert_path, key_path])

    # deploy Justin's plugin
    host.run_command(["wget", justin_plugin, "-O", "/opt/main.zip"])
    host.run_command(["unzip", "/opt/main.zip"])
    host.run_command(["cd", "/opt/scim-keycloak-user-storage-spi-main"])
    host.run_command(["KEYCLOAK_PATH=" + keycloak_path, "./redeploy-plugin.sh"])

    contents = textwrap.dedent("""
    KEYCLOAK_ADMIN=admin
    KEYCLOAK_ADMIN_PASSWORD=Secret123
    KC_HOSTNAME={0}:8443
    KC_HTTPS_CERTIFICATE_FILE={0}
    KC_HTTPS_CERTIFICATE_KEY_FILE={1}
    KC_HTTP_RELATIVE_PATH=/auth
    """).format(host.hostname, cert_path, key_path)
    host.put_file_conents(contents, "/etc/sysconfig/keycloak")

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
    ExecStart={0}/bin/kc.sh start
    TimeoutStartSec=600
    TimeoutStopSec=600
    [Install]
    WantedBy=multi-user.target
    """).format(keycloak_path)
    host.put_file_conents(conf_service, "/etc/systemd/system/keycloak.service")
    host.run_command(["systemctl", "daemon-reload"])

    build = textwrap.dedent("""
    su - keycloak -c '''
    export KEYCLOAK_ADMIN=admin
    export KEYCLOAK_ADMIN_PASSWORD=Secret123
    export KC_HOSTNAME=$(hostname):8443
    export KC_HTTPS_CERTIFICATE_FILE={0}
    export KC_HTTPS_CERTIFICATE_KEY_FILE={1}
    export KC_HTTPS_TRUST_STORE_FILE=/etc/x509/https/truststore.keystore
    export KC_HTTPS_TRUST_STORE_PASSWORD=Secret123
    export KC_HTTP_RELATIVE_PATH=/auth
    {2}/bin/kc.sh build
    '''
    """).format(cert_path, key_path, keycloak_path)
    host.put_file_conents(build, "/tmp/build.sh")
    host.run_command("sh", "/tmp/build.sh")

    status = host.run_command(["systemctl", "status", "keycloak"])
    assert "running" in status.stdout_text
    kcadmin_path = "{0}/bin/kcadm.sh".format(keycloak_path)
    kcadmin = [kcadmin_path,
               "config", "credentials", "--server", "https://{0}:8443/auth/".format(host.hostname),
               "--realm", "master" "--user", "admin", "--password", "Secret123"]
    tasks.run_repeatedly(
        host, kcadmin)
    host.run_command([kcadmin_path, "create", "users", "-r", "master", "-s", "username=testuser1",
                      "-s", "enabled=true", "-s", "email=testuser1@ipa.test"])
    host.run_command([kcadmin_path, "set-password", "-r", "master", "--username",
                      "testuser1", "--new-password", "Secret123"])
    status = host.run_command(["systemctl", "status", "keycloak"])
    assert "running" in status.stdout_text


class TestIDPKeycloak(IntegrationTest):

    num_replicas = 1
    topology = 'line'

    @classmethod
    def install(cls, mh):
        for pkg in ('firefox', 'xorg-x11-server-Xvfb'):
            assert tasks.is_package_installed(cls.master, pkg)
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

    @classmethod
    def uninstall(cls, mh):
        # Uninstall method is empty for debugging
        pass

    def test_setup_keycloak(self):
        keycloak_srv = self.replicas[0]
        tasks.kinit_admin(keycloak_srv)
        csr_file = 'tls.csr'
        cert_path = "/etc/x509/https/tls.crt"
        key_path = "/etc/x509/https/tls.key"
        keycloak_srv.run_command(["mkdir", "-p", "/etc/x509/https"])

        #  Create CSR
        openssl_cmd = [
            'openssl', 'req', '-newkey', 'rsa:2048', '-keyout', key_path,
            '-nodes', '-out', csr_file, '-subj', '/CN=' + keycloak_srv.hostname]
        keycloak_srv.run_command(openssl_cmd)

        #  Request cert from IPA
        cmd_args = ['ipa', 'cert-request', '--principal', 'HTTP/' + keycloak_srv.hostname,
                    '--certificate-out', cert_path, csr_file]
        keycloak_srv.run_command(cmd_args)

        keycloak_srv.run_command(["cp", key_path, cert_path, "/etc/x509/https/"])
        setup_keycloakserver(keycloak_srv, cert_path, key_path)
