"""Keycloak setup and IdP integration test helpers."""

from __future__ import absolute_import

import base64
import json
import os
import re
import textwrap
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks


def selenium_remote_finally(shot_path):
    """Return try/finally tail for remote Selenium scripts."""
    return textwrap.dedent(
        """
        finally:
            now = datetime.now().strftime("%M-%S")
            driver.get_screenshot_as_file({path} % now)
            driver.quit()
        """
    ).strip().format(path=repr(shot_path))


SELENIUM_REMOTE_HEAD = textwrap.dedent(
    """
    import os
    from selenium import webdriver
    from datetime import datetime
    from packaging.version import parse as parse_version
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    import time

    os.environ.setdefault("DISPLAY", ":99")
    options = Options()
    if parse_version(webdriver.__version__) < parse_version('4.10.0'):
        options.headless = True
        driver = webdriver.Firefox(
            executable_path="/opt/geckodriver", options=options)
    else:
        options.add_argument('-headless')
        service = webdriver.FirefoxService(
            executable_path="/opt/geckodriver")
        driver = webdriver.Firefox(options=options, service=service)
    driver.set_page_load_timeout(90)

    """
).strip() + "\n\n"


KEYCLOAK_USER_CODE_BODY = textwrap.dedent(
    """
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
    """
).strip()

keycloak_user_code_script = (
    SELENIUM_REMOTE_HEAD
    + KEYCLOAK_USER_CODE_BODY
    + "\n"
    + selenium_remote_finally("/var/log/httpd/screenshot-keycloak-%s.png")
)


def keycloak_truststore_path():
    return os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.jks")


def keycloak_ensure_kcadm_credentials(keycloak_host):
    """Configure ``kcadm.sh`` admin session on the Keycloak host."""
    password = keycloak_host.config.admin_password
    kcadmin_sh = "/opt/keycloak/bin/kcadm.sh"
    keystore = keycloak_truststore_path()
    keycloak_host.run_command(
        [kcadmin_sh, "config", "truststore",
         "--trustpass", password, keystore])
    kcadmin = [
        kcadmin_sh, "config", "credentials", "--server",
        "https://%s:8443/" % keycloak_host.hostname,
        "--realm", "master", "--user", "admin",
        "--password", password,
    ]
    tasks.run_repeatedly(keycloak_host, kcadmin, timeout=60)


def keycloak_client_internal_id(keycloak_host, client_id, realm="master"):
    """Return Keycloak internal client UUID for *client_id*, or ``None``."""
    kcadmin_sh = "/opt/keycloak/bin/kcadm.sh"
    out = keycloak_host.run_command(
        [kcadmin_sh, "get", "clients", "-r", realm,
         "-q", "clientId=%s" % client_id, "--fields", "id"],
        raiseonerr=False,
    )
    if out.returncode != 0:
        return None
    clients = json.loads(out.stdout_text or "[]")
    if not clients:
        return None
    return clients[0]["id"]


def keycloak_delete_client(keycloak_host, client_id, realm="master"):
    """Delete an OAuth client by its ``clientId`` (no-op if missing)."""
    internal_id = keycloak_client_internal_id(
        keycloak_host, client_id, realm=realm)
    if internal_id is None:
        return
    kcadmin_sh = "/opt/keycloak/bin/kcadm.sh"
    keycloak_host.run_command(
        [kcadmin_sh, "delete", "clients/%s" % internal_id, "-r", realm],
        raiseonerr=False,
    )


def keycloak_pem_cert_der_b64(pem_certificate_bytes):
    """Base64-encoded DER of a PEM certificate (Keycloak JWT credential)."""
    if isinstance(pem_certificate_bytes, str):
        pem_certificate_bytes = pem_certificate_bytes.encode("ascii")
    cert = x509.load_pem_x509_certificate(pem_certificate_bytes)
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


def keycloak_pem_cert_subject_dn(pem_certificate_bytes):
    """RFC4514 subject DN for Keycloak ``x509.subjectdn`` matching."""
    if isinstance(pem_certificate_bytes, str):
        pem_certificate_bytes = pem_certificate_bytes.encode("ascii")
    cert = x509.load_pem_x509_certificate(pem_certificate_bytes)
    return cert.subject.rfc4514_string()


def keycloak_openssl_cert_subject_dn(host, crt_path):
    """Subject DN from ``openssl x509 -subject`` (Keycloak format)."""
    out = host.run_command(
        ["openssl", "x509", "-in", crt_path, "-noout", "-subject"])
    subject = out.stdout_text.strip()
    if subject.lower().startswith("subject="):
        subject = subject.split("=", 1)[1].strip()
    return subject


def keycloak_oidc_client_json(
        domain_name, client_id, *, auth_method, extra_attrs,
):
    """Build Keycloak OIDC client JSON for device authorization grant."""
    attrs = {
        "oauth2.device.authorization.grant.enabled": "true",
        "oauth2.device.polling.interval": "5",
    }
    attrs.update(extra_attrs)
    if auth_method == "private_key_jwt":
        authenticator = "client-jwt"
    elif auth_method == "tls_client_auth":
        authenticator = "client-x509"
    else:
        raise ValueError("unsupported auth_method: %s" % auth_method)
    return {
        "enabled": True,
        "clientId": client_id,
        "protocol": "openid-connect",
        "clientAuthenticatorType": authenticator,
        "redirectUris": ["https://ipa-ca.%s/ipa/idp/*" % domain_name],
        "webOrigins": ["https://ipa-ca.%s" % domain_name],
        "attributes": attrs,
    }


def keycloak_create_cert_oidc_client(
    keycloak_host,
    domain_name,
    client_id,
    *,
    auth_method,
    extra_attrs,
    realm="master",
):
    """
    Create a confidential Keycloak client for JWT or mTLS client auth.

    Follows the setup used in SSSD ``test_oidc_child`` (PR #8708).
    """
    client_def = keycloak_oidc_client_json(
        domain_name, client_id,
        auth_method=auth_method, extra_attrs=extra_attrs)
    json_path = "/tmp/%s_client.json" % client_id
    keycloak_host.put_file_contents(json_path, json.dumps(client_def))
    kcadmin_sh = "/opt/keycloak/bin/kcadm.sh"
    keycloak_host.run_command(
        [kcadmin_sh, "create", "clients", "-r", realm, "-f", json_path],
    )


def keycloak_truststore_import_cert(keycloak_host, crt_path, alias):
    """Import a client certificate into Keycloak's HTTPS truststore."""
    password = keycloak_host.config.admin_password
    keystore = keycloak_truststore_path()
    keycloak_host.run_command([
        "keytool", "-storepass", password,
        "-keystore", keystore, "-noprompt",
        "-importcert", "-file", crt_path, "-alias", alias,
    ])


def keycloak_truststore_delete_cert(keycloak_host, alias):
    """Remove *alias* from Keycloak's HTTPS truststore (no-op if missing)."""
    password = keycloak_host.config.admin_password
    keystore = keycloak_truststore_path()
    keycloak_host.run_command([
        "keytool", "-storepass", password,
        "-keystore", keystore, "-delete", "-alias", alias, "-noprompt",
    ], raiseonerr=False)


def keycloak_set_https_client_auth(keycloak_host, mode):
    """
    Set ``KC_HTTPS_CLIENT_AUTH`` and restart Keycloak.

    Use ``none`` for secret-based IdP tests (browser device flow without
    mTLS).  Use ``request`` for RFC 8705 ``tls_client_auth`` tests so
    Keycloak accepts the client certificate at the token endpoint.
    """
    if mode not in ("none", "request", "required"):
        raise ValueError("unsupported KC_HTTPS_CLIENT_AUTH: %s" % mode)
    sysconfig_path = "/etc/sysconfig/keycloak"
    content = keycloak_host.get_file_contents(
        sysconfig_path, encoding="utf-8")
    lines = []
    found = False
    for line in content.splitlines():
        if line.startswith("KC_HTTPS_CLIENT_AUTH="):
            lines.append("KC_HTTPS_CLIENT_AUTH=%s" % mode)
            found = True
        else:
            lines.append(line)
    if not found:
        lines.append("KC_HTTPS_CLIENT_AUTH=%s" % mode)
    keycloak_host.put_file_contents(sysconfig_path, "\n".join(lines) + "\n")

    bashrc_path = "/etc/bashrc"
    bashrc = keycloak_host.get_file_contents(bashrc_path, encoding="utf-8")
    new_bashrc = re.sub(
        r"^export KC_HTTPS_CLIENT_AUTH=.*$",
        "export KC_HTTPS_CLIENT_AUTH=%s" % mode,
        bashrc,
        flags=re.MULTILINE,
    )
    if new_bashrc != bashrc:
        keycloak_host.put_file_contents(bashrc_path, new_bashrc)

    keycloak_host.run_command(["systemctl", "restart", "keycloak"])
    tasks.run_repeatedly(
        keycloak_host,
        ["systemctl", "is-active", "keycloak"],
        timeout=120,
    )
    keycloak_host.run_command([
        "bash", "-c",
        "unset KC_HTTPS_CLIENT_AUTH; set -a; . %s; set +a; "
        "/opt/keycloak/bin/kc.sh show-config" % sysconfig_path,
    ])


def setup_keycloakserver(host, version='26.4.4'):
    dir = "/opt/keycloak"
    password = host.config.admin_password
    packages = ["unzip", "java-25-openjdk-headless", "openssl", "maven", "wget"]
    # For RHEL 10 we don't install firefox as it is not shipped any more
    # as a rpm. The infra handles the installation from a zip file
    if not (tasks.get_platform(host) == "rhel"
       and tasks.get_platform_version(host)[0] == 10):
        packages.extend(["firefox", "xorg-x11-server-Xvfb"])
    tasks.install_packages(host, packages)
    #  add keycloak system user/group and folder
    url = "https://github.com/keycloak/keycloak/releases/download/{0}/keycloak-{0}.zip".format(version)  # noqa: E501
    host.run_command(["wget", url, "-O", "{0}-{1}.zip".format(dir, version)])
    host.run_command(
        ["unzip", "{0}-{1}.zip".format(dir, version), "-d", "/opt/"]
    )
    host.run_command(["mv", "{0}-{1}".format(dir, version), dir])
    host.run_command(["groupadd", "keycloak"])
    host.run_command(
        ["useradd", "-r", "-g", "keycloak", "-d", dir, "keycloak"]
    )
    host.run_command(["chown", "-R", "keycloak:", dir])
    host.run_command(["chmod", "o+x", "{0}/bin/".format(dir)])
    host.run_command(["restorecon", "-R", dir])

    # setup TLS certificate using IPA CA
    host.run_command(["kinit", "-k"])
    host.run_command(["ipa", "service-add", "HTTP/{0}".format(host.hostname)])

    key = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.key")
    crt = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.crt")
    keystore = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.jks")

    host.run_command(["ipa-getcert", "request", "-K",
                      "HTTP/{0}".format(host.hostname),
                      "-D", host.hostname, "-o", "keycloak",
                      "-O", "keycloak", "-m", "0600",
                      "-M", "0644",
                      "-k", key, "-f", crt, "-w"])
    host.run_command(["keytool", "-import", "-keystore", keystore,
                      "-file", "/etc/ipa/ca.crt",
                      "-alias", "ipa_ca",
                      "-trustcacerts", "-storepass", password, "-noprompt"])
    host.run_command(["chown", "keycloak:keycloak", keystore])

    # Setup keycloak service and config files
    contents = textwrap.dedent("""
    KC_BOOTSTRAP_ADMIN_USERNAME=admin
    KC_BOOTSTRAP_ADMIN_PASSWORD={admin_pswd}
    KC_HOSTNAME=https://{host}:8443/
    KC_HTTPS_CERTIFICATE_FILE={crt}
    KC_HTTPS_CERTIFICATE_KEY_FILE={key}
    KC_HTTPS_TRUST_STORE_FILE={store}
    KC_HTTPS_TRUST_STORE_PASSWORD={store_pswd}
    KC_HTTPS_CLIENT_AUTH=none
    """).format(admin_pswd=password, host=host.hostname, crt=crt, key=key,
                store=keystore, store_pswd=password)
    host.put_file_contents("/etc/sysconfig/keycloak", contents)

    contents = textwrap.dedent("""
    [Unit]
    Description=Keycloak Server
    After=network.target

    [Service]
    Type=idle
    EnvironmentFile=/etc/sysconfig/keycloak

    User=keycloak
    Group=keycloak
    ExecStart=/opt/keycloak/bin/kc.sh start
    TimeoutStartSec=600
    TimeoutStopSec=600

    [Install]
    WantedBy=multi-user.target
    """)
    host.put_file_contents("/etc/systemd/system/keycloak.service", contents)
    host.run_command(["systemctl", "daemon-reload"])

    # Run build stage first
    env_vars = textwrap.dedent("""
    export KC_BOOTSTRAP_ADMIN_USERNAME=admin
    export KC_HOSTNAME=https://{hostname}:8443/
    export KC_HTTPS_CERTIFICATE_FILE=/etc/pki/tls/certs/keycloak.crt
    export KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/pki/tls/private/keycloak.key
    export KC_HTTPS_TRUST_STORE_FILE=/etc/pki/tls/private/keycloak.jks
    export KC_HTTPS_TRUST_STORE_PASSWORD={STORE_PASS}
    export KC_BOOTSTRAP_ADMIN_PASSWORD={ADMIN_PASS}
    export KC_HTTPS_CLIENT_AUTH=none
    """).format(hostname=host.hostname, STORE_PASS=password,
                ADMIN_PASS=password)

    tasks.backup_file(host, '/etc/bashrc')
    content = host.get_file_contents('/etc/bashrc',
                                     encoding='utf-8')
    new_content = content + "\n{}".format(env_vars)
    host.put_file_contents('/etc/bashrc', new_content)
    host.run_command(['bash'])
    host.run_command(
        ['su', '-', 'keycloak', '-c', '/opt/keycloak/bin/kc.sh build'])
    host.run_command(["systemctl", "start", "keycloak"])
    host.run_command(["/opt/keycloak/bin/kc.sh", "show-config"])

    # Setup keycloak for use:
    kcadmin_sh = "/opt/keycloak/bin/kcadm.sh"

    host.run_command([kcadmin_sh, "config", "truststore",
                      "--trustpass", password, keystore])
    kcadmin = [kcadmin_sh, "config", "credentials", "--server",
               "https://{0}:8443/".format(host.hostname),
               "--realm", "master", "--user", "admin",
               "--password", password
               ]
    tasks.run_repeatedly(
        host, kcadmin, timeout=60)
    host.run_command(
        [kcadmin_sh, "create", "users", "-r", "master",
         "-s", "username=testuser1", "-s", "enabled=true",
         "-s", "email=testuser1@ipa.test"]
    )
    host.run_command(
        [kcadmin_sh, "set-password", "-r", "master",
         "--username", "testuser1", "--new-password", password]
    )


def setup_keycloak_client(host):
    password = host.config.admin_password
    host.run_command(["/opt/keycloak/bin/kcreg.sh",
                      "config", "credentials", "--server",
                      "https://{0}:8443/".format(host.hostname),
                      "--realm", "master", "--user", "admin",
                      "--password", password]
                     )

    client_json = textwrap.dedent("""
    {{
      "enabled" : true,
      "clientAuthenticatorType" : "client-secret",
      "redirectUris" : [ "https://ipa-ca.{redirect}/ipa/idp/*" ],
      "webOrigins" : [ "https://ipa-ca.{web}" ],
      "protocol" : "openid-connect",
      "attributes" : {{
      "oauth2.device.authorization.grant.enabled" : "true",
      "oauth2.device.polling.interval": "5"
      }}
    }}
    """).format(redirect=host.domain.name, web=host.domain.name)
    host.put_file_contents("/tmp/ipa_client.json", client_json)
    host.run_command(["/opt/keycloak/bin/kcreg.sh", "create",
                      "-f", "/tmp/ipa_client.json",
                      "-s", "clientId=ipa_oidc_client",
                      "-s", "secret={0}".format(password)]
                     )
    time.sleep(60)


def uninstall_keycloak(host):
    key = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.key")
    crt = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.crt")
    keystore = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.jks")

    host.run_command(["systemctl", "stop", "keycloak"], raiseonerr=False)
    host.run_command(["getcert", "stop-tracking", "-k", key, "-f", crt],
                     raiseonerr=False)
    host.run_command(["rm", "-rf", "/opt/keycloak",
                      "/etc/sysconfig/keycloak",
                      "/etc/systemd/system/keycloak.service",
                      key, crt, keystore])
    host.run_command(["systemctl", "daemon-reload"])
    host.run_command(["userdel", "keycloak"])
    host.run_command(["groupdel", "keycloak"], raiseonerr=False)
    tasks.restore_files(host)
