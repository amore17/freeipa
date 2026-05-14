from __future__ import absolute_import

import base64
import json
import os
import random
import re
import time
from datetime import timezone
import urllib.error
import urllib.parse
import urllib.request

import pytest
import textwrap
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks, create_keycloak

# OAuth device flow: Keycloak prints "Authenticate at {url} ..."; Microsoft
# Entra prints "Authenticate with PIN {user_code} at {url} ..." and the user
# must submit {user_code} on the device login page before signing in.
DEVICE_AUTH_PROMPT_RE = re.compile(
    r'Authenticate(?:\s+with\s+PIN\s+(\S+))?'
    r'\s+at\s+(.+?)\s+and\s+press\s+ENTER\.:',
    re.DOTALL,
)


def parse_device_auth_prompt(prompt):
    match = DEVICE_AUTH_PROMPT_RE.search(prompt)
    assert match is not None, prompt
    user_code = match.group(1)
    uri = match.group(2).strip()
    return uri, (user_code.strip() if user_code else None)


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
    from selenium import webdriver
    from datetime import datetime
    from packaging.version import parse as parse_version
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    import time
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

    """
).strip() + "\n\n"


KEYCLOCK_USER_CODE_BODY = textwrap.dedent(
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

keyclock_user_code_script = (
    SELENIUM_REMOTE_HEAD
    + KEYCLOCK_USER_CODE_BODY
    + "\n"
    + selenium_remote_finally("/var/log/httpd/screenshot-keyclock-%s.png")
)


def run_remote_selenium(host, script, remote_basename, timeout=30):
    path = "/tmp/%s" % remote_basename
    try:
        host.put_file_contents(path, script)
        tasks.run_repeatedly(host, ["python3", path], timeout=timeout)
    finally:
        host.run_command(["rm", "-f", path])


def add_keyclock_user_code(host, verification_uri):
    contents = keyclock_user_code_script.format(
        uri=verification_uri,
        passwd=host.config.admin_password,
    )
    run_remote_selenium(host, contents, "add_keyclock_user_code.py")


def kinit_idp(
    host,
    user,
    keycloak_server=None,
    *,
    azure_email=None,
    azure_password=None,
):
    """
    kinit for users with --user-auth-type=idp: complete OAuth2 device code flow
    in a browser. Use either keycloak_server= for Keycloak, or
    azure_email= and azure_password= for Microsoft Entra.
    """
    if keycloak_server is not None:
        if azure_email is not None or azure_password is not None:
            raise TypeError(
                "kinit_idp: do not combine keycloak_server= with "
                "azure_email=/azure_password="
            )
    elif azure_email is not None and azure_password is not None:
        pass
    elif azure_email is not None or azure_password is not None:
        raise TypeError(
            "kinit_idp: for Microsoft IdP, pass both azure_email= and "
            "azure_password="
        )
    else:
        raise TypeError(
            "kinit_idp: pass keycloak_server=... (Keycloak) or both "
            "azure_email= and azure_password= (Microsoft)"
        )

    ARMOR = "/tmp/armor"
    tasks.kdestroy_all(host)
    # create armor for FAST
    host.run_command(["kinit", "-n", "-c", ARMOR])
    cmd = ["kinit", "-T", ARMOR, user]

    with host.spawn_expect(cmd, default_timeout=100) as e:
        e.expect(DEVICE_AUTH_PROMPT_RE)
        prompt = e.get_last_output()
        uri, device_user_code = parse_device_auth_prompt(prompt)
        time.sleep(15)
        if uri:
            if keycloak_server is not None:
                add_keyclock_user_code(keycloak_server, uri)
            else:
                add_azure_user_code(
                    host, uri, azure_email, azure_password,
                    device_user_code=device_user_code,
                )
        e.sendline('\n')
        e.expect_exit()

    test_idp = host.run_command(["klist", "-C"])
    assert "152" in test_idp.stdout_text


AZUREUSER_CODE_BODY = textwrap.dedent(
    """
    DEVICE_USER_CODE = {device_user_code!r}
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
        # Entra: submit user code on "Enter code to allow access" first
        if DEVICE_USER_CODE:
            def _find_code_input(d):
                selectors = [
                    (By.NAME, "otc"),
                    (By.ID, "otc"),
                    (By.CSS_SELECTOR, "input[name='otc']"),
                    (By.CSS_SELECTOR, "input[formcontrolname='otc']"),
                    (By.CSS_SELECTOR, "input[aria-label*='Code']"),
                    (By.CSS_SELECTOR, "input[aria-label*='code']"),
                    (By.CSS_SELECTOR, "input[placeholder*='Code']"),
                    (By.CSS_SELECTOR, "input[placeholder*='code']"),
                ]
                last_exc = None
                for by, sel in selectors:
                    try:
                        return WebDriverWait(d, 10).until(
                            EC.element_to_be_clickable((by, sel)))
                    except Exception as exc:
                        last_exc = exc
                        continue
                raise last_exc

            code_el = _find_code_input(driver)
            code_el.clear()
            code_el.send_keys(DEVICE_USER_CODE)
            time.sleep(0.5)
            next_btn = WebDriverWait(driver, 15).until(
                EC.element_to_be_clickable((By.ID, "idSIButton9")))
            next_btn.click()
            time.sleep(2)
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
    """
).strip()

azure_user_code_script = (
    SELENIUM_REMOTE_HEAD
    + AZUREUSER_CODE_BODY
    + "\n"
    + selenium_remote_finally("/var/log/httpd/screenshot-azure-%s.png")
)


def add_azure_user_code(host, verification_uri, username, password,
                        device_user_code=None):
    contents = azure_user_code_script.format(
        uri=verification_uri,
        username=username,
        password=password,
        device_user_code=device_user_code or "",
    )
    run_remote_selenium(host, contents, "add_azure_user_code.py",
                        timeout=180)


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


def _azure_multihost_config_missing_attrs(config):
    """Names of multihost config attributes that are None (Azure IdP suite)."""
    pairs = (
        ("azure_username", config.azure_username),
        ("azure_user_password", config.azure_user_password),
        ("azure_tenant_id", config.azure_tenant_id),
        ("azure_admin_client_id", config.azure_admin_client_id),
        ("azure_admin_client_secret", config.azure_admin_client_secret),
        ("azure_domain", config.azure_domain),
    )
    return [name for name, val in pairs if val is None]


# Directory and openssl artifacts for Azure app-registration certificate tests.
IDP_CLIENT_OPENSSL_WORKDIR = "/tmp/idp-client-openssl"
IDP_CLIENT_P12_PASSWORD = "MyP12Password"
# Installed on master for ``ipa idp-add --client-cert-p12=...`` (JWT client).
IDP_CLIENT_P12_IPA_PATH = "/etc/ipa/idp-client.p12"
IDP_CLIENT_P12_NOPASS_IPA_PATH = "/etc/ipa/idp-client-nopass.p12"


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


def new_idp_client_graph_cert_display_name():
    """
    Entra ``keyCredentials`` ``displayName`` unique per run: ``idp-client-``,
    UTC compact timestamp, and a random decimal suffix.
    """
    return "idp-client-%s-%06d" % (
        time.strftime("%Y%m%dT%H%M%S", time.gmtime()),
        random.randint(0, 999999),
    )


def _x509_validity_iso8601_z(cert):
    """Graph ``keyCredentials`` entries expect UTC ISO-8601 with Z suffix."""
    if hasattr(cert, "not_valid_before_utc"):
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    else:
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return (
        nb.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        na.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def azure_acquire_graph_token(tenant_id, client_id, client_secret):
    """Client-credentials token for ``https://graph.microsoft.com/.default``."""
    url = (
        "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
        % tenant_id
    )
    body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
    ).encode("ascii")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Azure token request failed: %s" % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError("Azure token request failed: %s" % e.reason) from e
    if "access_token" not in payload:
        raise RuntimeError("Azure token response missing access_token: %r" % payload)
    return payload["access_token"]


def azure_graph_application_object_id(access_token, app_id):
    """Resolve application (registration) object id from its ``appId`` (client id)."""
    params = urllib.parse.urlencode({"$filter": "appId eq '%s'" % app_id})
    url = "https://graph.microsoft.com/v1.0/applications?%s" % params
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer %s" % access_token)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph applications lookup failed: %s" % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError("Graph applications lookup failed: %s" % e.reason) from e
    values = data.get("value") or []
    if not values:
        raise RuntimeError(
            "No application registration found for appId %s" % app_id
        )
    return values[0]["id"]


def upload_idp_client_crt_to_entra_app(
    access_token,
    app_object_id,
    pem_certificate_bytes,
    display_name="idp-client",
):
    """
    Upload a PEM X.509 certificate to the Entra ID app registration's
    ``keyCredentials`` (Microsoft Graph ``PATCH /applications/{id}``).

    Appends a new ``AsymmetricX509Cert`` entry; skips if the same DER is
    already present.  PEM is decoded to DER because Graph expects base64 DER
    in JSON (see Microsoft Learn: add certificate via Graph).

    ``startDateTime`` / ``endDateTime`` are taken from the certificate validity
    interval; omitting them can cause PATCH to fail.
    """
    if isinstance(pem_certificate_bytes, str):
        pem_certificate_bytes = pem_certificate_bytes.encode("ascii")
    cert = x509.load_pem_x509_certificate(pem_certificate_bytes)
    der = cert.public_bytes(serialization.Encoding.DER)
    key_b64 = base64.b64encode(der).decode("ascii")
    start_z, end_z = _x509_validity_iso8601_z(cert)

    base_url = "https://graph.microsoft.com/v1.0/applications/%s" % app_object_id
    req_get = urllib.request.Request(base_url)
    req_get.add_header("Authorization", "Bearer %s" % access_token)
    try:
        with urllib.request.urlopen(req_get, timeout=60) as resp:
            app = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph GET application failed: %s" % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError("Graph GET application failed: %s" % e.reason) from e

    key_credentials = app.get("keyCredentials") or []
    for entry in key_credentials:
        if entry.get("key") == key_b64:
            return

    key_credentials.append(
        {
            "startDateTime": start_z,
            "endDateTime": end_z,
            "type": "AsymmetricX509Cert",
            "usage": "Verify",
            "key": key_b64,
            "displayName": display_name,
        }
    )
    patch_body = json.dumps({"keyCredentials": key_credentials}).encode("utf-8")
    req_patch = urllib.request.Request(base_url, data=patch_body, method="PATCH")
    req_patch.add_header("Authorization", "Bearer %s" % access_token)
    req_patch.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req_patch, timeout=60) as resp:
            # 204 No Content
            resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph PATCH keyCredentials failed: %s"
            % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            "Graph PATCH keyCredentials failed: %s" % e.reason
        ) from e


def delete_idp_client_crt_from_entra_app(
    access_token,
    app_object_id,
    pem_certificate_bytes,
):
    """
    Remove the certificate matching ``idp-client.crt`` (same base64 DER
    ``key`` as uploaded) from the app registration's ``keyCredentials``.

    No-op if that credential is not present. Uses the same Graph
    ``GET`` + ``PATCH`` pattern as :func:`upload_idp_client_crt_to_entra_app`.
    """
    if isinstance(pem_certificate_bytes, str):
        pem_certificate_bytes = pem_certificate_bytes.encode("ascii")
    cert = x509.load_pem_x509_certificate(pem_certificate_bytes)
    der = cert.public_bytes(serialization.Encoding.DER)
    key_b64 = base64.b64encode(der).decode("ascii")

    base_url = "https://graph.microsoft.com/v1.0/applications/%s" % app_object_id
    req_get = urllib.request.Request(base_url)
    req_get.add_header("Authorization", "Bearer %s" % access_token)
    try:
        with urllib.request.urlopen(req_get, timeout=60) as resp:
            app = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph GET application (delete cert) failed: %s"
            % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            "Graph GET application (delete cert) failed: %s" % e.reason
        ) from e

    key_credentials = app.get("keyCredentials") or []
    new_credentials = [e for e in key_credentials if e.get("key") != key_b64]
    if len(new_credentials) == len(key_credentials):
        return

    patch_body = json.dumps({"keyCredentials": new_credentials}).encode("utf-8")
    req_patch = urllib.request.Request(base_url, data=patch_body, method="PATCH")
    req_patch.add_header("Authorization", "Bearer %s" % access_token)
    req_patch.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req_patch, timeout=60) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph PATCH keyCredentials (delete cert) failed: %s"
            % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            "Graph PATCH keyCredentials (delete cert) failed: %s" % e.reason
        ) from e


def install_test_idp_device_flow_topology(cls):
    """
    Install master + client + replica and tune SSSD / ``ipa`` for IdP device
    flow tests. Shared by :class:`TestIDP` and
    :class:`TestIdpClientCertificateAuthStories`.
    """
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


def ipa_idp_cli_supports_client_certificate_options(host):
    """True when ``ipa idp-add`` advertises certificate client-auth options."""
    r = host.run_command(["ipa", "idp-add", "--help"], raiseonerr=False)
    if r.returncode != 0:
        return False
    return "client-auth-method" in r.stdout_text


def ipa_idp_cli_supports_idp_show_outfile(host):
    """True when ``ipa idp-show`` supports writing a certificate PEM file."""
    r = host.run_command(["ipa", "idp-show", "--help"], raiseonerr=False)
    if r.returncode != 0:
        return False
    return "--out" in r.stdout_text or "--outfile" in r.stdout_text


def ldap_idp_entry_dn(master, idp_cn):
    """Return DN string ``cn=<idp_cn>,cn=idp,<basedn>``."""
    return "cn=%s,cn=idp,%s" % (idp_cn, str(master.domain.basedn))


def azure_private_key_jwt_idp_full_e2e_workflow(
    testcase,
    *,
    ldap_assert_pkcs12_and_cert=True,
    extra_kinit_hosts=(),
    verify_pem_export_with_openssl=False,
):
    """
    Microsoft Entra IdP using PKCS#12 + ``private_key_jwt`` (RFC 7523).

    Graph upload, ``ipa idp-add``, optional LDAP checks, ``kinit`` on the
    default IdP client host and on any *extra_kinit_hosts*.
    """
    testcase.require_azure_multihost_config()
    testcase.ensure_azure_idp_and_user()

    workdir = generate_idp_client_openssl_bundle(testcase.master)
    crt_path = os.path.join(workdir, "idp-client.crt")
    pem_bytes = testcase.master.get_file_contents(crt_path)

    token = None
    app_object_id = None
    uploaded = False
    p12_on_master = False
    jwt_idp_added = False
    try:
        tasks.user_add(
            testcase.master,
            testcase.AZURE_JWT_IPA_USERNAME,
            first="azurejwt",
            last="UserJwt",
            extra_args=[
                "--user-auth-type=idp",
                "--idp-user-id=" + testcase.azure_username,
                "--idp=" + testcase.AZURE_JWT_IDP_NAME,
            ],
        )
        token = azure_acquire_graph_token(
            testcase.azure_tenant_id,
            testcase.azure_admin_client_id,
            testcase.azure_admin_client_secret,
        )
        app_object_id = azure_graph_application_object_id(
            token,
            testcase.azure_admin_client_id,
        )
        cert_display_name = new_idp_client_graph_cert_display_name()
        upload_idp_client_crt_to_entra_app(
            token,
            app_object_id,
            pem_bytes,
            display_name=cert_display_name,
        )
        uploaded = True

        p12_src = os.path.join(workdir, "idp-client.p12")
        testcase.master.run_command(
            ["cp", p12_src, IDP_CLIENT_P12_IPA_PATH])
        testcase.master.run_command(
            ["chmod", "600", IDP_CLIENT_P12_IPA_PATH])
        p12_on_master = True

        tasks.kinit_admin(testcase.master)
        issuer = (
            "https://login.microsoftonline.com/%s/v2.0"
            % testcase.azure_tenant_id
        )
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple()
        )
        idp_add_cmd = [
            "ipa", "idp-add", testcase.AZURE_JWT_IDP_NAME,
            "--provider=microsoft",
            "--organization=%s" % testcase.azure_tenant_id,
            "--issuer=%s" % issuer,
            "--client-id=%s" % testcase.azure_admin_client_id,
            "--client-auth-method=private_key_jwt",
            "--client-cert-p12-file=%s" % IDP_CLIENT_P12_IPA_PATH,
        ]
        p12_stdin = "%s\n%s\n" % (
            IDP_CLIENT_P12_PASSWORD,
            IDP_CLIENT_P12_PASSWORD,
        )
        testcase.master.run_command(idp_add_cmd, stdin_text=p12_stdin)
        cmd = ["journalctl", "-g", "IPA.API", "--since=%s" % since]
        journal = testcase.master.run_command(cmd)
        assert '"userpkcs12": "********"' in journal.stdout_text
        jwt_idp_added = True

        show_out = testcase.master.run_command(
            ["ipa", "idp-show", testcase.AZURE_JWT_IDP_NAME])
        assert "private_key_jwt" in show_out.stdout_text.lower()

        if ldap_assert_pkcs12_and_cert:
            idp_dn = ldap_idp_entry_dn(
                testcase.master, testcase.AZURE_JWT_IDP_NAME)
            ls = tasks.ldapsearch_dm(
                testcase.master,
                idp_dn,
                ldap_args=[
                    "(objectclass=*)", "objectClass",
                    "userCertificate", "userPKCS12",
                ],
                scope="base",
            )
            assert "userPKCS12" in ls.stdout_text
            assert "usercertificate" in ls.stdout_text.lower()
            oc_lower = ls.stdout_text.lower()
            if "ipaidpclientauth" in oc_lower:
                ls_m = tasks.ldapsearch_dm(
                    testcase.master,
                    idp_dn,
                    ldap_args=[
                        "(objectclass=*)", "ipaIdpClientAuthMethod",
                    ],
                    scope="base",
                    raiseonerr=False,
                )
                if ls_m.returncode == 0 and ls_m.stdout_text.strip():
                    assert (
                        "private_key_jwt" in ls_m.stdout_text.lower()
                    )

        tasks.clear_sssd_cache(testcase.client)
        tasks.wait_for_sssd_domain_status_online(testcase.client)
        wait_for_ipa_user_lookup_id(
            testcase.client, testcase.AZURE_JWT_IPA_USERNAME)
        kinit_idp(
            testcase.client,
            testcase.AZURE_JWT_IPA_USERNAME,
            azure_email=testcase.azure_username,
            azure_password=testcase.azure_user_password,
        )
        test_idp = testcase.client.run_command(["klist", "-C"])
        assert "152" in test_idp.stdout_text

        if verify_pem_export_with_openssl:
            assert ipa_idp_cli_supports_idp_show_outfile(testcase.master), (
                "workflow called with verify_pem_export_with_openssl but "
                "CLI has no certificate export option"
            )
            pem_out = "/tmp/idp-show-export-cert-test.pem"
            testcase.master.run_command(
                ["rm", "-f", pem_out],
                raiseonerr=False,
            )
            testcase.master.run_command(
                [
                    "ipa", "idp-show", testcase.AZURE_JWT_IDP_NAME,
                    "--out", pem_out,
                ],
            )
            testcase.master.run_command(
                ["openssl", "x509", "-in", pem_out, "-text", "-noout"],
            )

        for extra in extra_kinit_hosts:
            tasks.clear_sssd_cache(extra)
            tasks.wait_for_sssd_domain_status_online(extra)
            wait_for_ipa_user_lookup_id(
                extra, testcase.AZURE_JWT_IPA_USERNAME)
            kinit_idp(
                extra,
                testcase.AZURE_JWT_IPA_USERNAME,
                azure_email=testcase.azure_username,
                azure_password=testcase.azure_user_password,
            )
            out = extra.run_command(["klist", "-C"])
            assert "152" in out.stdout_text

    finally:
        if jwt_idp_added:
            try:
                tasks.kinit_admin(testcase.master)
                testcase.master.run_command(
                    ["ipa", "idp-del", testcase.AZURE_JWT_IDP_NAME],
                    raiseonerr=False,
                )
            except Exception:
                pass
        if p12_on_master:
            try:
                testcase.master.run_command(
                    ["rm", "-f", IDP_CLIENT_P12_IPA_PATH],
                    raiseonerr=False,
                )
            except Exception:
                pass
        if uploaded and token is not None and app_object_id is not None:
            try:
                delete_idp_client_crt_from_entra_app(
                    token, app_object_id, pem_bytes)
            except Exception:
                pass


class TestIDP(IntegrationTest):

    num_replicas = 2
    topology = 'line'
    AZURE_IDP_NAME = "azureidp"
    AZURE_IPA_USERNAME = "testazure"
    AZURE_JWT_IPA_USERNAME = "testazurejwt"
    AZURE_JWT_IDP_NAME = "Azure-JWT"

    @classmethod
    def install(cls, mh):
        install_test_idp_device_flow_topology(cls)

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

    def require_azure_multihost_config(self):
        """Skip if Azure multihost config is incomplete."""
        cfg = self.master.config
        missing = _azure_multihost_config_missing_attrs(cfg)
        if missing:
            pytest.skip(
                "Azure IdP tests require these multihost configuration "
                "attributes (non-null): " + ", ".join(missing)
            )
        self.azure_username = cfg.azure_username
        self.azure_user_password = cfg.azure_user_password
        self.azure_tenant_id = cfg.azure_tenant_id
        self.azure_admin_client_id = cfg.azure_admin_client_id
        self.azure_admin_client_secret = cfg.azure_admin_client_secret
        self.azure_domain = cfg.azure_domain

    def ensure_azure_idp_and_user(self):
        """Create Microsoft IdP and linked IPA user if absent."""
        host = self.master
        idp_name = self.AZURE_IDP_NAME
        ipa_user = self.AZURE_IPA_USERNAME
        tasks.kinit_admin(host)
        idp_show = host.run_command(
            ["ipa", "idp-show", idp_name], raiseonerr=False)
        if idp_show.returncode != 0:
            host.run_command(
                [
                    "ipa", "idp-add", idp_name,
                    "--provider", "microsoft",
                    "--organization", self.azure_tenant_id,
                    "--client-id", self.azure_admin_client_id,
                    "--secret",
                ],
                stdin_text=self.azure_admin_client_secret + "\n",
            )

        user_show = host.run_command(
            ["ipa", "user-show", ipa_user], raiseonerr=False)
        if user_show.returncode != 0:
            tasks.user_add(
                host,
                ipa_user,
                first="azure",
                last="User",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.azure_username,
                    "--idp=" + idp_name,
                ],
            )

    def test_azure_idp_add_and_user(self):
        """
        Add Azure IDP with Microsoft provider and associate user with mail id.

        Uses ipa idp-add with --provider microsoft, --organization (tenant ID),
        --client-id, and --secret from stdin. Then adds IPA user linked to
        the IdP with idp-user-id set to the user's email.
        """
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()

        result = self.master.run_command(
            ["ipa", "idp-show", self.AZURE_IDP_NAME])
        assert self.AZURE_IDP_NAME in result.stdout_text
        assert "login.microsoftonline.com" in result.stdout_text

        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=" + self.azure_username]
        )
        assert self.AZURE_IPA_USERNAME in list_user.stdout_text

        list_by_idp = self.master.run_command(
            ["ipa", "user-find", "--idp=" + self.AZURE_IDP_NAME]
        )
        assert self.AZURE_IPA_USERNAME in list_by_idp.stdout_text


    def test_azure_idp_kinit(self):
        """
        Full OAuth 2.0 Device Authorization Grant kinit with Azure IdP.

        Performs kinit with FAST armor for the IdP-configured user and
        automates the Microsoft login page via headless Selenium to
        complete the device code flow end-to-end.  Verifies the
        resulting ticket carries the IdP authentication indicator (152).
        """
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()
        tasks.clear_sssd_cache(self.client)
        tasks.wait_for_sssd_domain_status_online(self.client)
        wait_for_ipa_user_lookup_id(self.client, self.AZURE_IPA_USERNAME)
        kinit_idp(
            self.client,
            self.AZURE_IPA_USERNAME,
            azure_email=self.azure_username,
            azure_password=self.azure_user_password,
        )

    def test_azure_cert(self):
        """
        Test CERT AZURE certificate authorization grant.

        Generate client certificate material with openssl on the IPA master,
        upload ``idp-client.crt`` to the Entra app registration used for IdP
        (same ``azure_admin_client_id`` as ``ipa idp-add``), then install the
        PKCS#12 bundle on the master and run ``ipa idp-add`` for JWT client
        auth (``private_key_jwt``) against Microsoft OIDC issuer v2.0.
        """
        if not ipa_idp_cli_supports_client_certificate_options(self.master):
            pytest.skip(
                "ipa idp-add has no --client-auth-method / PKCS#12 options"
            )
        azure_private_key_jwt_idp_full_e2e_workflow(self)


def ipa_idp_mod_supports_client_certificate_options(host):
    r = host.run_command(["ipa", "idp-mod", "--help"], raiseonerr=False)
    if r.returncode != 0:
        return False
    return "client-auth-method" in r.stdout_text


class TestIdpClientCertificateAuthStories(IntegrationTest):
    """
    Acceptance-oriented coverage for external IdP client authentication
    using PKCS#12 bundles (RFC 7523 ``private_key_jwt``) and related
    operational stories. Each test docstring references the story (S#) and
    workflow test case id (TC-*) from the IdP certificate-auth backlog.

    **Stories**

    S1 — Configure new IdP using JWT client assertion (RFC 7523).
    S2 — Configure new IdP using mTLS client authentication (RFC 8705).
    S3 — Migrate existing IdP from client secret to certificate auth.
    S4 — Separation of duties for IdP management vs secret material.
    S5 — Certificate rotation (replace PKCS#12 on an IdP entry).
    S6 — Multi-master / replica topology (config replicates; auth works).
    S7 — Upgrade / backup / restore preserves IdP cert auth.

    **Test case mapping (automate vs manual)**

    * TC-A01 / TC-B01 / TC-E01 (partial) — ``test_story_s1_s6_azure_jwt_cli_ldap_and_kinit``
    * TC-A02 — ``test_story_s2_tls_client_auth_placeholder`` (manual / future lab)
    * TC-A03 — ``test_tc_a03_keycloak_client_secret_backward_compat``
    * PKCS#12 empty passphrase — ``test_idp_add_pkcs12_empty_passphrase_succeeds``
    * TC-A04 — UI only (manual)
    * TC-A05 — ``test_story_s1_tc_a05_idp_show_pem_export`` when ``ipa idp-show --out`` exists
    * TC-B02 — covered by S2 placeholder until Keycloak mTLS automation exists
    * TC-B03 — ``test_tc_b03_ipa_otpd_stopped_negative``
    * TC-C01 — ``test_story_s3_tc_c01_migrate_secret_to_private_key_jwt``
    * TC-C02 / TC-C03 / TC-C04 — mix of ``test_tc_c04_mod_method_without_p12`` and skips
    * TC-D01 / TC-D02 / TC-D04 — ``test_tc_d01_d02_d04_idp_rbac_and_ldap``
    * TC-D03 — implied when admin ``ipa idp-show --all`` is exercised elsewhere
    * TC-D05 / TC-D06 — not automated here (filesystem + log scanning)
    * TC-E01 — replica kinit inside ``test_story_s1_s6_azure_jwt_cli_ldap_and_kinit``
    * TC-E02 — old-replica mixed topology (manual; skipped)
    * TC-E03 — upgrade schema (manual / upgrade suite)
    * TC-E04 — ``test_story_s7_tc_e04_backup_restore_note`` (documented skip)
    """

    num_replicas = 2
    topology = 'line'
    AZURE_IDP_NAME = "azureidp"
    AZURE_IPA_USERNAME = "testazure"
    AZURE_JWT_IPA_USERNAME = "testazurejwt"
    AZURE_JWT_IDP_NAME = "Azure-JWT"

    @classmethod
    def install(cls, mh):
        install_test_idp_device_flow_topology(cls)

    def require_azure_multihost_config(self):
        """Skip if Azure multihost config is incomplete."""
        cfg = self.master.config
        missing = _azure_multihost_config_missing_attrs(cfg)
        if missing:
            pytest.skip(
                "Azure IdP tests require these multihost configuration "
                "attributes (non-null): " + ", ".join(missing)
            )
        self.azure_username = cfg.azure_username
        self.azure_user_password = cfg.azure_user_password
        self.azure_tenant_id = cfg.azure_tenant_id
        self.azure_admin_client_id = cfg.azure_admin_client_id
        self.azure_admin_client_secret = cfg.azure_admin_client_secret
        self.azure_domain = cfg.azure_domain

    def ensure_azure_idp_and_user(self):
        """Create Microsoft IdP and linked IPA user if absent."""
        host = self.master
        idp_name = self.AZURE_IDP_NAME
        ipa_user = self.AZURE_IPA_USERNAME
        tasks.kinit_admin(host)
        idp_show = host.run_command(
            ["ipa", "idp-show", idp_name], raiseonerr=False)
        if idp_show.returncode != 0:
            host.run_command(
                [
                    "ipa", "idp-add", idp_name,
                    "--provider", "microsoft",
                    "--organization", self.azure_tenant_id,
                    "--client-id", self.azure_admin_client_id,
                    "--secret",
                ],
                stdin_text=self.azure_admin_client_secret + "\n",
            )

        user_show = host.run_command(
            ["ipa", "user-show", ipa_user], raiseonerr=False)
        if user_show.returncode != 0:
            tasks.user_add(
                host,
                ipa_user,
                first="azure",
                last="User",
                extra_args=[
                    "--user-auth-type=idp",
                    "--idp-user-id=" + self.azure_username,
                    "--idp=" + idp_name,
                ],
            )

    def test_story_s1_s6_azure_jwt_cli_ldap_and_kinit(self):
        """
        S1 / S6 — TC-A01, TC-B01, TC-E01 (replica path).

        ``ipa idp-add`` with ``--client-auth-method=private_key_jwt`` and
        PKCS#12; LDAP carries cert material; Kerberos device flow succeeds on
        the client and on a second replica.
        """
        if not ipa_idp_cli_supports_client_certificate_options(self.master):
            pytest.skip(
                "ipa idp-add has no --client-auth-method / PKCS#12 options"
            )
        self.require_azure_multihost_config()
        azure_private_key_jwt_idp_full_e2e_workflow(
            self,
            extra_kinit_hosts=(self.replica,),
        )

    def test_story_s1_tc_a05_idp_show_pem_export(self):
        """
        S1 — TC-A05 (PEM export + ``openssl x509`` parse).

        Requires ``ipa idp-show --out`` (or equivalent) on the server under test.
        """
        if not ipa_idp_cli_supports_client_certificate_options(self.master):
            pytest.skip(
                "ipa idp-add has no --client-auth-method / PKCS#12 options"
            )
        if not ipa_idp_cli_supports_idp_show_outfile(self.master):
            pytest.skip("ipa idp-show has no PEM export option (TC-A05)")
        self.require_azure_multihost_config()
        azure_private_key_jwt_idp_full_e2e_workflow(
            self,
            verify_pem_export_with_openssl=True,
        )

    def test_story_s2_tls_client_auth_placeholder(self):
        """
        S2 — TC-A02 / TC-B02 (``tls_client_auth`` / RFC 8705).

        Automating mTLS against a token endpoint needs a dedicated IdP lab
        (Keycloak mutual TLS, wire capture, or proxy assertions). Track as
        manual / future integration once ``--client-auth-method=tls_client_auth``
        is exercised the same way as ``private_key_jwt`` here.
        """
        pytest.skip(
            "TC-A02/TC-B02: tls_client_auth + mTLS token endpoint lab not wired"
        )

    def test_story_s3_tc_c01_migrate_secret_to_private_key_jwt(self):
        """
        S3 — TC-C01 (``client_secret`` IdP → ``private_key_jwt``).

        Starts from the Entra ``azureidp`` entry created with ``--secret``,
        uploads a new client cert to the same app registration, then runs
        ``ipa idp-mod`` with PKCS#12 material and re-checks device-flow kinit.
        """
        if not ipa_idp_cli_supports_client_certificate_options(self.master):
            pytest.skip(
                "ipa idp-add has no --client-auth-method / PKCS#12 options"
            )
        if not ipa_idp_mod_supports_client_certificate_options(self.master):
            pytest.skip("ipa idp-mod has no client certificate auth options")
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()

        token = None
        app_object_id = None
        pem_bytes = None
        workdir = generate_idp_client_openssl_bundle(self.master)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)
        token = azure_acquire_graph_token(
            self.azure_tenant_id,
            self.azure_admin_client_id,
            self.azure_admin_client_secret,
        )
        app_object_id = azure_graph_application_object_id(
            token,
            self.azure_admin_client_id,
        )
        cert_display_name = new_idp_client_graph_cert_display_name()
        upload_idp_client_crt_to_entra_app(
            token,
            app_object_id,
            pem_bytes,
            display_name=cert_display_name,
        )
        p12_src = os.path.join(workdir, "idp-client.p12")
        self.master.run_command(["cp", p12_src, IDP_CLIENT_P12_IPA_PATH])
        self.master.run_command(["chmod", "600", IDP_CLIENT_P12_IPA_PATH])
        issuer = (
            "https://login.microsoftonline.com/%s/v2.0"
            % self.azure_tenant_id
        )
        try:
            tasks.kinit_admin(self.master)
            mod_cmd = [
                "ipa", "idp-mod", self.AZURE_IDP_NAME,
                "--issuer=%s" % issuer,
                "--client-auth-method=private_key_jwt",
                "--client-cert-p12-file=%s" % IDP_CLIENT_P12_IPA_PATH,
            ]
            p12_stdin = "%s\n%s\n" % (
                IDP_CLIENT_P12_PASSWORD,
                IDP_CLIENT_P12_PASSWORD,
            )
            self.master.run_command(mod_cmd, stdin_text=p12_stdin)
            show = self.master.run_command(
                ["ipa", "idp-show", self.AZURE_IDP_NAME])
            assert "private_key_jwt" in show.stdout_text.lower()
            idp_dn = ldap_idp_entry_dn(self.master, self.AZURE_IDP_NAME)
            ls = tasks.ldapsearch_dm(
                self.master,
                idp_dn,
                ldap_args=[
                    "(objectclass=*)", "objectClass",
                    "userCertificate", "userPKCS12",
                ],
                scope="base",
            )
            assert "userPKCS12" in ls.stdout_text
            tasks.clear_sssd_cache(self.client)
            tasks.wait_for_sssd_domain_status_online(self.client)
            wait_for_ipa_user_lookup_id(self.client, self.AZURE_IPA_USERNAME)
            kinit_idp(
                self.client,
                self.AZURE_IPA_USERNAME,
                azure_email=self.azure_username,
                azure_password=self.azure_user_password,
            )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["rm", "-f", IDP_CLIENT_P12_IPA_PATH],
                raiseonerr=False,
            )
            if (
                token is not None
                and app_object_id is not None
                and pem_bytes is not None
            ):
                delete_idp_client_crt_from_entra_app(
                    token, app_object_id, pem_bytes)
            # Best-effort: return to interactive client secret auth for reruns
            self.master.run_command(
                ["ipa", "idp-mod", self.AZURE_IDP_NAME, "--secret"],
                stdin_text=self.azure_admin_client_secret + "\n",
                raiseonerr=False,
            )

    def test_story_s5_tc_c03_certificate_rotation_placeholder(self):
        """
        S5 — TC-C03 (replace PKCS#12 on an existing cert-based IdP).

        Same shape as ``ipa idp-mod ... --client-cert-p12-file=`` with a new
        bundle once two distinct client certs are registered with the IdP;
        skipped here to avoid a second Graph upload cycle in every CI run.
        """
        pytest.skip(
            "TC-C03: rotation test is a second idp-mod + new P12; run ad-hoc "
            "when validating expiry/compromise workflows"
        )

    def test_story_s7_tc_e04_backup_restore_note(self):
        """
        S7 — TC-E04 (backup / restore preserves cert-based IdP).

        ``TestIDP.test_idp_backup_restore`` already covers client-secret IdP
        references; extending it with PKCS#12 attributes belongs in that test
        once backup metadata is confirmed to include binary ``userPKCS12``.
        """
        pytest.skip(
            "TC-E04: extend ipa-backup/ipa-restore coverage for userPKCS12 "
            "alongside TestIDP.test_idp_backup_restore"
        )

    def test_tc_a03_keycloak_client_secret_backward_compat(self):
        """
        S1 (negative / compat) — TC-A03.

        Default ``ipa idp-add`` with ``--secret`` and no client-auth method
        continues to provision Keycloak-backed IdPs unchanged.
        """
        create_keycloak.setup_keycloakserver(self.client)
        time.sleep(60)
        create_keycloak.setup_keycloak_client(self.client)
        tasks.kinit_admin(self.master)
        pw = self.client.config.admin_password
        self.master.run_command(
            [
                "ipa", "idp-add", "keycloakidp", "--provider=keycloak",
                "--client-id=ipa_oidc_client", "--org=master",
                "--base-url={0}:8443".format(self.client.hostname),
            ],
            stdin_text="{0}\n{0}".format(pw),
        )
        show = self.master.run_command(["ipa", "idp-show", "keycloakidp"])
        text = show.stdout_text.lower()
        assert "private_key_jwt" not in text
        assert "tls_client_auth" not in text
        tasks.user_add(
            self.master,
            "keycloakuser",
            extra_args=["--user-auth-type=idp",
                        "--idp-user-id=testuser1@ipa.test",
                        "--idp=keycloakidp"],
        )
        tasks.clear_sssd_cache(self.master)
        kinit_idp(self.master, "keycloakuser", keycloak_server=self.client)

    def test_idp_add_pkcs12_empty_passphrase_succeeds(self):
        """
        ``ipa idp-add`` must accept a PKCS#12 with an empty MAC password.

        Supplying only newlines for the PKCS#12 passphrase prompts used to
        trigger an uncaught ``InternalError``; the server must either import
        the bundle successfully or return a normal validation error — never
        ``InternalError``.
        """
        if not ipa_idp_cli_supports_client_certificate_options(self.master):
            pytest.skip(
                "ipa idp-add has no --client-auth-method / PKCS#12 options"
            )
        tasks.kinit_admin(self.master)
        nopass_name = "keycloakidpnopassp12"
        workdir = "/tmp/idp-openssl-nopass-%06d" % random.randint(0, 999999)
        generate_idp_client_openssl_bundle(
            self.master, workdir=workdir, p12_password="")
        p12_src = os.path.join(workdir, "idp-client.p12")
        self.master.run_command(
            [
                "openssl", "pkcs12", "-in", p12_src, "-nodes",
                "-passin", "pass:", "-noout",
            ],
            cwd=workdir,
        )
        self.master.run_command(["cp", p12_src, IDP_CLIENT_P12_NOPASS_IPA_PATH])
        self.master.run_command(["chmod", "600", IDP_CLIENT_P12_NOPASS_IPA_PATH])
        pw = self.client.config.admin_password
        try:
            res = self.master.run_command(
                [
                    "ipa", "idp-add", nopass_name,
                    "--provider=keycloak",
                    "--client-id=ipa_oidc_client",
                    "--org=master",
                    "--base-url={0}:8443".format(self.client.hostname),
                    "--client-auth-method=private_key_jwt",
                    "--client-cert-p12-file=%s" % IDP_CLIENT_P12_NOPASS_IPA_PATH,
                ],
                stdin_text="\n\n",
                raiseonerr=False,
            )
            combined = res.stdout_text + res.stderr_text
            assert "internalerror" not in combined.lower(), combined
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "idp-del", nopass_name],
                raiseonerr=False,
            )
            self.master.run_command(
                ["rm", "-f", IDP_CLIENT_P12_NOPASS_IPA_PATH],
                raiseonerr=False,
            )
            self.master.run_command(["rm", "-rf", workdir], raiseonerr=False)

    def test_tc_c04_mod_method_without_p12_behavior(self):
        """
        S3 — TC-C04 (method switch without supplying a new PKCS#12 file).

        Asserts the CLI either rejects the operation or documents the
        preservation behavior for an entry that still has no cert material.
        """
        if not ipa_idp_mod_supports_client_certificate_options(self.master):
            pytest.skip("ipa idp-mod has no --client-auth-method")
        tasks.kinit_admin(self.master)
        res = self.master.run_command(
            [
                "ipa", "idp-mod", "keycloakidp",
                "--client-auth-method=private_key_jwt",
            ],
            raiseonerr=False,
        )
        assert res.returncode != 0, (
            "TC-C04: idp-mod to private_key_jwt without P12 must fail or be "
            "explicitly documented as a no-op; got success without cert upload"
        )

    def test_tc_d01_d02_d04_idp_rbac_and_ldap(self):
        """
        S4 — TC-D01, TC-D02, TC-D04.

        * User without IdP read rights cannot run ``ipa idp-show``.
        * User with only *System: Read External IdP server* must not obtain
          ``ipaIdpClientSecret`` over LDAP.
        """
        tasks.kinit_admin(self.master)
        reader_pass = "SecretReader123!SecretReader123!"
        tasks.user_add(
            self.master,
            "idpnoidp",
            password=reader_pass,
            first="No",
            last="Idp",
        )
        tasks.user_add(
            self.master,
            "idpread",
            password=reader_pass,
            first="Idp",
            last="Reader",
        )
        priv = "idp_readonly_priv_%06d" % random.randint(0, 999999)
        role = "idp_readonly_role_%06d" % random.randint(0, 999999)
        try:
            self.master.run_command(
                ["ipa", "privilege-add", priv,
                 "--desc", "read idp metadata only"],
                raiseonerr=False,
            )
            perm_add = self.master.run_command(
                [
                    "ipa", "privilege-add-permission", priv,
                    "--permission", "System: Read External IdP server",
                ],
                raiseonerr=False,
            )
            if perm_add.returncode != 0:
                pytest.skip(
                    "TC-D02/D04: could not attach "
                    "'System: Read External IdP server' (%s)"
                    % perm_add.stderr_text.strip()
                )
            self.master.run_command(
                ["ipa", "role-add", role, "--desc", "IdP read-only"],
            )
            self.master.run_command(
                ["ipa", "role-add-member-privilege", role,
                 "--privileges", priv],
            )
            self.master.run_command(
                ["ipa", "role-add-member-user", role, "--users=idpread"],
            )

            tasks.kdestroy_all(self.master)
            tasks.kinit_as_user(self.master, "idpnoidp", reader_pass)
            no_right = self.master.run_command(
                ["ipa", "idp-show", "keycloakidp"],
                raiseonerr=False,
            )
            assert no_right.returncode != 0

            tasks.kdestroy_all(self.master)
            tasks.kinit_as_user(self.master, "idpread", reader_pass)
            ok_show = self.master.run_command(
                ["ipa", "idp-show", "keycloakidp"],
                raiseonerr=False,
            )
            assert ok_show.returncode == 0, ok_show.stderr_text

            basedn = str(self.master.domain.basedn)
            reader_dn = "uid=idpread,cn=users,cn=accounts,%s" % basedn
            idp_dn = ldap_idp_entry_dn(self.master, "keycloakidp")
            ldap_res = tasks.run_ldapsearch(
                self.master,
                reader_dn,
                reader_pass,
                idp_dn,
                ["(objectclass=*)", "ipaIdpClientSecret"],
                scope="base",
                raiseonerr=False,
            )
            assert "ipaIdpClientSecret::" not in ldap_res.stdout_text
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "role-del", role], raiseonerr=False)
            self.master.run_command(
                ["ipa", "privilege-del", priv], raiseonerr=False)
            tasks.user_del(self.master, "idpread", raiseonerr=False)
            tasks.user_del(self.master, "idpnoidp", raiseonerr=False)

    def test_tc_b03_ipa_otpd_stopped_negative(self):
        """
        S1/S2 — TC-B03 (``ipa-otpd`` outage).

        With IdP device flow configured, stopping ``ipa-otpd`` must yield a
        predictable Kerberos client failure rather than hanging indefinitely.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(["systemctl", "stop", "ipa-otpd"])
        try:
            tasks.kdestroy_all(self.master)
            res = self.master.run_command(
                ["timeout", "35", "kinit", "keycloakuser"],
                raiseonerr=False,
            )
            assert res.returncode != 0
        finally:
            self.master.run_command(
                ["systemctl", "start", "ipa-otpd"], raiseonerr=False)
            tasks.run_repeatedly(
                self.master,
                ["systemctl", "is-active", "ipa-otpd"],
                timeout=60,
            )
