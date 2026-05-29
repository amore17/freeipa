from __future__ import absolute_import

import base64
import inspect
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
    import time
    from selenium import webdriver
    from datetime import datetime
    from packaging.version import parse as parse_version
    from selenium.webdriver.firefox.options import Options
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC

    os.environ.setdefault("DISPLAY", ":99")

    def _firefox_driver():
        options = Options()
        # Keycloak may use KC_HTTPS_CLIENT_AUTH=request for mTLS tests; do not
        # block headless Firefox on an optional client-cert TLS prompt.
        options.set_preference(
            "security.default_personal_cert", "Select Automatically")
        options.set_capability("acceptInsecureCerts", True)
        if parse_version(webdriver.__version__) < parse_version('4.10.0'):
            options.headless = True
            drv = webdriver.Firefox(
                executable_path="/opt/geckodriver", options=options)
        else:
            options.add_argument('-headless')
            service = webdriver.FirefoxService(
                executable_path="/opt/geckodriver")
            drv = webdriver.Firefox(options=options, service=service)
        drv.set_page_load_timeout(60)
        return drv

    driver = _firefox_driver()

    """
).strip() + "\n\n"


KEYCLOCK_USER_CODE_BODY = textwrap.dedent(
    """
    verification_uri = "{uri}"
    driver.get(verification_uri)
    try:
        # Device flow may show a confirmation step before the login form.
        for _el_id in ("kc-login", "login", "continue"):
            try:
                btn = WebDriverWait(driver, 5).until(
                    EC.element_to_be_clickable((By.ID, _el_id)))
                btn.click()
                break
            except Exception:
                pass
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
        time.sleep(2)
    """
).strip()

azure_user_code_script = (
    SELENIUM_REMOTE_HEAD
    + AZUREUSER_CODE_BODY
    + "\n"
    + selenium_remote_finally("/var/log/httpd/screenshot-azure-%s.png")
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


def _azure_multihost_config_missing_attrs(config):
    """Names of multihost config attributes that are None (Azure IdP suite)."""
    pairs = (
        ("azure_username", config.azure_username),
        ("azure_user_password", config.azure_user_password),
        ("azure_tenant_id", config.azure_tenant_id),
        ("azure_admin_client_id", config.azure_admin_client_id),
        ("azure_admin_client_secret", config.azure_admin_client_secret),
    )
    return [name for name, val in pairs if val is None]


# Directory and openssl artifacts for Azure app-registration certificate tests.
IDP_CLIENT_OPENSSL_WORKDIR = "/tmp/idp-client-openssl"
IDP_CLIENT_P12_PASSWORD = "MyP12Password"
# Installed on master for ``ipa idp-add --client-cert-p12=...`` (JWT client).
IDP_CLIENT_P12_IPA_PATH = "/etc/ipa/idp-client.p12"
IDP_CLIENT_TLS_P12_IPA_PATH = "/etc/ipa/idp-client-tls.p12"
IDP_CLIENT_P12_NOPASS_IPA_PATH = "/etc/ipa/idp-client-nopass.p12"
IDP_CLIENT_AUTH_AUX_OC = "ipaidpclientauth"
# Entra ``keyCredentials`` ``displayName`` values from integration tests.
ENTRA_TEST_CERT_DISPLAY_PREFIX = "test_"

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
    """True if LDAP LDIF contains a value line for *attribute* (not ``# requesting``)."""
    attr_lower = attribute.lower()
    for line in ldap_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith(attr_lower + ":"):
            return True
    return False


def idp_access_denied(stderr_text):
    """True if CLI/LDAP output indicates IdP read access was denied."""
    text = stderr_text.lower()
    return "insufficient access" in text or "not found" in text


def idp_ldap_dn(host, idp_name):
    """LDAP DN of an IdP reference entry."""
    return "cn=%s,cn=idp,%s" % (idp_name, host.domain.basedn)


def idp_ldap_entry_text(host, idp_name, ldap_host=None):
    """Directory Manager ldapsearch of an IdP entry (optionally on *ldap_host*)."""
    ldap_host = ldap_host or host
    return tasks.ldapsearch_dm(
        ldap_host,
        idp_ldap_dn(host, idp_name),
        ["objectClass", "userPKCS12", "userCertificate;binary"],
        scope="base",
    ).stdout_text


def idp_show_out_available(host):
    """True if ``ipa idp-show --out=`` appears in CLI help on *host*."""
    help_out = host.run_command(
        ["ipa", "idp-show", "--help"], raiseonerr=False)
    return "--out" in help_out.stdout_text


def idp_show_out_works(host, idp_name, out_path):
    """True if ``ipa idp-show <idp> --out=`` succeeds (server implements it)."""
    if not idp_show_out_available(host):
        return False
    result = host.run_command(
        ["ipa", "idp-show", idp_name, "--out=%s" % out_path],
        raiseonerr=False,
    )
    if result.returncode != 0:
        return False
    return host.transport.file_exists(out_path)


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


def calling_test_name(suffix=""):
    """Pytest test function name (IntegrationTest is not unittest.TestCase)."""
    for frame_info in inspect.stack():
        if frame_info.function.startswith("test_"):
            name = frame_info.function
            break
    else:
        name = "idp-test"
    if suffix:
        name = "%s%s" % (name, suffix)
    return name


def new_idp_client_graph_cert_display_name(test_name):
    """
    Entra ``keyCredentials`` ``displayName``: ``<test_name>-<UTC date/time>``.
    """
    return "%s-%s" % (
        test_name,
        time.strftime("%Y%m%dT%H%M%S", time.gmtime()),
    )


def _graph_sanitize_key_credentials(key_credentials):
    """
    Prepare ``keyCredentials`` for Graph PATCH without dropping other types.

    Only omit broken ``AsymmetricX509Cert`` entries (null/empty ``key``).
    Password/secret credentials and non-cert types must be preserved.
    """
    sane = []
    for entry in key_credentials or []:
        if entry.get("type") == "AsymmetricX509Cert":
            if entry.get("key"):
                sane.append(entry)
        else:
            sane.append(entry)
    return sane


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
    if not pem_certificate_bytes:
        raise ValueError("empty PEM certificate")
    if isinstance(pem_certificate_bytes, str):
        pem_certificate_bytes = pem_certificate_bytes.encode("ascii")
    cert = x509.load_pem_x509_certificate(pem_certificate_bytes)
    der = cert.public_bytes(serialization.Encoding.DER)
    key_b64 = base64.b64encode(der).decode("ascii")
    if not key_b64:
        raise ValueError("empty DER for Graph keyCredentials")
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

    key_credentials = _graph_sanitize_key_credentials(
        app.get("keyCredentials"))
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
    if not pem_certificate_bytes:
        return
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

    key_credentials = _graph_sanitize_key_credentials(
        app.get("keyCredentials"))
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


def delete_entra_app_certs_by_display_name_prefix(
    access_token,
    app_object_id,
    display_name_prefix,
):
    """
    Remove all ``keyCredentials`` whose ``displayName`` starts with *prefix*.

    Used to clean up integration-test certificates when DER-based delete
    misses a credential (e.g. token failure or PEM mismatch).
    """
    if not display_name_prefix:
        return
    base_url = "https://graph.microsoft.com/v1.0/applications/%s" % app_object_id
    req_get = urllib.request.Request(base_url)
    req_get.add_header("Authorization", "Bearer %s" % access_token)
    try:
        with urllib.request.urlopen(req_get, timeout=60) as resp:
            app = json.loads(resp.read().decode())
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        raise RuntimeError(
            "Graph GET application (purge by displayName) failed: %s" % e
        ) from e

    key_credentials = _graph_sanitize_key_credentials(
        app.get("keyCredentials"))

    def _test_credential(entry):
        name = entry.get("displayName") or ""
        return name.startswith(display_name_prefix)

    new_credentials = [e for e in key_credentials if not _test_credential(e)]
    if len(new_credentials) == len(key_credentials):
        return

    patch_body = json.dumps({"keyCredentials": new_credentials}).encode("utf-8")
    req_patch = urllib.request.Request(base_url, data=patch_body, method="PATCH")
    req_patch.add_header("Authorization", "Bearer %s" % access_token)
    req_patch.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req_patch, timeout=60) as resp:
            resp.read()
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        raise RuntimeError(
            "Graph PATCH keyCredentials (purge by displayName) failed: %s" % e
        ) from e


def purge_entra_idp_test_client_certs(
    tenant_id,
    client_id,
    client_secret,
    app_object_id,
    *pem_certificates,
    display_name_prefix=ENTRA_TEST_CERT_DISPLAY_PREFIX,
    token=None,
):
    """
    Best-effort removal of test client certs from an Entra app registration.

    Deletes by DER (``pem_certificates``) and by ``displayName`` prefix.
    """
    if not app_object_id:
        return
    if token is None:
        token = azure_acquire_graph_token(tenant_id, client_id, client_secret)
    for pem in pem_certificates:
        if not pem:
            continue
        delete_idp_client_crt_from_entra_app(token, app_object_id, pem)
    delete_entra_app_certs_by_display_name_prefix(
        token, app_object_id, display_name_prefix)


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


def keycloak_oidc_client_json(domain_name, client_id, *, auth_method, extra_attrs):
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

    Use ``none`` for browser/device-flow tests and ``request`` only while
    exercising RFC 8705 ``tls_client_auth`` at the token endpoint.
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
    keycloak_host.run_command(["systemctl", "restart", "keycloak"])
    tasks.run_repeatedly(
        keycloak_host,
        ["systemctl", "is-active", "keycloak"],
        timeout=120,
    )


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
        return uri, (user_code.strip() if user_code else None)

    @staticmethod
    def run_remote_selenium(host, script, remote_basename, timeout=30):
        path = "/tmp/%s" % remote_basename
        try:
            host.put_file_contents(path, script)
            tasks.run_repeatedly(
                host,
                ["timeout", "--signal=TERM", "120", "python3", path],
                timeout=max(timeout, 150),
            )
        finally:
            host.run_command(["rm", "-f", path])

    @staticmethod
    def kinit_idp(
        host,
        user,
        keycloak_server=None,
        *,
        azure_email=None,
        azure_password=None,
    ):
        """
        kinit for users with --user-auth-type=idp: complete OAuth2 device code
        flow in a browser. Use either keycloak_server= for Keycloak, or
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
        host.run_command(["kinit", "-n", "-c", ARMOR])
        cmd = ["kinit", "-T", ARMOR, user]

        with host.spawn_expect(cmd, default_timeout=100) as e:
            e.expect(DEVICE_AUTH_PROMPT_RE)
            prompt = e.get_last_output()
            uri, device_user_code = TestIDP.parse_device_auth_prompt(prompt)
            time.sleep(5)
            if uri:
                if keycloak_server is not None:
                    TestIDPKeycloak.add_keycloak_user_code(
                        keycloak_server, uri)
                else:
                    TestIDPAzure.add_azure_user_code(
                        host, uri, azure_email, azure_password,
                        device_user_code=device_user_code,
                    )
            e.sendline('\n')
            e.expect_exit()

        test_idp = host.run_command(["klist", "-C"])
        assert "152" in test_idp.stdout_text



class TestIDPKeycloak(TestIDP):
    """Keycloak IdP integration tests."""

    KEYCLOAK_IDP_NAME = "keycloakidp"
    KEYCLOAK_USER = "keycloakuser"
    KEYCLOAK_IDP_USER_ID = "testuser1@ipa.test"
    KEYCLOAK_JWT_IDP_NAME = "keycloakjwtidp"
    KEYCLOAK_TLS_IDP_NAME = "keycloaktlsidp"
    KEYCLOAK_JWT_USER = "keycloakjwtuser"
    KEYCLOAK_TLS_USER = "keycloaktlsuser"
    KEYCLOAK_JWT_CLIENT_ID = "ipa_oidc_jwt_client"
    KEYCLOAK_TLS_CLIENT_ID = "ipa_oidc_tls_client"
    KEYCLOAK_MTLS_TRUSTSTORE_ALIAS = "idp-client-mtls"

    def _ensure_keycloak_for_cert_tests(self):
        """Ensure Keycloak is running and ``kcadm`` is authenticated."""
        result = self.client.run_command(
            ["systemctl", "is-active", "keycloak"], raiseonerr=False)
        if result.returncode != 0:
            create_keycloak.setup_keycloakserver(self.client)
            time.sleep(60)
            create_keycloak.setup_keycloak_client(self.client)
        keycloak_ensure_kcadm_credentials(self.client)

    @staticmethod
    def add_keycloak_user_code(host, verification_uri):
        contents = keyclock_user_code_script.format(
            uri=verification_uri,
            passwd=host.config.admin_password,
        )
        TestIDP.run_remote_selenium(
            host, contents, "add_keycloak_user_code.py")

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
        self.kinit_idp(self.master, 'keycloakuser', keycloak_server=self.client)

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
        self.kinit_idp(self.master, 'keycloakuser', keycloak_server=self.client)
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
            self.kinit_idp(
                self.client, 'keycloakuser', keycloak_server=self.client)
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
        self.kinit_idp(self.replica, 'keycloakuser', keycloak_server=self.client)

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
            self.kinit_idp(self.master, user, keycloak_server=self.client)
        finally:
            tasks.kdestroy_all(self.master)
            tasks.kinit_admin(self.master)
            self.master.run_command(["rm", "-rf", backup_path])
            self.master.run_command(["ipa", "idp-del", "testidp"])

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
            self.kinit_idp(
                self.master,
                self.KEYCLOAK_JWT_USER,
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
                keycloak_delete_client(self.client, self.KEYCLOAK_JWT_CLIENT_ID)
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
        subject_dn = keycloak_pem_cert_subject_dn(pem_bytes)
        crt_on_keycloak = "/tmp/idp-client.crt"

        kc_client_added = False
        truststore_imported = False
        https_client_auth_enabled = False
        p12_on_master = False
        tls_idp_added = False
        tls_user_added = False
        try:
            pem_text = (
                pem_bytes.decode("ascii")
                if isinstance(pem_bytes, bytes) else pem_bytes
            )
            self.client.put_file_contents(crt_on_keycloak, pem_text)
            keycloak_set_https_client_auth(self.client, "request")
            https_client_auth_enabled = True
            keycloak_truststore_delete_cert(
                self.client, self.KEYCLOAK_MTLS_TRUSTSTORE_ALIAS)
            keycloak_truststore_import_cert(
                self.client, crt_on_keycloak, self.KEYCLOAK_MTLS_TRUSTSTORE_ALIAS)
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
            self.kinit_idp(
                self.master,
                self.KEYCLOAK_TLS_USER,
                keycloak_server=self.client,
            )
            test_idp = self.master.run_command(["klist", "-C"])
            assert "152" in test_idp.stdout_text
        finally:
            if kc_client_added:
                keycloak_delete_client(self.client, self.KEYCLOAK_TLS_CLIENT_ID)
            if truststore_imported:
                keycloak_truststore_delete_cert(
                    self.client, self.KEYCLOAK_MTLS_TRUSTSTORE_ALIAS)
            if https_client_auth_enabled:
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


class TestIDPCLI(IntegrationTest):
    """
    Client-side ``ipa idp-*`` validation (no external IdP required).

    Uses the IPA master's Dogtag ``ca-agent.p12`` as a stand-in PKCS#12 file.
    """

    topology = "line"

    def test_prompts_for_secret(self):
        """``idp-add`` with ``--client-cert-p12-file`` prompts for PKCS#12 password."""
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple(),
        )
        cmd = [
            "ipa", "idp-add", "MyKeycloak",
            "--provider", "keycloak",
            "--org", "myrealm",
            "--base-url", "keycloak.example.com",
            "--client-id", "ipa-client",
            "--client-auth-method", "private_key_jwt",
            "--client-cert-p12-file", "/root/ca-agent.p12",
        ]
        with self.master.spawn_expect(cmd, extra_ssh_options=['-t']) as e:
            e.expect('PKCS#12 password:')
            e.sendline(self.master.config.admin_password)
            e.expect('Added Identity Provider reference', timeout=60)
            e.expect_exit(ignore_remaining_output=True)

        journal = self.master.run_command(
            ["journalctl", "-g", "IPA.API", "--since=%s" % since])
        assert '"userpkcs12": "********"' in journal.stdout_text
        self.master.run_command(["ipa", "idp-del", "MyKeycloak"])

    def test_noninteractive_no_secret(self):
        """Non-interactive ``idp-add`` with P12 file requires ``--secret``."""
        cmd = [
            "ipa", "-n", "idp-add", "MyKeycloak",
            "--provider", "keycloak",
            "--org", "myrealm",
            "--base-url", "keycloak.example.com",
            "--client-id", "ipa-client",
            "--client-auth-method", "private_key_jwt",
            "--client-cert-p12-file", "/root/ca-agent.p12",
        ]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1
        assert "ipa: ERROR: 'secret' is required" in result.stderr_text


class TestIDPAzure(TestIDP):
    """Microsoft Entra (Azure) IdP integration tests."""

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

    @staticmethod
    def add_azure_user_code(host, verification_uri, username, password,
                            device_user_code=None):
        contents = azure_user_code_script.format(
            uri=verification_uri,
            username=username,
            password=password,
            device_user_code=device_user_code or "",
        )
        TestIDP.run_remote_selenium(
            host, contents, "add_azure_user_code.py", timeout=180)

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

    def ensure_azure_idp_and_user(self):
        """Create Microsoft IdP and linked IPA user if absent."""
        host = self.master
        idp_name = self.AZURE_IDP_NAME
        ipa_user = self.AZURE_IPA_USERNAME
        tasks.kinit_admin(host)
        idp_show = host.run_command(
            ["ipa", "idp-show", idp_name, "--all"], raiseonerr=False)
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

    def _microsoft_issuer_url(self):
        return "https://login.microsoftonline.com/%s/v2.0" % self.azure_tenant_id

    def _entra_upload_client_cert(self, pem_bytes, test_method_name=None):
        if test_method_name is None:
            test_method_name = calling_test_name()
        token = azure_acquire_graph_token(
            self.azure_tenant_id,
            self.azure_admin_client_id,
            self.azure_admin_client_secret,
        )
        app_object_id = azure_graph_application_object_id(
            token, self.azure_admin_client_id)
        cert_display_name = new_idp_client_graph_cert_display_name(
            test_method_name)
        upload_idp_client_crt_to_entra_app(
            token, app_object_id, pem_bytes, display_name=cert_display_name)
        return token, app_object_id

    def _entra_delete_uploaded_certs(
        self, app_object_id, *pem_certificates, token=None,
    ):
        """
        Remove client certificates from the Entra app registration.

        Call this first in ``finally`` blocks (before ``idp-del`` / ``user-del``).
        A fresh Graph token is acquired when *token* is not supplied.
        Also drops credentials whose ``displayName`` starts with ``test_``.
        """
        if not app_object_id:
            return
        pem_list = [p for p in pem_certificates if p]
        try:
            purge_entra_idp_test_client_certs(
                self.azure_tenant_id,
                self.azure_admin_client_id,
                self.azure_admin_client_secret,
                app_object_id,
                *pem_list,
                token=token,
            )
        except Exception as exc:
            self.master.log.warning(
                "Entra client cert cleanup failed for app %s: %s",
                app_object_id, exc,
            )

    @classmethod
    def teardown_class(cls):
        """Remove leftover ``test_*`` certs from the Entra app registration."""
        master = getattr(cls, "master", None)
        if master is None:
            return
        cfg = master.config
        missing = _azure_multihost_config_missing_attrs(cfg)
        if missing:
            return
        try:
            purge_entra_idp_test_client_certs(
                cfg.azure_tenant_id,
                cfg.azure_admin_client_id,
                cfg.azure_admin_client_secret,
                azure_graph_application_object_id(
                    azure_acquire_graph_token(
                        cfg.azure_tenant_id,
                        cfg.azure_admin_client_id,
                        cfg.azure_admin_client_secret,
                    ),
                    cfg.azure_admin_client_id,
                ),
            )
        except Exception as exc:
            master.log.warning(
                "Entra test cert teardown_class cleanup failed: %s", exc)
        try:
            tasks.kinit_admin(master)
            for role in ("idp-read-only", "idp-secret-read"):
                master.run_command(
                    ["ipa", "role-del", role], raiseonerr=False)
            for priv in (IDP_PRIV_READ_SERVER, IDP_PRIV_READ_CLIENT_SECRET):
                master.run_command(
                    ["ipa", "privilege-del", priv], raiseonerr=False)
            for user in ("idpnoperm", "idpread", "idpsecretread"):
                master.run_command(
                    ["ipa", "user-del", user], raiseonerr=False)
        except Exception as exc:
            master.log.warning(
                "IdP permission teardown_class cleanup failed: %s", exc)

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
                    "--idp-user-id=" + self.azure_username,
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
                self.kinit_idp(
                    host,
                    ipa_user,
                    azure_email=self.azure_username,
                    azure_password=self.azure_user_password,
                )
                klist = host.run_command(["klist", "-C"])
                assert "152" in klist.stdout_text
                return
            except Exception as err:
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
                ["ipa", "idp-show", idp_name, "--all"], raiseonerr=False).returncode == 0:
            return
        self.master.run_command(
            [
                "ipa", "idp-add", idp_name,
                "--provider", "microsoft",
                "--organization", self.azure_tenant_id,
                "--client-id", self.azure_admin_client_id,
                "--secret",
            ],
            stdin_text=self.azure_admin_client_secret + "\n",
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
        token, app_object_id = self._entra_upload_client_cert(pem_bytes)
        p12_src = os.path.join(workdir, "idp-client.p12")
        self.master.run_command(["cp", p12_src, p12_ipa_path])
        self.master.run_command(["chmod", "600", p12_ipa_path])
        tasks.kinit_admin(self.master)
        self.master.run_command(
            [
                "ipa", "idp-add", idp_name,
                "--provider=microsoft",
                "--organization=%s" % self.azure_tenant_id,
                "--issuer=%s" % self._microsoft_issuer_url(),
                "--client-id=%s" % self.azure_admin_client_id,
                "--client-auth-method=%s" % auth_method,
                "--client-cert-p12-file=%s" % p12_ipa_path,
            ],
            stdin_text=p12_passphrase_stdin(p12_password),
        )
        self._ensure_idp_user(idp_name, ipa_user, first, last)
        return token, app_object_id, pem_bytes, workdir

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
            ["ipa", "idp-show", self.AZURE_IDP_NAME, "--all"])
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
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()
        tasks.clear_sssd_cache(self.client)
        tasks.wait_for_sssd_domain_status_online(self.client)
        wait_for_ipa_user_lookup_id(self.client, self.AZURE_IPA_USERNAME)
        self.kinit_idp(
            self.client,
            self.AZURE_IPA_USERNAME,
            azure_email=self.azure_username,
            azure_password=self.azure_user_password,
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
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()

        workdir = generate_idp_client_openssl_bundle(self.master)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)

        token = None
        app_object_id = None
        uploaded = False
        p12_on_master = False
        jwt_idp_added = False
        try:
            token = azure_acquire_graph_token(
                self.azure_tenant_id,
                self.azure_admin_client_id,
                self.azure_admin_client_secret,
            )
            app_object_id = azure_graph_application_object_id(
                token,
                self.azure_admin_client_id,
            )
            cert_display_name = new_idp_client_graph_cert_display_name(
                calling_test_name())
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes,
                display_name=cert_display_name,
            )
            uploaded = True

            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_P12_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_P12_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            issuer = (
                "https://login.microsoftonline.com/%s/v2.0"
                % self.azure_tenant_id
            )
            # ``idp_add`` requires ``--provider`` or explicit OAuth endpoints;
            # JWT/P12 options do not replace that. Use the Microsoft template for
            # device/authorize/token/userinfo URLs (same tenant as issuer).
            # Note the time to parse the journal
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=10)).timetuple()
            )
            idp_add_cmd = [
                "ipa", "idp-add", self.AZURE_JWT_IDP_NAME,
                "--provider=microsoft",
                "--organization=%s" % self.azure_tenant_id,
                "--issuer=%s" % issuer,
                "--client-id=%s" % self.azure_admin_client_id,
                "--client-auth-method=private_key_jwt",
                "--client-cert-p12-file=%s" % IDP_CLIENT_P12_IPA_PATH,
            ]
            # PKCS#12 passphrase (and confirm) if ``ipa`` prompts like ``--secret``.
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
                    "--idp-user-id=" + self.azure_username,
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
            self.kinit_idp(
                self.client,
                self.AZURE_JWT_IPA_USERNAME,
                azure_email=self.azure_username,
                azure_password=self.azure_user_password,
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            if jwt_idp_added:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "idp-del", self.AZURE_JWT_IDP_NAME],
                    raiseonerr=False,
                )
            if p12_on_master:
                self.master.run_command(
                    ["rm", "-f", IDP_CLIENT_P12_IPA_PATH],
                    raiseonerr=False,
                )
            self.master.run_command(
                ["rm", "-rf", workdir], raiseonerr=False)

    def test_azure_tls_client_auth(self):
        """
        Test Azure IdP using mTLS client authentication (RFC 8705).

        Same Entra app-registration certificate upload as ``test_azure_cert``,
        but ``ipa idp-add`` uses ``--client-auth-method=tls_client_auth`` so
        token exchange presents the client certificate at the TLS layer.
        """
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()

        workdir = generate_idp_client_openssl_bundle(self.master)
        crt_path = os.path.join(workdir, "idp-client.crt")
        pem_bytes = self.master.get_file_contents(crt_path)

        token = None
        app_object_id = None
        uploaded = False
        p12_on_master = False
        tls_idp_added = False
        try:
            token = azure_acquire_graph_token(
                self.azure_tenant_id,
                self.azure_admin_client_id,
                self.azure_admin_client_secret,
            )
            app_object_id = azure_graph_application_object_id(
                token,
                self.azure_admin_client_id,
            )
            cert_display_name = new_idp_client_graph_cert_display_name(
                calling_test_name())
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes,
                display_name=cert_display_name,
            )
            uploaded = True

            p12_src = os.path.join(workdir, "idp-client.p12")
            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_TLS_P12_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_TLS_P12_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            issuer = (
                "https://login.microsoftonline.com/%s/v2.0"
                % self.azure_tenant_id
            )
            since = time.strftime(
                '%Y-%m-%d %H:%M:%S',
                (datetime.now() - timedelta(seconds=10)).timetuple()
            )
            idp_add_cmd = [
                "ipa", "idp-add", self.AZURE_TLS_IDP_NAME,
                "--provider=microsoft",
                "--organization=%s" % self.azure_tenant_id,
                "--issuer=%s" % issuer,
                "--client-id=%s" % self.azure_admin_client_id,
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
                    "--idp-user-id=" + self.azure_username,
                    "--idp=" + self.AZURE_TLS_IDP_NAME,
                ],
            )
            tasks.clear_sssd_cache(self.client)
            tasks.wait_for_sssd_domain_status_online(self.client)
            wait_for_ipa_user_lookup_id(
                self.client, self.AZURE_TLS_IPA_USERNAME)
            self.kinit_idp(
                self.client,
                self.AZURE_TLS_IPA_USERNAME,
                azure_email=self.azure_username,
                azure_password=self.azure_user_password,
            )
            test_idp = self.client.run_command(["klist", "-C"])
            assert "152" in test_idp.stdout_text
        finally:
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            if tls_idp_added:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "idp-del", self.AZURE_TLS_IDP_NAME],
                    raiseonerr=False,
                )
            if p12_on_master:
                self.master.run_command(
                    ["rm", "-f", IDP_CLIENT_TLS_P12_IPA_PATH],
                    raiseonerr=False,
                )
            self.master.run_command(
                ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_add_pkcs12_empty_passphrase_succeeds(self):
        """
        ``ipa idp-add`` accepts a PKCS#12 bundle with an empty MAC password.

        Generates client cert material with ``p12_password=""``, uploads the
        certificate to the Entra app registration, imports the bundle via
        ``--client-cert-p12-file`` against Microsoft OIDC, and confirms the IdP
        is created when only newlines are supplied at the PKCS#12 passphrase
        prompts.  Completes device-flow kinit end-to-end.
        """
        self.require_azure_multihost_config()
        self.ensure_azure_idp_and_user()

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
        uploaded = False
        p12_on_master = False
        nopass_idp_added = False
        try:
            token = azure_acquire_graph_token(
                self.azure_tenant_id,
                self.azure_admin_client_id,
                self.azure_admin_client_secret,
            )
            app_object_id = azure_graph_application_object_id(
                token,
                self.azure_admin_client_id,
            )
            cert_display_name = new_idp_client_graph_cert_display_name(
                calling_test_name())
            upload_idp_client_crt_to_entra_app(
                token,
                app_object_id,
                pem_bytes,
                display_name=cert_display_name,
            )
            uploaded = True

            self.master.run_command(
                ["cp", p12_src, IDP_CLIENT_P12_NOPASS_IPA_PATH])
            self.master.run_command(
                ["chmod", "600", IDP_CLIENT_P12_NOPASS_IPA_PATH])
            p12_on_master = True

            tasks.kinit_admin(self.master)
            issuer = (
                "https://login.microsoftonline.com/%s/v2.0"
                % self.azure_tenant_id
            )
            self.master.run_command(
                [
                    "ipa", "idp-add", self.AZURE_NOPASS_IDP_NAME,
                    "--provider=microsoft",
                    "--organization=%s" % self.azure_tenant_id,
                    "--issuer=%s" % issuer,
                    "--client-id=%s" % self.azure_admin_client_id,
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            if nopass_idp_added:
                tasks.kinit_admin(self.master)
                self.master.run_command(
                    ["ipa", "idp-del", self.AZURE_NOPASS_IDP_NAME],
                    raiseonerr=False,
                )
            if p12_on_master:
                self.master.run_command(
                    ["rm", "-f", IDP_CLIENT_P12_NOPASS_IPA_PATH],
                    raiseonerr=False,
                )
            self.master.run_command(
                ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_add_defaults_to_client_secret(self):
        """TC-A03: ``idp-add`` without ``--client-auth-method`` uses client secret."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-a03"
        try:
            self._add_azure_secret_idp(idp_name)
            show = self.master.run_command(["ipa", "idp-show", idp_name, "--all"])
            assert "secret:" in show.stdout_text.lower()
            assert "private_key_jwt" not in show.stdout_text.lower()
            assert "tls_client_auth" not in show.stdout_text.lower()
            self._assert_idp_ldap_client_auth_absent(idp_name)
            self._ensure_idp_user(idp_name, "testazurea03", "azure", "A03")
            self._azure_device_kinit("testazurea03")
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", "testazurea03"], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)

    def test_export_public_certificate(self):
        """
        TC-A05: ``ipa idp-show <name> --out=<file>`` exports the public cert.

        Writes PEM from the ``userCertificate`` attribute only (no private key),
        as in https://github.com/freeipa/freeipa/pull/8308. Users with
        ``System: Read External IdP server`` may export; users without IdP
        read permission cannot.
        """
        self.require_azure_multihost_config()
        idp_name = "azure-tc-a05"
        out_admin = "/tmp/idp-tc-a05-export.crt"
        out_read = "/tmp/idp-tc-a05-export-read.crt"
        out_noperm = "/tmp/idp-tc-a05-export-noperm.crt"
        token = app_object_id = pem_bytes = workdir = None
        perm_setup = False
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name,
                "testazurea05",
                "/tmp/idp-tc-a05.p12",
                first="azure",
                last="A05",
            )
            orig_cert = os.path.join(workdir, "idp-client.crt")
            if not idp_show_out_works(self.master, idp_name, out_admin):
                probe = self.master.run_command(
                    ["ipa", "idp-show", idp_name, "--out=%s" % out_admin],
                    raiseonerr=False,
                )
                pytest.xfail(
                    "ipa idp-show --out is not functional on this build: %s"
                    % probe.stderr_text.strip())
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
            assert idp_access_denied(denied.stderr_text)
        finally:
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            for path in (out_admin, out_read, out_noperm):
                self.master.run_command(["rm", "-f", path], raiseonerr=False)
            tasks.kinit_admin(self.master)
            if perm_setup:
                self._teardown_idp_permission_users("testazurea05")
            else:
                self.master.run_command(
                    ["ipa", "user-del", "testazurea05"], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-tc-a05.p12"], raiseonerr=False)

    def test_migrate_secret_to_private_key_jwt(self):
        """
        TC-C01 / Story S3: migrate client_secret IdP to ``private_key_jwt``.

        ``ipaIdpClientAuth`` and cert attributes appear; secret stores P12
        passphrase; device-flow kinit still works.
        """
        self.require_azure_multihost_config()
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
            token, app_object_id = self._entra_upload_client_cert(pem_bytes)
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
            show = self.master.run_command(["ipa", "idp-show", idp_name, "--all"])
            assert "private_key_jwt" in show.stdout_text.lower()
            self._assert_idp_ldap_client_auth_present(idp_name)
            self._azure_device_kinit(ipa_user, retries=10)
        finally:
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-migrate-tc-c01.p12"], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_migrate_cert_to_client_secret(self):
        """TC-C02: migrate certificate IdP back to ``client_secret``."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-c02"
        ipa_user = "testazurec02"
        new_secret = "NewSecretForC02!"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
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
            show = self.master.run_command(["ipa", "idp-show", idp_name, "--all"])
            show_lower = show.stdout_text.lower()
            assert "secret:" in show_lower
            assert "private_key_jwt" not in show_lower
            self._assert_idp_ldap_client_auth_absent(idp_name)
            self._azure_device_kinit(ipa_user)
        finally:
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-tc-c02.p12"], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_certificate_rotation(self):
        """Story S5: ``idp-mod`` replaces PKCS#12; auth uses the new key."""
        self.require_azure_multihost_config()
        idp_name = self.AZURE_ROTATE_IDP_NAME
        ipa_user = self.AZURE_ROTATE_IPA_USERNAME
        p12_path = "/tmp/idp-rotate-story-s5.p12"
        token = app_object_id = pem_bytes1 = pem_bytes2 = None
        workdir1 = workdir2 = None
        try:
            workdir1 = generate_idp_client_openssl_bundle(self.master)
            pem_bytes1 = self.master.get_file_contents(
                os.path.join(workdir1, "idp-client.crt"))
            token, app_object_id = self._entra_upload_client_cert(
                pem_bytes1, calling_test_name("-v1"))
            p12_src = os.path.join(workdir1, "idp-client.p12")
            self.master.run_command(["cp", p12_src, p12_path])
            self.master.run_command(["chmod", "600", p12_path])
            tasks.kinit_admin(self.master)
            self.master.run_command(
                [
                    "ipa", "idp-add", idp_name,
                    "--provider=microsoft",
                    "--organization=%s" % self.azure_tenant_id,
                    "--issuer=%s" % self._microsoft_issuer_url(),
                    "--client-id=%s" % self.azure_admin_client_id,
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes1, pem_bytes2, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            for wd in (workdir1, workdir2):
                if wd:
                    self.master.run_command(
                        ["rm", "-rf", wd], raiseonerr=False)

    def test_idp_cert_replication(self):
        """TC-E01 / Story S6: cert IdP data replicates; kinit succeeds from client."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-e01"
        ipa_user = "testazuree01"
        p12_path = "/tmp/idp-tc-e01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="E01",
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)


    def _ensure_idp_test_privilege(self, privilege_name, permission_name):
        """
        Create a test privilege that includes a PR #8308 managed *permission*.

        ``ipa role-add-privilege`` expects privilege names, not permission names.
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
            # Refresh admin credentials: user creation above can expire the ticket.
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "role-del", role], raiseonerr=False)
            add_role = self.master.run_command(
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
        User with built-in ``External IdP server Administrators`` only (TC-PERM).

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

    def _stop_ipa_otpd(self):
        """Stop and mask ``ipa-otpd``; return True if no ``ipa-otpd`` process."""
        for cmd in (
            ["systemctl", "stop", "ipa-otpd.socket"],
            ["systemctl", "stop", "ipa-otpd"],
            ["systemctl", "mask", "--now", "ipa-otpd"],
        ):
            self.master.run_command(cmd, raiseonerr=False)
        self.master.run_command(["killall", "ipa-otpd"], raiseonerr=False)
        time.sleep(2)
        return self.master.run_command(
            ["pgrep", "ipa-otpd"], raiseonerr=False).returncode != 0

    def _start_ipa_otpd(self):
        """Unmask and start ``ipa-otpd`` after tests that stop it."""
        self.master.run_command(
            ["systemctl", "unmask", "ipa-otpd"], raiseonerr=False)
        self.master.run_command(
            ["systemctl", "start", "ipa-otpd"], raiseonerr=False)
        self.master.run_command(
            ["systemctl", "reset-failed", "ipa-otpd"], raiseonerr=False)

    def test_idp_show_no_permission(self):
        """TC-D01: user without IdP permissions cannot ``idp-show``."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-d01"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, "testazured01", "/tmp/idp-tc-d01.p12",
                first="azure", last="D01",
            )
            self._setup_idp_permission_users()
            tasks.kinit_as_user(
                self.master, self.IDP_PERM_NONE_USER, "Secret123")
            result = self.master.run_command(
                ["ipa", "idp-show", idp_name], raiseonerr=False)
            assert result.returncode != 0
            assert idp_access_denied(result.stderr_text)
        finally:
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self._teardown_idp_permission_users("testazured01")
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-tc-d01.p12"], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_read_permission_hides_secrets(self):
        """
        TC-D02: ``System: Read External IdP server`` sees metadata only.

        Per PR #8308, this permission includes ``usercertificate`` and
        ``ipaidpclientauthmethod`` but not ``userpkcs12`` / ``ipaidpclientsecret``.
        ``idp-show --all`` is not used (it requests protected attributes).
        """
        self.require_azure_multihost_config()
        idp_name = "azure-tc-d02"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self._teardown_idp_permission_users("testazured02")
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-tc-d02.p12"], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_read_secret_permission(self):
        """
        TC-D03: ``System: Read External IdP server client secret`` may use
        ``idp-show --all`` (sensitive fields still masked in CLI output).
        """
        self.require_azure_multihost_config()
        idp_name = "azure-tc-d03"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self._teardown_idp_permission_users("testazured03")
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-tc-d03.p12"], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_ldap_cannot_read_userpkcs12(self):
        """TC-D04: non-privileged LDAP bind cannot read ``userPKCS12``."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-d04"
        basedn = self.master.domain.basedn
        bind_dn = "uid=%s,cn=users,cn=accounts,%s" % (
            self.IDP_PERM_NONE_USER, basedn)
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self._teardown_idp_permission_users("testazured04")
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-tc-d04.p12"], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_logging_does_not_leak_secrets(self):
        """TC-D06: debug/API logs redact PKCS#12 and private key material."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-d06"
        ipa_user = "testazured06"
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple(),
        )
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(
                ["rm", "-f", "/tmp/idp-tc-d06.p12"], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_show_help_lists_out_option(self):
        """TC-OUT-04: ``ipa idp-show --help`` documents ``--out``."""
        assert idp_show_out_available(self.master)

    def test_idp_modify_admin_can_add_cert_idp(self):
        """TC-PERM-01: External IdP admin can ``idp-add`` with PKCS#12."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-perm01"
        ipa_user = "testazureperm01"
        p12_path = "/tmp/idp-tc-perm01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            workdir = generate_idp_client_openssl_bundle(self.master)
            pem_bytes = self.master.get_file_contents(
                os.path.join(workdir, "idp-client.crt"))
            token, app_object_id = self._entra_upload_client_cert(pem_bytes)
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
                    "--organization=%s" % self.azure_tenant_id,
                    "--issuer=%s" % self._microsoft_issuer_url(),
                    "--client-id=%s" % self.azure_admin_client_id,
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self._teardown_idp_modify_admin()
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_modify_admin_can_rotate_pkcs12(self):
        """TC-PERM-02: External IdP admin can ``idp-mod`` PKCS#12 bundle."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-perm02"
        ipa_user = "testazureperm02"
        p12_path = "/tmp/idp-tc-perm02.p12"
        token = app_object_id = pem_bytes1 = pem_bytes2 = None
        workdir1 = workdir2 = None
        try:
            token, app_object_id, pem_bytes1, workdir1 = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Perm02",
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes1, pem_bytes2, token=token)
            tasks.kinit_admin(self.master)
            self._teardown_idp_modify_admin()
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            for wd in (workdir1, workdir2):
                if wd:
                    self.master.run_command(
                        ["rm", "-rf", wd], raiseonerr=False)

    def test_idp_mod_wrong_secret_only_fails(self):
        """TC-SEC-01: ``idp-mod --secret`` alone must not break cert auth silently."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-sec01"
        ipa_user = "testazuresec01"
        p12_path = "/tmp/idp-tc-sec01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Sec01",
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_mod_secret_only_without_p12_rejected(self):
        """TC-SEC-02: changing passphrase without P12 should fail."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-sec02"
        ipa_user = "testazuresec02"
        p12_path = "/tmp/idp-tc-sec02.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Sec02",
            )
            tasks.kinit_admin(self.master)
            mod = self.master.run_command(
                ["ipa", "idp-mod", idp_name, "--secret"],
                stdin_text=p12_passphrase_stdin(),
                raiseonerr=False,
            )
            assert mod.returncode != 0
        finally:
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_mod_p12_on_client_secret_idp_rejected(self):
        """TC-MOD-01: cannot upload P12 on ``client_secret`` IdP without method change."""
        self.require_azure_multihost_config()
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
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_mod_client_secret_and_p12_rejected(self):
        """TC-MOD-03: ``client_secret`` + P12 file in one ``idp-mod`` is rejected."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-mod03"
        ipa_user = "testazuremod03"
        p12_path = "/tmp/idp-tc-mod03.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Mod03",
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_migrate_cert_to_client_secret_without_secret(self):
        """TC-MIG-01: revert to ``client_secret`` without ``--secret`` (stale passphrase)."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-mig01"
        ipa_user = "testazuremig01"
        p12_path = "/tmp/idp-tc-mig01.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Mig01",
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
                % (self.azure_admin_client_secret,
                   self.azure_admin_client_secret),
            )
            self._azure_device_kinit(ipa_user)
        finally:
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_show_out_on_client_secret_idp(self):
        """TC-OUT-02: ``--out`` on ``client_secret``."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-out02"
        out_path = "/tmp/idp-tc-out02-no-cert.pem"
        try:
            self._add_azure_secret_idp(idp_name)
            tasks.kinit_admin(self.master)
            self.master.run_command(["rm", "-f", out_path], raiseonerr=False)
            if not idp_show_out_available(self.master):
                pytest.skip("ipa idp-show --out not in CLI help on this build")
            result = self.master.run_command(
                ["ipa", "idp-show", idp_name, "--out=%s" % out_path],
                raiseonerr=False,
            )
            combined = result.stdout_text + result.stderr_text
            assert result.returncode == 0 and (
                    "ignoring --out" in combined.lower())
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", out_path], raiseonerr=False)

    def test_idp_cert_backup_restore(self):
        """TC-BKP-01 / TC-E04: backup and restore preserve cert-based IdP data."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-bkp"
        ipa_user = "testazurebkp"
        p12_path = "/tmp/idp-tc-bkp.p12"
        token = app_object_id = pem_bytes = workdir = None
        backup_path = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Bkp",
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if backup_path:
                self.master.run_command(
                    ["rm", "-rf", backup_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_idp_show_not_displays_cert_metadata(self):
        """
        TC-DISP-01: ``idp-show`` not displays certificate subject/issuer/dates.

        Certificate metadata comes from ``usercertificate`` and is visible to
        principals with ``System: Read External IdP server`` (see idp-client-
        authentication design); it is not shown without that permission.
        """
        self.require_azure_multihost_config()
        idp_name = "azure-tc-disp01"
        ipa_user = "testazuredisp01"
        p12_path = "/tmp/idp-tc-disp01.p12"
        token = app_object_id = pem_bytes = workdir = None
        perm_setup = False
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Disp01",
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            if perm_setup:
                self._teardown_idp_permission_users(ipa_user)
            else:
                self.master.run_command(
                    ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_switch_jwt_tls_without_reupload_p12(self):
        """TC-MOD-04: switch ``tls_client_auth`` <-> ``private_key_jwt`` without new P12."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-mod04"
        ipa_user = "testazuremod04"
        p12_path = "/tmp/idp-tc-mod04.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "user-del", ipa_user], raiseonerr=False)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)

    def test_ldap_modify_userpkcs12_denied_without_secret_perm(self):
        """TC-PERM-03: ``idpread`` cannot LDAP-modify ``userPKCS12``."""
        self.require_azure_multihost_config()
        idp_name = "azure-tc-ldap03"
        ipa_user = "testazureldap03"
        p12_path = "/tmp/idp-tc-ldap03.p12"
        token = app_object_id = pem_bytes = workdir = None
        try:
            token, app_object_id, pem_bytes, workdir = self._add_azure_cert_idp(
                idp_name, ipa_user, p12_path, first="azure", last="Ldap03",
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
            self._entra_delete_uploaded_certs(
                app_object_id, pem_bytes, token=token)
            tasks.kinit_admin(self.master)
            self._teardown_idp_permission_users(ipa_user)
            self.master.run_command(
                ["ipa", "idp-del", idp_name], raiseonerr=False)
            self.master.run_command(["rm", "-f", p12_path], raiseonerr=False)
            if workdir:
                self.master.run_command(
                    ["rm", "-rf", workdir], raiseonerr=False)
