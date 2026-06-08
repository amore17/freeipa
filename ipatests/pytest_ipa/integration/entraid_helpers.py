# Authors:
#   FreeIPA Integration Tests
#
# Copyright (C) 2026  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Microsoft Entra ID helpers for IPA integration tests."""

from __future__ import absolute_import

import base64
import inspect
import json
import logging
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Entra ``keyCredentials`` ``displayName`` values from integration tests.
ENTRA_TEST_CERT_DISPLAY_PREFIX = "test_"

logger = logging.getLogger(__name__)


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
                if last_exc is None:
                    raise RuntimeError("no selectors for device code input")
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


def azure_user_code_script(remote_head, remote_finally):
    """Build remote Selenium script for Entra device-flow user auth."""
    return remote_head + AZUREUSER_CODE_BODY + "\n" + remote_finally


def microsoft_issuer_url(cfg):
    """Microsoft v2.0 issuer URL for the tenant in *cfg*."""
    return (
        "https://login.microsoftonline.com/%s/v2.0"
        % cfg.azure_tenant_id
    )


def azure_multihost_config_missing_attrs(config):
    """Names of multihost config attributes that are None (Azure IdP suite)."""
    pairs = (
        ("azure_username", config.azure_username),
        ("azure_user_password", config.azure_user_password),
        ("azure_tenant_id", config.azure_tenant_id),
        ("azure_admin_client_id", config.azure_admin_client_id),
        ("azure_admin_client_secret", config.azure_admin_client_secret),
    )
    return [name for name, val in pairs if val is None]


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


def _graph_application_url(app_object_id):
    return "https://graph.microsoft.com/v1.0/applications/%s" % app_object_id


def _graph_get_application(
        access_token, app_object_id,
        error_context="GET application",
):
    url = _graph_application_url(app_object_id)
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer %s" % access_token)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph %s failed: %s"
            % (error_context, e.read().decode(errors="replace"))
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            "Graph %s failed: %s" % (error_context, e.reason)
        ) from e


def _graph_patch_key_credentials(
        access_token, app_object_id, key_credentials, error_context,
):
    url = _graph_application_url(app_object_id)
    patch_body = json.dumps(
        {"keyCredentials": key_credentials},
    ).encode("utf-8")
    req = urllib.request.Request(url, data=patch_body, method="PATCH")
    req.add_header("Authorization", "Bearer %s" % access_token)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph %s failed: %s"
            % (error_context, e.read().decode(errors="replace"))
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            "Graph %s failed: %s" % (error_context, e.reason)
        ) from e


def azure_acquire_graph_token(tenant_id, client_id, client_secret):
    """Client-credentials token for Microsoft Graph."""
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
            "Azure token request failed: %s"
            % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError("Azure token request failed: %s" % e.reason) from e
    if "access_token" not in payload:
        raise RuntimeError(
            "Azure token response missing access_token: %r" % payload
        )
    return payload["access_token"]


def azure_graph_application_object_id(access_token, app_id):
    """Resolve application object id from its ``appId`` (client id)."""
    safe_app_id = app_id.replace("'", "''")
    params = urllib.parse.urlencode({"$filter": "appId eq '%s'" % safe_app_id})
    url = "https://graph.microsoft.com/v1.0/applications?%s" % params
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer %s" % access_token)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            "Graph applications lookup failed: %s"
            % e.read().decode(errors="replace")
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(
            "Graph applications lookup failed: %s" % e.reason
        ) from e
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

    app = _graph_get_application(access_token, app_object_id)
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
    _graph_patch_key_credentials(
        access_token, app_object_id, key_credentials,
        "PATCH keyCredentials")


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

    app = _graph_get_application(
        access_token, app_object_id,
        error_context="GET application (delete cert)",
    )
    key_credentials = _graph_sanitize_key_credentials(
        app.get("keyCredentials"))
    new_credentials = [e for e in key_credentials if e.get("key") != key_b64]
    if len(new_credentials) == len(key_credentials):
        return

    _graph_patch_key_credentials(
        access_token, app_object_id, new_credentials,
        "PATCH keyCredentials (delete cert)")


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
    app = _graph_get_application(
        access_token, app_object_id,
        error_context="GET application (purge by displayName)")

    key_credentials = _graph_sanitize_key_credentials(
        app.get("keyCredentials"))

    def _test_credential(entry):
        name = entry.get("displayName") or ""
        return name.startswith(display_name_prefix)

    new_credentials = [e for e in key_credentials if not _test_credential(e)]
    if len(new_credentials) == len(key_credentials):
        return

    _graph_patch_key_credentials(
        access_token, app_object_id, new_credentials,
        "PATCH keyCredentials (purge by displayName)")


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


def entra_upload_client_cert(cfg, pem_bytes, test_method_name=None):
    """
    Upload *pem_bytes* to the Entra app registration from multihost *cfg*.

    Returns ``(token, app_object_id)`` for use in test cleanup.
    """
    if test_method_name is None:
        test_method_name = calling_test_name()
    token = azure_acquire_graph_token(
        cfg.azure_tenant_id,
        cfg.azure_admin_client_id,
        cfg.azure_admin_client_secret,
    )
    app_object_id = azure_graph_application_object_id(
        token, cfg.azure_admin_client_id)
    cert_display_name = new_idp_client_graph_cert_display_name(
        test_method_name)
    upload_idp_client_crt_to_entra_app(
        token, app_object_id, pem_bytes, display_name=cert_display_name)
    return token, app_object_id


def entra_delete_uploaded_certs(
    cfg, app_object_id, *pem_certificates, token=None,
):
    """
    Remove client certificates from the Entra app registration.

    Call first in ``finally`` (before ``idp-del`` / ``user-del``).
    A fresh Graph token is acquired when *token* is not supplied.
    Also drops credentials whose ``displayName`` starts with ``test_``.
    """
    if not app_object_id:
        return
    pem_list = [p for p in pem_certificates if p]
    try:
        purge_entra_idp_test_client_certs(
            cfg.azure_tenant_id,
            cfg.azure_admin_client_id,
            cfg.azure_admin_client_secret,
            app_object_id,
            *pem_list,
            token=token,
        )
    except Exception as exc:
        logger.warning(
            "Entra client cert cleanup failed for app %s: %s",
            app_object_id, exc,
        )
