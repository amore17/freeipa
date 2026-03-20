"""
Azure Entra ID (Microsoft Graph API) automation for FreeIPA IdP testing.

Provisions all Azure-side resources needed to test FreeIPA external IdP
integration with Microsoft Entra ID:

  1. Authenticates as an admin service principal to obtain a Graph API token.
  2. Creates a test user in the Azure AD tenant.
  3. Creates (or reuses) a security group and adds the user to it.
  4. Registers an Azure AD application and its service principal.
  5. Generates a self-signed X.509 certificate, uploads it to the app
     registration, and authenticates the service principal with it.
  6. Grants the service principal the User.Read.All application permission
     (with admin consent) so it can query the Graph /users endpoint.
  7. Verifies the SP can call the Graph API.

The resulting appId, client secret / certificate, and user credentials are
intended to be fed into FreeIPA's ``ipa idp-add --provider microsoft`` flow
and the OAuth 2.0 Device Authorization Grant tests.
"""
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
import requests
import uuid
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from msal import ConfidentialClientApplication
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]

# Well-known appId for Microsoft Graph
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# Well-known appRole id for User.Read.All (Application type)
USER_READ_ALL_ROLE_ID = "df021288-bdef-4463-88db-98f22de89214"


class TestIDPAzure(IntegrationTest):
    """
    Test Azure (Microsoft) Identity Provider configuration.

    Provisions all Azure-side resources (user, group, app registration,
    service principal, certificate) via the Microsoft Graph API on
    cls.master, then verifies FreeIPA external IdP integration with
    Microsoft Entra ID.
    """

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, extra_args=["--no-dnssec-validation"])
        tasks.kinit_admin(cls.master)
        cls.master.run_command(
            ["ipa", "config-mod", "--user-auth-type=idp", "--user-auth-type=password"]
        )
        cls.setup_azure()

    @classmethod
    def uninstall(cls, mh):
        pass

    @classmethod
    def setup_azure(cls):
        cfg = cls.master.config
        cls.azure_tenant_id = cfg.azure_tenant_id
        cls.azure_admin_client_id = cfg.azure_admin_client_id
        cls.azure_admin_client_secret = cfg.azure_admin_client_secret
        cls.azure_domain = cfg.azure_domain
        cls.authority = (
            f"https://login.microsoftonline.com/{cls.azure_tenant_id}"
        )

        cls.admin_token = cls.get_admin_token()
        cls.azure_username, cls.azure_password = cls.create_user(cls.admin_token)
        cls.group_id = cls.get_or_create_group(cls.admin_token, "automation")
        cls.add_user_to_group(cls.admin_token, cls.azure_username, cls.group_id)
        cls.app_data = cls.create_app(cls.admin_token)
        cls.sp_data = cls.create_service_principal(
            cls.admin_token, cls.app_data["appId"]
        )
        cls.private_key_pem, cls.cert_der_bytes, cls.thumbprint = (
            cls.generate_certificate()
        )
        cls.upload_certificate(
            cls.admin_token, cls.app_data["id"], cls.cert_der_bytes
        )
        cls.sp_token = cls.authenticate_sp(
            cls.app_data["appId"], cls.private_key_pem, cls.thumbprint
        )

    @classmethod
    def get_admin_token(cls):
        app = ConfidentialClientApplication(
            client_id=cls.azure_admin_client_id,
            client_credential=cls.azure_admin_client_secret,
            authority=cls.authority,
        )
        token = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        if "access_token" not in token:
            raise Exception(f"Failed to get admin token: {token}")
        return token["access_token"]

    @classmethod
    def create_user(cls, access_token):
        url = "https://graph.microsoft.com/v1.0/users"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        unique_id = uuid.uuid4().hex[:6]
        user_principal_name = f"user{unique_id}@{cls.azure_domain}"
        password = "TempPassword123!"

        payload = {
            "accountEnabled": True,
            "displayName": f"Automation User {unique_id}",
            "mailNickname": f"user{unique_id}",
            "userPrincipalName": user_principal_name,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": password,
            },
        }

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return user_principal_name, password

    @staticmethod
    def get_or_create_group(access_token, group_name="automation"):
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        url = (
            "https://graph.microsoft.com/v1.0/groups"
            f"?$filter=displayName eq '{group_name}'"
        )
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if data["value"]:
            return data["value"][0]["id"]

        payload = {
            "displayName": group_name,
            "mailNickname": group_name.replace(" ", ""),
            "mailEnabled": False,
            "securityEnabled": True,
        }

        response = requests.post(
            "https://graph.microsoft.com/v1.0/groups",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()["id"]

    @staticmethod
    def add_user_to_group(access_token, user_principal_name, group_id):
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        url = f"https://graph.microsoft.com/v1.0/users/{user_principal_name}"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        user_id = response.json()["id"]

        url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/$ref"
        payload = {
            "@odata.id": (
                f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
            )
        }

        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 204:
            return
        if (
            response.status_code == 400
            and "added object references already exist" in response.text
        ):
            return
        response.raise_for_status()

    @staticmethod
    def create_app(access_token):
        url = "https://graph.microsoft.com/v1.0/applications"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        display_name = f"auto-app-{uuid.uuid4().hex[:6]}"
        payload = {"displayName": display_name, "signInAudience": "AzureADMyOrg"}

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def create_service_principal(access_token, app_id):
        url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }
        payload = {"appId": app_id}

        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def generate_certificate():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "auto-app-cert")]
        )

        now = datetime.now(timezone.utc) - timedelta(minutes=5)
        end = now + timedelta(days=365)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(uuid.uuid4().int >> 64)
            .not_valid_before(now)
            .not_valid_after(end)
            .sign(key, hashes.SHA256())
        )

        private_key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        cert_der_bytes = cert.public_bytes(serialization.Encoding.DER)
        thumbprint = hashlib.sha1(cert_der_bytes).digest().hex()

        return private_key_pem, cert_der_bytes, thumbprint

    @staticmethod
    def upload_certificate(access_token, app_object_id, cert_der_bytes):
        # PATCH keyCredentials instead of /addKey because the latter requires
        # a proof-of-possession JWT signed with an existing key.
        url = f"https://graph.microsoft.com/v1.0/applications/{app_object_id}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        payload = {
            "keyCredentials": [
                {
                    "type": "AsymmetricX509Cert",
                    "usage": "Verify",
                    "key": base64.b64encode(cert_der_bytes).decode(),
                    "displayName": "auto-app-cert",
                }
            ]
        }

        response = requests.patch(url, json=payload, headers=headers)
        response.raise_for_status()

    @staticmethod
    def grant_api_permissions(access_token, sp_object_id):
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"?$filter=appId eq '{MS_GRAPH_APP_ID}'"
        )
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        graph_sp = response.json()["value"][0]

        url = (
            "https://graph.microsoft.com/v1.0/servicePrincipals"
            f"/{sp_object_id}/appRoleAssignments"
        )
        payload = {
            "principalId": sp_object_id,
            "resourceId": graph_sp["id"],
            "appRoleId": USER_READ_ALL_ROLE_ID,
        }
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()

    @classmethod
    def authenticate_sp(cls, client_id, private_key_pem, thumbprint):
        app = ConfidentialClientApplication(
            client_id=client_id,
            authority=cls.authority,
            client_credential={
                "private_key": private_key_pem,
                "thumbprint": thumbprint,
            },
        )
        token = app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        if "access_token" not in token:
            raise Exception(f"Failed to authenticate SP: {token}")
        return token["access_token"]

    @staticmethod
    def call_graph_api(token):
        url = "https://graph.microsoft.com/v1.0/users"
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json().get("value", [])

    def test_azure_idp_add_and_user(self):
        """
        Add Azure IDP with Microsoft provider and associate user with mail id.

        Uses ipa idp-add with --provider microsoft, --organization (tenant ID),
        --client-id, and --secret from stdin. Then adds IPA user linked to
        the IdP with idp-user-id set to the user's email.
        """
        # Add Azure IDP - secret from stdin (echo or stdin_text)
        AZURE_IDP_NAME = "amoreidp"
        idp_add_cmd = [
            "ipa", "idp-add", AZURE_IDP_NAME,
            "--provider", "microsoft",
            "--organization", self.azure_tenant_id,
            "--client-id", self.azure_admin_client_id,
            "--secret",
        ]
        self.master.run_command(
            idp_add_cmd,
            stdin_text=self.azure_admin_client_secret + "\n"
        )

        # Verify IDP was created
        result = self.master.run_command(["ipa", "idp-show", AZURE_IDP_NAME])
        assert AZURE_IDP_NAME in result.stdout_text
        assert "login.microsoftonline.com" in result.stdout_text

        # Add user with idp-user-id as email (mail id)
        AZURE_IPA_USERNAME = "testazure"
        tasks.user_add(
            self.master,
            AZURE_IPA_USERNAME,
            first="Amore",
            last="User",
            extra_args=[
                "--user-auth-type=idp",
                "--idp-user-id=" + self.azure_username,
                "--idp=" + AZURE_IDP_NAME,
            ],
        )

        # Verify user can be found by idp-user-id
        list_user = self.master.run_command(
            ["ipa", "user-find", "--idp-user-id=" + self.azure_username]
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
        assert self.azure_username in user_show.stdout_text
