import ssl
import OpenSSL
from datetime import datetime
from enum import Enum
from loguru import logger

import adal
from azure.keyvault.certificates import CertificateClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.identity import ClientSecretCredential
from azure.storage.common import TokenCredential
from msrestazure.azure_active_directory import ServicePrincipalCredentials
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.graphrbac import GraphRbacManagementClient
from msgraph.core import APIVersion, GraphClient


class CredentialType(Enum):
    Principal = "PrincipalType1"
    ClientSecret = "ClientSecret"
    Token = "Token"


class ExecuteCmd(Enum):
    get_cluster_cert_exp = "get_cluster_cert_exp"
    get_resources = "get_resources"
    get_keyvault_cert_exp = "get_keyvault_cert_exp"
    get_storage_account_key = "get_storage_account_key"
    get_aks_cre_exp = "get_aks_cre_exp"


class AzureResourceType(Enum):
    Cluster = "Cluster"
    KeyVault = "KeyVault"
    StorageAccount = "StorageAccount"

    @classmethod
    def get_resource_value(cls, res_type_str):
        rs_type_str = {cls.Cluster: "Microsoft.ContainerService/managedClusters",
                       cls.KeyVault: "Microsoft.KeyVault/vaults",
                       cls.StorageAccount: "Microsoft.Storage/storageAccounts"}
        try:
            return rs_type_str[res_type_str]
        except KeyError:
            return None


class AzureCredential:
    @classmethod
    def get_credential(cls, client_id: str, app_secret: str, tenant_id: str, cre_type: CredentialType = CredentialType.ClientSecret, resource_url: str = None):
        try:
            if cre_type is CredentialType.Principal:
                if resource_url is not None:
                    return ServicePrincipalCredentials(
                        client_id=client_id,
                        secret=app_secret,
                        tenant=tenant_id,
                        resource=resource_url
                    )
                else:
                    return ServicePrincipalCredentials(
                        client_id=client_id,
                        secret=app_secret,
                        tenant=tenant_id
                    )
            elif cre_type is CredentialType.ClientSecret:
                return ClientSecretCredential(client_id=client_id, client_secret=app_secret, tenant_id=tenant_id)
            elif cre_type is CredentialType.Token:
                resource_url: str = "https://management.core.windows.net/"
                authority_url = "https://login.microsoftonline.com/" + tenant_id
                context = adal.AuthenticationContext(authority_url)
                token = context.acquire_token_with_client_credentials(resource=resource_url, client_id=client_id, client_secret=app_secret)

                return TokenCredential(token["accessToken"])
        except Exception as e:
            logger.error(f'Exception : {__name__}.AzureCredential.get_credential\n{e}')
        return None


class AzureClient:
    @staticmethod
    def get_rm_client(credential, subscription_id: str) -> ResourceManagementClient:
        try:
            return ResourceManagementClient(credential, subscription_id)
        except Exception as e:
            logger.error(f'Exception : {__name__}.AzureClient.get_rm_client\n{e}')
        return None

    @staticmethod
    def get_cs_client(credential, subscription_id: str) -> ContainerServiceClient:
        try:
            return ContainerServiceClient(credential, subscription_id)
        except Exception as e:
            logger.error(f'Exception : {__name__}.AzureClient.get_cs_client\n{e}')
        return None

    @staticmethod
    def get_rbac_client(credential, tenant_id: str) -> GraphRbacManagementClient:
        try:
            return GraphRbacManagementClient(credentials=credential, tenant_id=tenant_id)
        except Exception as e:
            logger.error(f'Exception : {__name__}.AzureClient.get_rbac_client\n{e}')
        return None

    @staticmethod
    def get_auth_client(credential, subscription_id: str) -> AuthorizationManagementClient:
        try:
            return AuthorizationManagementClient(credential, subscription_id)
        except Exception as e:
            logger.error(f'Exception : {__name__}.AzureClient.get_auth_client\n{e}')
        return None

    @staticmethod
    def get_kvm_client(credential, subscription_id: str) -> KeyVaultManagementClient:
        try:
            return KeyVaultManagementClient(credential=credential, subscription_id=subscription_id)
        except Exception as e:
            logger.error(f'Exception : {__name__}.AzureClient.get_kvm_client\n\t{e}')
        return None

    @staticmethod
    def get_sm_client(credential, subscription_id: str) -> StorageManagementClient:
        try:
            return StorageManagementClient(credential, subscription_id)
        except Exception as e:
            logger.error(f'Exception : {__name__}.AzureClient.get_sm_client\n\t{e}')
        return None


class CertUtil:
    @staticmethod
    def get_ssl_cert_exp_date(url: str, certficate: str = None, type: str = "PEM") -> datetime:
        try:
            if certficate is not None:
                cert = certficate
            else:
                cert = ssl.get_server_certificate((url, 443))
            if cert is not None:
                enc_type = OpenSSL.crypto.FILETYPE_PEM if type == "PEM" else OpenSSL.crypto.FILETYPE_ASN1
                x509 = OpenSSL.crypto.load_certificate(enc_type, cert)
                if x509 is not None:
                    return datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
        except Exception as e:
            logger.info(f'Exception: {__name__}.CertUtil.get_ssl_cert_exp_date\n\t{e}')
        return None

    @staticmethod
    def get_remained_days(after: datetime) -> int:
        return (after - datetime.now()).days


class ClientBase:
    _credential = None
    _client = None

    def __init__(self, client_id: str, tenant_id: str, app_secret: str, subscription_id: str):
        self._client_id = client_id
        self._tenant_id = tenant_id
        self._app_secret = app_secret
        self._subscription_id = subscription_id
        self._credential = None
        self._client = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._client is not None:
            if self._client.__class__.__name__ not in ["GraphRbacManagementClient", "GraphClient"]:
                self._client.close()
            self._client = None


class StorageManagerClient(ClientBase):
    def __enter__(self) -> StorageManagementClient:
        self._credential = AzureCredential.get_credential(cre_type=CredentialType.Token, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret)
        if self._credential is not None:
            self._client = AzureClient.get_sm_client(credential=self._credential, subscription_id=self._subscription_id)
            return self._client
        else:
            return None


class ResourceManagerClient(ClientBase):
    def __enter__(self) -> ResourceManagementClient:
        self._credential = AzureCredential.get_credential(cre_type=CredentialType.ClientSecret, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret)
        if self._credential is not None:
            self._client = AzureClient.get_rm_client(self._credential, subscription_id=self._subscription_id)
            return self._client
        else:
            return None


class KeyVaultManagerClient(ClientBase):
    def __enter__(self) -> KeyVaultManagementClient:
        self._credential = AzureCredential.get_credential(cre_type=CredentialType.ClientSecret, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret)
        if self._credential is not None:
            self._client = AzureClient.get_kvm_client(credential=self._credential, subscription_id=self._subscription_id)
            return self._client
        return None


class CertClient(ClientBase):
    def __init__(self, client_id: str, tenant_id: str, app_secret: str, vault_name: str):
        self._vault_name = vault_name
        super().__init__(client_id=client_id, tenant_id=tenant_id, app_secret=app_secret, subscription_id="")

    def __enter__(self) -> CertificateClient:
        url = f"https://{self._vault_name}.vault.azure.net"
        self._credential = AzureCredential.get_credential(cre_type=CredentialType.ClientSecret, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret)
        if self._credential is not None:
            self._client = CertificateClient(vault_url=url, credential=self._credential)
            return self._client
        return None


class AzureContainerClient(ClientBase):
    def __enter__(self) -> ContainerServiceClient:
        self._credential = AzureCredential.get_credential(cre_type=CredentialType.ClientSecret, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret)
        if self._credential is not None:
            self._client: ContainerServiceClient = AzureClient.get_cs_client(self._credential, subscription_id=self._subscription_id)
            return self._client
        else:
            return None


class AuthorityClient(ClientBase):
    def __enter__(self) -> AuthorizationManagementClient:
        self._credential = TokenCredential()
        # self._credential = AzureCredential.(cre_type=CredentialType.Principal, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret)

        if self._credential is not None:
            self._client: AuthorizationManagementClient = AzureClient.get_auth_client(self._credential, subscription_id=self._subscription_id)
            return self._client
        else:
            print('credential is none')
            return None


class AzureGraphRBACClient(ClientBase):
    def __enter__(self) -> GraphRbacManagementClient:
        resource_url = "https://graph.windows.net"
        self._credential = AzureCredential.get_credential(cre_type=CredentialType.ClientSecret, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret, resource_url=resource_url)
        if self._credential is not None:
            self._client: GraphRbacManagementClient = AzureClient.get_rbac_client(self._credential, tenant_id=self._tenant_id)
            return self._client
        else:
            return None


class AzureCliGraphClient(ClientBase):
    def __enter__(self) -> GraphClient:
        self._credential = AzureCredential.get_credential(cre_type=CredentialType.ClientSecret, client_id=self._client_id, tenant_id=self._tenant_id, app_secret=self._app_secret)
        if self._credential is not None:
            self._client = GraphClient(credential=self._credential, api_version=APIVersion.beta)
            return self._client
        else:
            return None
