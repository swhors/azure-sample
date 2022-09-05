from datetime import datetime

import loguru
from azure.mgmt.containerservice.v2018_03_31.models import ManagedCluster
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.v2015_06_15.models import StorageAccount
from azure.mgmt.storage.v2016_01_01.models import StorageAccountListKeysResult, StorageAccountKey
from azure.mgmt.keyvault.v2016_10_01.models import Resource
from azure.keyvault.certificates import CertificateClient, CertificateProperties

from lib.azure_core import (
    AzureResourceType,
    CertUtil,
    StorageManagerClient,
    ResourceManagerClient,
    KeyVaultManagerClient,
    AzureContainerClient, CertClient,
)

is_print_date: bool = False


class ResourceListService:
    @classmethod
    def operate(cls, rs_type: AzureResourceType, client_id: str, tenant_id: str, app_secret: str, subscription_id: str):
        rs_mgmt_client: ResourceManagementClient
        with ResourceManagerClient(client_id, tenant_id, app_secret, subscription_id) as rs_mgmt_client:
            resource_list = []
            if rs_mgmt_client is not None:
                resources: [] = rs_mgmt_client.resources.list()
                for resource in resources:
                    rs_dict = resource.as_dict()
                    if rs_dict["type"] == rs_type.get_resource_value(rs_type):
                        resource_list.append(rs_dict)
            return resource_list


class SMAccountKeyService:
    @classmethod
    def operate(cls, client_id: str, tenant_id: str, app_secret: str, subscription_id: str):
        sm_client: StorageManagementClient
        with StorageManagerClient(client_id=client_id, tenant_id=tenant_id, app_secret=app_secret, subscription_id=subscription_id) as sm_client:
            key_list = []

            if sm_client is not None:
                account: StorageAccount

                for account in sm_client.storage_accounts.list():
                    id_splits = account.id.split("/")
                    resource_group_name = id_splits[4]
                    result: StorageAccountListKeysResult = sm_client.storage_accounts.list_keys(account_name=account.name, resource_group_name=resource_group_name)
                    key: StorageAccountKey
                    for key in result.keys:
                        key_list.append((resource_group_name, account.name, key.key_name, key.value))
            return key_list


class KeyValutCertExpService:
    @classmethod
    def operate(cls, client_id: str, tenant_id: str, app_secret: str, subscription_id: str):
        kvm_client: KeyVaultManagementClient
        with KeyVaultManagerClient(client_id=client_id, tenant_id=tenant_id, app_secret=app_secret, subscription_id=subscription_id) as kvm_client:
            metric_cols = []
            if kvm_client is not None:
                vault_list = kvm_client.vaults.list()
                vault: Resource
                for vault in vault_list:
                    c_client: CertificateClient
                    try:
                        with CertClient(vault_name=vault.name, client_id=client_id, tenant_id=tenant_id, app_secret=app_secret) as c_client:
                            results = c_client.list_properties_of_certificates()
                            result: CertificateProperties
                            for result in results:
                                after = result.expires_on.replace(tzinfo=None)
                                remained = CertUtil.get_remained_days(after=after)
                                if is_print_date:
                                    print(f'after={after}, {type(after)}, {remained}')
                                metric_key = f'azure_keyvault_{vault.name}_{result.name}_credential_remained'
                                metric_cols.append((metric_key, remained))
                    except Exception as e:
                        loguru.logger.error(f"Exception: {__name__}.KeyValutCertExpService.operate\n\t{e}")
            return metric_cols


class AzureClusterCertExpService:
    @classmethod
    def operate(cls, client_id: str, tenant_id: str, app_secret: str, subscription_id: str) -> []:
        cim_client: ContainerServiceClient
        with AzureContainerClient(client_id=client_id, tenant_id=tenant_id, app_secret=app_secret, subscription_id=subscription_id) as cim_client:
            metric_cols = []
            if cim_client is not None:
                cred0 = cim_client.managed_clusters.list()
                cre: ManagedCluster
                for cre in cred0:
                    if cre.fqdn is not None:
                        after: datetime = CertUtil.get_ssl_cert_exp_date(cre.fqdn)
                        if after is not None:
                            remained = CertUtil.get_remained_days(after=after)
                            metric_key = f'azure_cluster_{cre.name}_credential_remained'
                            metric_cols.append((metric_key, remained))
                    else:
                        loguru.logger.info(f"{__name__}.AzureClusterCertExpService.operate : \'cre.fqdn\' is None. {cre.name}")
                return metric_cols
            return []
