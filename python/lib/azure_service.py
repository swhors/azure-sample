import base64
from datetime import datetime
from pprint import pprint

import loguru
from azure.mgmt.containerservice.v2018_03_31.models import ManagedCluster
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.containerservice.models import CredentialResults, ManagedClusterServicePrincipalProfile, ManagedClusterAccessProfile, ManagedClusterUpgradeProfile, ManagedClusterAADProfile
from azure.mgmt.resource.resources.models import GenericResource
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
    AzureContainerClient,
    CertClient, AuthorityClient, AzureGraphRBACClient, AzureCliGraphClient
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


class AzureAKSSPCredExpService:
    @classmethod
    def operate(cls, client_id: str, tenant_id: str, app_secret: str, subscription_id: str) -> []:
        cs_client: ContainerServiceClient
        clusters = {}
        metric_cols = []
        with ResourceManagerClient(client_id, tenant_id, app_secret, subscription_id) as rm_client:
            rs: GenericResource
            for rs in rm_client.resources.list():
                rs_dict = rs.as_dict()
                if rs_dict["type"] == "Microsoft.ContainerService/managedClusters":
                    ids: [] = rs.id.split('/')
                    if len(ids) == 9:
                        clusters[ids[4] + "*" + ids[8]]=[ids[4], ids[8]]
                    else:
                        print(f'{ids}')
        with AzureContainerClient(client_id, tenant_id, app_secret, subscription_id) as ac_client:
            for clus in clusters:
                cluster: ManagedCluster = ac_client.managed_clusters.get(resource_group_name=clusters[clus][0], resource_name=clusters[clus][1])
                spp: ManagedClusterServicePrincipalProfile = cluster.service_principal_profile
                clusters[clus].append(spp.client_id)
                clusters[clus].append(spp.secret)
        with AzureCliGraphClient(client_id, tenant_id, app_secret, subscription_id) as graph_client:
            queries = ['https://graph.microsoft.com/v1.0/users',
                       "https://graph.microsoft.com/v1.0/servicePrincipals"]
            for clus in clusters:
                def _filter_to_query(filter):
                    if filter is not None:
                        from urllib.parse import quote
                        return "?$filter={}".format(quote(filter, safe=''))
                    return ''
                if clusters[clus][2] != "msi":
                    query = queries[1]+ _filter_to_query(filter="servicePrincipalNames/any(c:c eq '{}')".format(clusters[clus][2]))
                    result = graph_client.get(query, params={'$select': 'passwordCredentials', '$top': '10'},)
                    result_json = result.json()
                    if 'value' in result_json:
                        password_dict_list = result.json()['value']
                        if len(password_dict_list) > 0 and 'passwordCredentials' in password_dict_list[0]:
                            cred_list = password_dict_list[0]['passwordCredentials']
                            if len(cred_list) > 0 and 'endDateTime' in cred_list[0]:
                                after: datetime = datetime.strptime(cred_list[0]['endDateTime'], "%Y-%m-%dT%H:%M:%SZ")
                                remained = CertUtil.get_remained_days(after=after)
                                metric_key = f'azure_cluster_{clusters[clus][1]}_sp_remained'
                                metric_cols.append((metric_key, remained))
        return metric_cols


class AzureClusterCertExpService2:
    @classmethod
    def operate(cls, client_id: str, tenant_id: str, app_secret: str, subscription_id: str) -> []:
        cs_client: ContainerServiceClient
        with AzureContainerClient(client_id=client_id, tenant_id=tenant_id, app_secret=app_secret, subscription_id=subscription_id) as cs_client:
            def print_credential(crs: CredentialResults, name: str) -> str:
                kube_conf: CredentialResults = crs.kubeconfigs[0]
                conf = kube_conf.value.decode('utf-8')
                ext_conf = kube_conf.additional_properties
                import yaml
                kubeconf_json = yaml.safe_load(conf)
                # cert = base64.b64decode(kubeconf_json['clusters'][0]['cluster']['certificate-authority-data'])
                cert = base64.b64decode(kubeconf_json['users'][0]['user']['client-certificate-data'])

                after: datetime = CertUtil.get_ssl_cert_exp_date(url=None, certficate=cert)
                if after is not None:
                    remained = CertUtil.get_remained_days(after=after)
                    metric_key = f'azure_cluster_{name}_credential_remained={remained}'
                    return metric_key
                    # metric_cols.append((metric_key, remained))
                return None

            clusters = cs_client.managed_clusters.list()
            cls: ManagedCluster
            metric_cols = []
            for cls in clusters:
                admin_crs: CredentialResults = cs_client.managed_clusters.list_cluster_admin_credentials(
                    resource_group_name=cls.node_resource_group, resource_name=cls.name)
                # crs: CredentialResults = cs_client.managed_clusters.list_cluster_user_credentials(
                #     resource_group_name=cls.node_resource_group, resource_name=cls.name)
                metric = print_credential(admin_crs, cls.name)
                if metric is not None:
                    metric_cols.append(metric)
            return metric_cols
