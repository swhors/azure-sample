from configs import AzureConfig
from lib.config_util import read_local_env
from lib.azure_core import ExecuteCmd, AzureResourceType
from lib.azure_service import AzureClusterCertExpService, ResourceListService, KeyValutCertExpService, SMAccountKeyService, AzureAKSSPCredExpService


def parse_args() -> (ExecuteCmd, AzureResourceType):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--cmd', required=False, default=ExecuteCmd.get_resources, type=ExecuteCmd,
                        help='sub function name')
    parser.add_argument('--rs_type', required=False, default=AzureResourceType.Cluster, type=AzureResourceType,
                        help='resource type')

    args = parser.parse_args()

    return args.cmd, args.rs_type


execution_funcs = {ExecuteCmd.get_cluster_cert_exp: AzureClusterCertExpService,
                   ExecuteCmd.get_resources: ResourceListService,
                   ExecuteCmd.get_keyvault_cert_exp: KeyValutCertExpService,
                   ExecuteCmd.get_storage_account_key: SMAccountKeyService,
                   ExecuteCmd.get_aks_cre_exp: AzureAKSSPCredExpService}


def main():
    execute_cmd, rs_type = parse_args()
    azure_config: AzureConfig = read_local_env(cls_name='AzureConfig', conf_file_name='configs.py', conf_main_key="azure_config")
    if execute_cmd == ExecuteCmd.get_resources:
        results = execution_funcs[execute_cmd]().operate(client_id=azure_config.application_id,
                                                         tenant_id=azure_config.tenant_id,
                                                         app_secret=azure_config.secret_value,
                                                         subscription_id=azure_config.subscription_id,
                                                         rs_type=rs_type)
    else:
        results = execution_funcs[execute_cmd]().operate(client_id=azure_config.application_id, tenant_id=azure_config.tenant_id, app_secret=azure_config.secret_value, subscription_id=azure_config.subscription_id)
    for result in results:
        print(result)


if __name__ == "__main__":
    main()
