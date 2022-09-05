from configs import Config, AzureAppConfig
from lib.config_util import read_local_env
from lib.azure_app_config import (
    init_azure_appconfig,
    get_config,
    create_config,
    delete_config, create_app_config_from_class, delete_app_config_by_class, print_config_from_app_config
)

from azure.appconfiguration import AzureAppConfigurationClient

app_config_client = None


def test_create_get_delete(client):
    create_config(client=client, app_name="app_config", key="test_key", phase="dev", val="1234567",
                  content_type="string")
    test_key: str = get_config(client=client, app_name="app_config", key="test_key", phase="dev")
    print(f'test_key after create = {test_key}')
    delete_config(client=client, app_name="app_config", key="test_key", phase="dev")
    test_key: str = get_config(client=client, app_name="app_config", key="test_key", phase="dev")
    print(f'test_key after delete = {test_key}')


def test_config_class(client):
    config_local: Config = read_local_env(cls_name="Config", conf_file_name="app_config.py", conf_main_key="app")
    config_local.set_app_config_client(client)
    config_local._phase = "local"

    create_app_config_from_class(config=config_local, client=client, phase="dev", app_name="app_config")
    print_config_from_app_config(config_class=config_local.__class__, client=client, app_name="app_config", phase="dev")
    delete_app_config_by_class(config_class=config_local.__class__, client=client, app_name="app_config", phase="dev")


if __name__ == "__main__":
    azure_app_config: AzureAppConfig = read_local_env(cls_name="AzureAppConfig", conf_file_name="app_config.py",
                                                      conf_main_key="app_config")

    print(f'app_config.con_str={azure_app_config.con_str}')

    app_config_client: AzureAppConfigurationClient = init_azure_appconfig(con_str=azure_app_config.con_str)

    test_create_get_delete(client=app_config_client)
    test_config_class(client=app_config_client)

    app_config_client.close()
