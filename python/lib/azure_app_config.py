import loguru
from azure.appconfiguration import ConfigurationSetting
from loguru import logger
from azure.appconfiguration import AzureAppConfigurationClient

from lib.config_util import get_cls_property

SERVICE_NAME = "azure_collector"

stored_confs = {}

appconfig_client = None


def get_app_key(app_name: str, key: str, phase: str):
    return SERVICE_NAME + "_" + key + (("_" + phase) if phase is not None else "")


def init_azure_appconfig(con_str: str) -> AzureAppConfigurationClient:
    global appconfig_client
    appconfig_client = AzureAppConfigurationClient.from_connection_string(connection_string=con_str)
    loguru.logger.info(f"{__name__}.init_azure_appconfig completed")
    return appconfig_client


def create_config(client: AzureAppConfigurationClient, app_name: str, key: str, val, content_type: str = "string", phase: str = None) -> bool:
    app_key = get_app_key(app_name=app_name, key=key, phase=phase)
    config_setting = ConfigurationSetting(
        key=app_key,
        label=app_key,
        value=val,
        content_type=content_type,
        tags={"config": app_key}
    )
    added_config_setting = client.add_configuration_setting(config_setting)
    return True if added_config_setting is not None else False


def get_app_config_value(value, content_type: str):
    if content_type is None:
        return value
    else:
        if content_type == "int":
            return int(value)
        elif content_type == "string":
            return value
        return None


def get_config(client: AzureAppConfigurationClient, app_name: str, key: str, phase: str = None, is_new: bool = False, default_val: object = None):
    app_key = get_app_key(app_name=app_name, key=key, phase=phase)

    try:
        if app_key in stored_confs.keys() and not is_new:
            if stored_confs[app_key] is not None:
                return get_app_config_value(stored_confs[app_key][0], stored_confs[app_key][1])
            else:
                return default_val

        fetched_config_setting: ConfigurationSetting = client.get_configuration_setting(key=app_key, label=app_key)

        stored_confs[app_key] = (fetched_config_setting.value, fetched_config_setting.content_type)

        return get_app_config_value(fetched_config_setting.value, fetched_config_setting.content_type)

    except Exception as e:
        logger.error(f'Exception : {__name__}.get_config\n\t{e}')
    return default_val


def delete_config(client: AzureAppConfigurationClient, app_name: str, key: str, phase: str = "dev") -> bool:
    app_key = get_app_key(app_name=app_name, key=key, phase=phase)
    deleted_config_setting = client.delete_configuration_setting(
        key=app_key, label=app_key
    )
    if app_key in stored_confs.keys():
        stored_confs[app_key] = None
    return True if deleted_config_setting is not None else False


def create_app_config_from_class(config: object, client: AzureAppConfigurationClient, app_name: str, phase: str = "dev") -> bool:
    properties = get_cls_property(config.__class__)

    for property_key in properties:
        try:
            atr = getattr(config.__class__, "_" + property_key)
            if isinstance(atr, int):
                type_str = "int"
            elif isinstance(atr, str):
                type_str = "string"
            else:
                type_str = "object"
            val = getattr(config, property_key)
            create_config(client=client, app_name=app_name, key=property_key, content_type=type_str, phase=phase, val=val)
        except Exception as e:
            if e == AttributeError:
                print(f'e={e}')
                continue
            else:
                if "has no attribute" not in str(e):
                    loguru.logger.error(f"Exception :\n\t{__name__}.create_app_config_from_class\n\t{e}")
                else:
                    continue
    return True


def delete_app_config_by_class(config_class, client: AzureAppConfigurationClient, app_name: str, phase: str = "dev"):
    properties = get_cls_property(config_class)

    for property_key in properties:
        delete_config(client=client, app_name=app_name, phase=phase, key=property_key)


def print_config_from_app_config(config_class, client: AzureAppConfigurationClient, app_name: str, phase: str = "dev"):
    properties = get_cls_property(config_class)
    for property_key in properties:
        val = get_config(client=client, app_name=app_name, phase=phase, key=property_key)
        print(f'cls={config_class}, key={property_key}, phase={phase}, val={val}')
