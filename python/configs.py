from lib.azure_app_config import get_config


class ConfigBase:
    def attributes_from_dict(self, attributes: {}):
        for key in attributes.keys():
            setattr(self, key, attributes[key])


class AzureAppConfig(ConfigBase):
    con_str = ""


class AzureConfig(ConfigBase):
    _subscription_id: str
    _tenant_id: str
    _application_id: str
    _secret_value: str

    @property
    def application_id(self):
        return self._application_id

    @application_id.setter
    def application_id(self, val):
        self._application_id = val

    @property
    def subscription_id(self):
        return self._subscription_id

    @subscription_id.setter
    def subscription_id(self, val):
        self._subscription_id = val

    @property
    def tenant_id(self):
        return self._tenant_id

    @tenant_id.setter
    def tenant_id(self, val):
        self._tenant_id = val

    @property
    def secret_value(self):
        return self._secret_value

    @secret_value.setter
    def secret_value(self, val):
        self._secret_value = val


class Config(ConfigBase):
    _phase = "local"
    _db_host = "localhost"
    _db_port = 3306
    _db_user = "tester"
    _db_password = "tester"
    _db_database = "test_db"

    def __init__(self, db_host: str = "localhost", db_port: int = 3306, db_user: str = "test", db_password: str = "test", db_database: str = "test", phase: str = "local"):
        self._phase = phase
        self._db_host = db_host
        self._db_port = db_port
        self._db_user = db_user
        self._db_password = db_password
        self._db_database = db_database
        self._app_config_client = None

    def set_app_config_client(self, client):
        self._app_config_client = client

    @property
    def db_host(self):
        if self._phase == "local":
            return self._db_host
        else:
            return get_config(client=self._app_config_client, app_name="app_config", key="db_host", phase=self._phase, default_val=self._db_host)

    @db_host.setter
    def db_host(self, val: str):
        self._db_host = val

    @property
    def db_port(self):
        if self._phase == "local":
            return self._db_port
        else:
            return get_config(client=self._app_config_client, app_name="app_config", key="db_port", phase=self._phase, default_val=self._db_port)

    @db_port.setter
    def db_port(self, val: int):
        self._db_port = val

    @property
    def db_database(self):
        if self._phase == "local":
            return self._db_database
        else:
            return get_config(client=self._app_config_client, app_name="app_config", key="db_database", phase=self._phase, default_val=self._db_database)

    @db_database.setter
    def db_database(self, val: str):
        self._db_database = val

    @property
    def db_user(self):
        if self._phase == "local":
            return self._db_user
        else:
            return get_config(client=self._app_config_client, app_name="app_config", key="db_user", phase=self._phase, default_val=self._db_user)

    @db_user.setter
    def db_user(self, val: str):
        self._db_user = val

    @property
    def db_password(self):
        if self._phase == "local":
            return self._db_password
        else:
            return get_config(client=self._app_config_client, app_name="app_config", key="db_password", phase=self._phase, default_val=self._db_password)

    @db_password.setter
    def db_password(self, val: str):
        self._db_password = val

    def __repr__(self):
        marked_pw = '*'*len(self.db_password)
        return f"Config<db_database={self.db_database},db_host={self.db_host},db_port={self.db_port},db_user={self.db_port},db_password={marked_pw}>"
