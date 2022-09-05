import yaml
import inspect


from importlib.util import spec_from_file_location, module_from_spec


def isprop(v):
    return isinstance(v, property)


def get_cls_property(cls) -> []:
    return [name for (name, value) in inspect.getmembers(cls, isprop)]


def class_from_file(file_path: str, cls_name: str) -> []:
    spec = spec_from_file_location('classname', file_path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    cls = getattr(module, cls_name)
    return cls


def read_local_env(cls_name: str, conf_file_name: str, conf_main_key: str) -> {}:
    with open('local_env.yaml') as env_file:
        envs: {} = yaml.load(env_file, Loader=yaml.FullLoader)
        if conf_main_key not in envs.keys():
            print(f'\tError : {__name__}.read_local_env don\'t have main key')
            return None
        cls = class_from_file(conf_file_name, cls_name)
        config_class = cls()
        if hasattr(config_class, "attributes_from_dict"):
            config_class.attributes_from_dict(envs[conf_main_key])
            return config_class
        print(f'\tError : {__name__}.read_local_env don\'t have \'attributes_from_dict\'')
        return None
