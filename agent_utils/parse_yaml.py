import yaml
import os


def load_yaml_file(fp):
    if not os.path.exists(fp):
        save_yaml_file({}, fp)

    with open(fp, 'r', encoding='utf-8') as f:
        result = yaml.load(f.read(), Loader=yaml.FullLoader)
        return result


def save_yaml_file(data, fp):
    with open(fp, 'w', encoding='utf-8') as f:
        yaml.dump(data=data, stream=f, allow_unicode=True)
