import yaml

__all__ = ["Config"]


class Config:
    def __init__(self, config_file):
        with open(config_file) as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
        self.language = config["language"]
        self.repository = config["repository"]
