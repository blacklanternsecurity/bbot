import omegaconf


def flatten_config(config, base="bbot"):
    """
    Flatten a JSON-like config into a list of environment variables:
        {"modules": [{"httpx": {"timeout": 5}}]} --> "BBOT_MODULES_HTTPX_TIMEOUT=5"
    """
    if type(config) == omegaconf.dictconfig.DictConfig:
        for k, v in config.items():
            new_base = f"{base}_{k}"
            if type(v) == omegaconf.dictconfig.DictConfig:
                yield from flatten_config(v, base=new_base)
            elif type(v) != omegaconf.listconfig.ListConfig:
                yield (new_base.upper(), str(v))
