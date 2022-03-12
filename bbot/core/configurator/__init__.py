from . import db, files
from omegaconf import OmegaConf

config = OmegaConf.merge(
    # first look in the database
    db.get_config(),
    # then in our .yaml files
    files.get_config(),
    # finally, pull from CLI arguments
    OmegaConf.from_cli()
)
