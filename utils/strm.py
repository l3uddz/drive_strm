import os

from . import path
from .log import logger

log = logger.get_logger(__name__)


def write_strms(cfg, file_id, file_paths):
    strm_url = f"{cfg.strm.access_url.lstrip('/')}/strm/{file_id}"
    root_path = cfg.strm.root_path
    for file_path in file_paths:
        new_file_path = os.path.join(root_path, f'{file_path}.strm')
        if path.make_dirs(os.path.dirname(new_file_path)):
            log.debug(f"Writing STRM: {new_file_path}")
            with open(new_file_path, 'w') as fp:
                fp.write(strm_url)


def remove_strms(cfg, file_paths):
    root_path = cfg.strm.root_path
    sorted_paths = path.sort_path_list(file_paths)
    for file_path in sorted_paths:
        new_file_path = os.path.join(root_path, f'{file_path}.strm')
        log.debug(f"Removing STRM: {new_file_path}")
        path.delete(new_file_path)
