import os

from . import path
from .log import logger

log = logger.get_logger(__name__)

transcode_versions = ['1080', '720', '480', '360']


def write_strms(cfg, file_id, file_paths):
    strm_url = f"{cfg.strm.access_url.rstrip('/')}/strm/{file_id}"
    root_path = cfg.strm.root_path
    for file_path in file_paths:
        # set versions to write
        files_to_write = {'OG': os.path.join(root_path, f'{file_path}.strm')}
        if cfg.strm.show_transcodes:
            for version in transcode_versions:
                files_to_write[version] = os.path.join(root_path, f'{file_path} - {version}.strm')

        # write strms
        for strm_version, new_file_path in files_to_write.items():
            if path.make_dirs(os.path.dirname(new_file_path)):
                log.debug(f"Writing STRM: {new_file_path}")
                with open(new_file_path, 'w') as fp:
                    fp.write(strm_url if strm_version == 'OG' else f'{strm_url}?transcode={strm_version}')


def remove_strms(cfg, file_paths):
    root_path = cfg.strm.root_path
    sorted_paths = path.sort_path_list(file_paths)
    for file_path in sorted_paths:
        # set versions to remove
        files_to_remove = {'OG': os.path.join(root_path, f'{file_path}.strm')}
        if cfg.strm.show_transcodes:
            for version in transcode_versions:
                files_to_remove[version] = os.path.join(root_path, f'{file_path} - {version}.strm')

        for strm_version, file_path in files_to_remove.items():
            log.debug(f"Removing STRM: {file_path}")
            path.delete(file_path)
