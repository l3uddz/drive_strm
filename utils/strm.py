import os
import re

from . import path
from .log import logger

log = logger.get_logger(__name__)

transcode_versions = ['1080', '720', '480', '360']


def write_strms(cfg, file_id, file_paths):

    strm_url = f"{cfg.strm.access_url.rstrip('/')}/strm/{file_id}"
    root_path = cfg.strm.root_path

    for file_path in file_paths:

        # TV shows
        if 'season' in os.path.basename(os.path.dirname(file_path)).lower():

            # set versions to write
            if cfg.strm.show_transcodes:

                # set new_file_path to basename (filename without extension)
                new_file_path = os.path.splitext(file_path)[0]

                # remove quality tags
                new_file_path = re.sub(r'\.?\s?(2160|1080|720|480|360)p', "", new_file_path, flags=re.IGNORECASE)

                files_to_write = {'OG': os.path.join(root_path, f'{new_file_path} - ORIGINAL.strm')}

                for version in transcode_versions:

                    files_to_write[version] = os.path.join(root_path, f'{new_file_path} - {version}.strm')
            else:

                files_to_write = {'OG': os.path.join(root_path, f'{file_path}.strm')}

        # Movies
        else:

            # set versions to write
            if cfg.strm.show_transcodes:

                # set new_file_path to folder name
                new_file_path = os.path.basename(os.path.dirname(file_path))

                files_to_write = {'OG': os.path.join(root_path, os.path.split(file_path)[0], f'{new_file_path} - ORIGINAL.strm')}

                for version in transcode_versions:

                    files_to_write[version] = os.path.join(root_path, os.path.split(file_path)[0], f'{new_file_path} - {version}.strm')
            else:

                files_to_write = {'OG': os.path.join(root_path, f'{file_path}.strm')}

        # write strms
        for strm_version, file_name in files_to_write.items():

            if path.make_dirs(os.path.dirname(file_name)):

                log.debug(f"Writing STRM: {file_name}")

                with open(file_name, 'w') as fp:

                    fp.write(strm_url if strm_version == 'OG' else f'{strm_url}?transcode={strm_version}')


def remove_strms(cfg, file_paths):

    root_path = cfg.strm.root_path
    sorted_paths = path.sort_path_list(file_paths)

    for file_path in sorted_paths:

        # TV shows
        if 'season' in os.path.basename(os.path.dirname(file_path)).lower():

            # set versions to write
            if cfg.strm.show_transcodes:

                # set new_file_path to basename (filename without extension)
                new_file_path = os.path.splitext(file_path)[0]

                # remove quality tags
                new_file_path = re.sub(r'\.?\s?(2160|1080|720|480|360)p', "", new_file_path, flags=re.IGNORECASE)

                files_to_remove = {'OG': os.path.join(root_path, f'{new_file_path} - ORIGINAL.strm')}

                for version in transcode_versions:

                    files_to_remove[version] = os.path.join(root_path, f'{new_file_path} - {version}.strm')

            else:

                files_to_remove = {'OG': os.path.join(root_path, f'{file_path}.strm')}

        # Movies
        else:

            # set versions to write
            if cfg.strm.show_transcodes:

                # set new_file_path to folder name
                new_file_path = os.path.basename(os.path.dirname(file_path))

                files_to_remove = {'OG': os.path.join(root_path, os.path.split(file_path)[0], f'{new_file_path} - ORIGINAL.strm')}

                for version in transcode_versions:

                    files_to_remove[version] = os.path.join(root_path, os.path.split(file_path)[0], f'{new_file_path} - {version}.strm')

            else:

                files_to_remove = {'OG': os.path.join(root_path, f'{file_path}.strm')}

        for strm_version, file_name in files_to_remove.items():

            log.debug(f"Removing STRM: {file_name}")

            path.delete(file_name)
