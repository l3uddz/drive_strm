import os
import re

from loguru import logger

from . import path

transcode_versions = ['1080', '720', '480', '360']


def write_strms(cfg, file_id, teamdrive_id, file_paths):
    # generate strm url
    strm_url = f"{cfg.strm.access_url.rstrip('/')}/strm/{file_id}"
    if teamdrive_id is not None and len(teamdrive_id):
        strm_url += f'?teamdrive_id={teamdrive_id}'

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
                    files_to_write[version] = os.path.join(root_path, f'{new_file_path} - {version}p.strm')
            else:

                files_to_write = {'OG': os.path.join(root_path, f'{file_path}.strm')}

        # Movies
        else:

            # set versions to write
            if cfg.strm.show_transcodes:

                # set new_file_path to folder name
                new_file_path = os.path.basename(os.path.dirname(file_path))

                files_to_write = {
                    'OG': os.path.join(root_path, os.path.split(file_path)[0], f'{new_file_path} - ORIGINAL.strm')}

                for version in transcode_versions:
                    files_to_write[version] = os.path.join(root_path, os.path.split(file_path)[0],
                                                           f'{new_file_path} - {version}p.strm')
            else:

                files_to_write = {'OG': os.path.join(root_path, f'{file_path}.strm')}

        # write strms
        for strm_version, file_name in files_to_write.items():

            if path.make_dirs(os.path.dirname(file_name)):
                logger.debug(f"Writing STRM: {file_name}")

                with open(file_name, 'w') as fp:
                    tmp_url = strm_url
                    if strm_version != 'OG':
                        if '?' in strm_url:
                            tmp_url = f'{strm_url}&transcode={strm_version}'
                        else:
                            f'{strm_url}?transcode={strm_version}'
                    fp.write(tmp_url)


def remove_strms(cfg, file_paths):
    root_path = cfg.strm.root_path
    sorted_paths = path.sort_path_list(file_paths)

    for file_path in sorted_paths:
        full_path = os.path.join(root_path, file_path)
        if os.path.isdir(full_path):
            # this is a directory - so only remove the directory
            files_to_remove = {'OG': full_path}
        else:
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
                        files_to_remove[version] = os.path.join(root_path, f'{new_file_path} - {version}p.strm')

                else:

                    files_to_remove = {'OG': os.path.join(root_path, f'{file_path}.strm')}

            # Movies
            else:

                # set versions to write
                if cfg.strm.show_transcodes:

                    # set new_file_path to folder name
                    new_file_path = os.path.basename(os.path.dirname(file_path))

                    files_to_remove = {
                        'OG': os.path.join(root_path, os.path.split(file_path)[0], f'{new_file_path} - ORIGINAL.strm')}

                    for version in transcode_versions:
                        files_to_remove[version] = os.path.join(root_path, os.path.split(file_path)[0],
                                                                f'{new_file_path} - {version}p.strm')

                else:

                    files_to_remove = {'OG': os.path.join(root_path, f'{file_path}.strm')}

        for strm_version, file_name in files_to_remove.items():
            logger.debug(f"Removing STRM: {file_name}")

            # remove file/folder
            is_dir = os.path.isdir(file_name)
            path.delete(file_name)
            if not is_dir:
                dir_path = os.path.dirname(file_name)
                left_over_files = path.find_files(dir_path)
                left_over_folders = path.find_folders(dir_path)
                if not len(left_over_files) and not len(left_over_folders):
                    logger.debug(f"Removing empty .strm folder: {dir_path}")
                    path.delete(dir_path)
