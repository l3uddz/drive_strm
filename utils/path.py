import hashlib
import os
from pathlib import Path

from loguru import logger

from . import process

try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote


def get_file_extension(file):
    extensions = Path(file).suffixes
    extension = ''.join(extensions).lstrip('.')
    return extension.lower()


def get_file_hash(file):
    # get file size for hash
    file_size = 0
    try:
        file_size = os.path.getsize(file)
    except Exception:
        logger.exception(f"Exception getting file size of {file!r}: ")
    # set basic string to use for hash
    key = "{filename}-{size}".format(filename=os.path.basename(file), size=file_size)
    return hashlib.md5(key.encode('utf-8')).hexdigest()


def sort_path_list(file_list, sep=os.path.sep, high_to_low=True):
    return sorted(file_list, key=lambda x: x.count(sep), reverse=high_to_low)


def find_files(folder, extension=None, depth=None):
    file_list = []
    start_count = folder.count(os.sep)
    for path, subdirs, files in os.walk(folder, topdown=True):
        for name in files:
            if depth and path.count(os.sep) - start_count >= depth:
                del subdirs[:]
                continue
            file = os.path.join(path, name)
            if not extension:
                file_list.append(file)
            else:
                # file_extension = get_file_extension(file)
                if file.lower().endswith(extension.lower()):
                    file_list.append(file)

    return sort_path_list(file_list)


def find_folders(folder, extension=None, depth=None):
    folder_list = []
    start_count = folder.count(os.sep)
    for path, subdirs, files in os.walk(folder, topdown=True):
        for name in subdirs:
            if depth and path.count(os.sep) - start_count >= depth:
                del subdirs[:]
                continue
            file = os.path.join(path, name)
            if not extension:
                folder_list.append(file)
            elif file.lower().endswith(extension.lower()):
                folder_list.append(file)

    return sort_path_list(folder_list)


def opened_files(path):
    files = []

    try:
        process = os.popen('lsof -wFn +D %s | tail -n +2 | cut -c2-' % cmd_quote(path))
        data = process.read()
        for item in data.split('\n'):
            if not item or len(item) <= 3 or item.isdigit() or not os.path.isfile(item):
                continue
            files.append(item)

        return files

    except Exception:
        logger.exception(f"Exception retrieving open files from {path!r}: ")
    return []


def delete(path):
    if isinstance(path, list):
        for item in path:
            if os.path.exists(item):
                logger.debug(f"Removing {item!r}")
                try:
                    if not os.path.isdir(item):
                        os.remove(item)
                    else:
                        os.rmdir(item)

                    return True
                except Exception:
                    logger.exception(f"Exception deleting {item!r}: ")
            else:
                logger.debug(f"Skipping deletion of {item!r} as it does not exist")
    else:
        if os.path.exists(path):
            logger.debug(f"Removing {path!r}")
            try:
                if not os.path.isdir(path):
                    os.remove(path)
                else:
                    os.rmdir(path)

                return True
            except Exception:
                logger.exception(f"Exception deleting {path!r}: ")
        else:
            logger.debug(f"Skipping deletion of {path!r} as it does not exist")
    return False


def remove_empty_dirs(path, depth):
    if os.path.exists(path):
        logger.debug(f"Removing empty directories from {path!r} with mindepth {depth}")
        cmd = 'find %s -mindepth %d -type d -empty -delete' % (cmd_quote(path), depth)
        try:
            logger.debug(f"Using: {cmd}")
            process.execute(cmd, logs=False)
            return True
        except Exception:
            logger.exception(f"Exception while removing empty directories from {path!r}: ")
            return False
    else:
        logger.error(f"Cannot remove empty directories from {path!r} as it does not exist")
    return False


def get_size(path, excludes=None):
    try:
        cmd = "du -s --block-size=1G"
        if excludes:
            for item in excludes:
                cmd += ' --exclude=%s' % cmd_quote(item)
        cmd += ' %s | cut -f1' % cmd_quote(path)
        logger.debug(f"Using: {cmd}")
        # get size
        proc = os.popen(cmd)
        data = proc.read().strip("\n")
        proc.close()
        return int(data) if data.isdigit() else 0
    except Exception:
        logger.exception(f"Exception getting size of {path!r}: ")
    return 0


def make_dirs(path):
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except Exception:
        logger.exception(f"Exception creating folders at {path}: ")
    return False
