from loguru import logger

from . import database
from .model import Settings, FileItem


############################################################
# SETTINGS METHODS
############################################################


def get_setting_value(setting_key, default_value=None):
    found_value = default_value
    try:
        database.connect(reuse_if_open=True)
        rows = Settings.select().where(Settings.key == setting_key).limit(1).dicts()
        if len(rows) > 0:
            found_value = rows[0]['value']
            logger.debug(f"Retrieved setting from database {setting_key!r}: {found_value}")
    except Exception:
        logger.exception(f"Exception retrieving value for setting {setting_key!r}: ")
    finally:
        database.close()
    return found_value


def set_setting_value(setting_key, setting_value):
    try:
        database.connect(reuse_if_open=True)
        Settings.replace({'key': setting_key, 'value': setting_value}).execute()
        return True
    except Exception:
        logger.exceptino(f"Exception saving value for setting {setting_key!r}: ")
    finally:
        database.close()
    return False


############################################################
# FILES METHODS
############################################################

def get_file_item(file_id, teamdrive_id=None):
    try:
        database.connect(reuse_if_open=True)
        rows = FileItem.select().where(FileItem.item_id == file_id, FileItem.drive_id == teamdrive_id).limit(1).dicts()
        if len(rows) > 0:
            file_item = rows[0]
            logger.trace(f"Retrieved file from database with id {file_id!r} - drive_id {teamdrive_id!r}: {file_item}")
            return file_item
    except Exception:
        logger.exception(f"Exception retrieving file_id {file_id!r}: ")
    finally:
        database.close()
    return None


def set_file_item(file_id, file_name, file_size=0, file_hash=None, file_parents='[]', file_paths='[]',
                  teamdrive_id=None):
    try:
        database.connect(reuse_if_open=True)
        FileItem.replace({'item_id': file_id, 'drive_id': teamdrive_id, 'item_hash': file_hash, 'item_name': file_name,
                          'item_size': file_size, 'item_parents': file_parents, 'item_paths': file_paths}).execute()
        return True
    except Exception:
        logger.exception(
            f"Exception setting file with id {file_id!r} - drive_id: {teamdrive_id!r} - name: {file_name}: ")
    finally:
        database.close()
    return False


def delete_file_item(file_id, teamdrive_id=None):
    try:
        database.connect(reuse_if_open=True)
        FileItem.delete().where(FileItem.item_id == file_id, FileItem.drive_id == teamdrive_id).execute()
        return True
    except Exception:
        logger.exception(
            f"Exception deleting file with id {file_id!r} - drive_id: {teamdrive_id!r}: ")
    finally:
        database.close()
    return False
