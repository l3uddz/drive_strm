from peewee import *

from . import database


############################################################
# MODELS
############################################################


class BaseModel(Model):
    class Meta:
        database = database


class FileItem(BaseModel):
    item_id = CharField(max_length=64, null=False, index=True, primary_key=True)
    drive_id = CharField(max_length=64, null=True, default=None)
    item_hash = CharField(max_length=128, null=True, default=None)
    item_name = TextField(null=False)
    item_size = BigIntegerField(null=False, default=0)
    item_parents = TextField(null=False, default='[]')
    item_paths = TextField(null=False, default='[]')

    class Meta:
        table_name = "file_items"


class Settings(BaseModel):
    key = CharField(max_length=64, null=False, primary_key=True)
    value = TextField(null=True)

    class Meta:
        table_name = "settings"


############################################################
# FUNCTIONS
############################################################

def create_all_tables():
    tables = [FileItem, Settings]
    # connect database
    database.connect(reuse_if_open=True)

    # create tables
    for table in tables:
        table.create_table()

    # close database
    database.close()
