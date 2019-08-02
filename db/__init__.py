from peewee import *

############################################################
# INIT
############################################################

database = SqliteDatabase(None, thread_safe=True)


############################################################
# METHODS
############################################################

def init_db(db_path):
    global database

    database.init(db_path, pragmas={
        'journal_mode': 'wal'
    })

    return True
