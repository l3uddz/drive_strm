#!/usr/bin/env python3
import os
import sys

import click
from flask import Flask, Response, request, redirect, abort, stream_with_context
from gevent.pywsgi import WSGIServer
from loguru import logger

import db
from db.model import create_all_tables
from google import GoogleDriveManager, GooglePoller
from utils import path

############################################################
# INIT
############################################################

# Globals
flask_app = Flask(__name__)
cfg = None
strm = None
poller = None
manager = None


# Click
@click.group(help='drive_strm for Google Drive.')
@click.version_option('0.0.1', prog_name='drive_strm')
@click.option(
    '-v', '--verbose',
    envvar="LOG_LEVEL",
    count=True,
    default=0,
    help='Adjust the logging level')
@click.option(
    '--config-path',
    envvar='DRIVE_STRM_CONFIG_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Configuration filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.json")
)
@click.option(
    '--log-path',
    envvar='DRIVE_STRM_LOG_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Log filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "activity.log")
)
@click.option(
    '--vault-path',
    envvar='DRIVE_STRM_VAULT_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Vault filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "vault.db")
)
def click_app(verbose, config_path, log_path, vault_path):
    global cfg, manager, poller, strm

    # Load config
    from utils.config import Config
    cfg = Config(config_path=config_path).cfg

    # Load logger
    log_levels = {0: 'INFO', 1: 'DEBUG', 2: 'TRACE'}
    log_level = log_levels[verbose] if verbose in log_levels else 'TRACE'
    config_logger = {
        'handlers': [
            {'sink': sys.stdout, 'backtrace': True if verbose >= 2 else False, 'level': log_level},
            {'sink': log_path,
             'rotation': '30 days',
             'retention': '7 days',
             'enqueue': True,
             'backtrace': True if verbose >= 2 else False,
             'level': log_level}
        ]
    }
    logger.configure(**config_logger)

    # Load database
    db.init_db(vault_path)
    create_all_tables()

    # Load google drive
    manager = GoogleDriveManager(client_id=cfg.google.client_id, client_secret=cfg.google.client_secret,
                                 allowed_teamdrives=cfg.google.teamdrives, cfg=cfg)

    poller = GooglePoller(manager, cfg)

    # Load strm
    from utils import strm as strm_module
    strm = strm_module

    # Display params
    logger.debug("%s = %r" % ("CONFIG_PATH".ljust(12), config_path))
    logger.debug("%s = %r" % ("LOG_PATH".ljust(12), log_path))
    logger.debug("%s = %r" % ("VAULT_PATH".ljust(12), vault_path))
    logger.debug("")


############################################################
# CLICK FUNCTIONS
############################################################

@click_app.command(help='Authorize Google Drive account')
@click.option('--auth-code', '-c', default=None, required=False, help='Authorization Code', )
@click.option('--link-only', '-l', required=False, is_flag=True, help='Authorization Link only to stdout')
def authorize(auth_code=None, link_only=False):
    global manager

    if link_only:
        print(manager.get_auth_link())
        sys.exit(0)

    # Provide authorization link
    if not auth_code:
        logger.info("Visit the link below and paste the authorization code")
        logger.info(manager.get_auth_link())
        auth_code = input("Enter authorization code: ")

    logger.info("Exchanging authorization code for an access token...")
    token = manager.exchange_code(auth_code)
    if not token or 'access_token' not in token:
        logger.error("Failed to exchange auth code for an access token.....")
        sys.exit(1)
    else:
        logger.info(f"Exchanged authorization code for an access token:\n\n{json.dumps(token, indent=2)}\n")
    sys.exit(0)


@click_app.command(help='Validate Google Access Token')
def validate():
    global manager, cfg

    # validate auth token
    if manager.is_authorized():
        logger.info("Validated access token!")
    else:
        logger.error("Failed to validate access token...")
        sys.exit(1)
    sys.exit(0)


@click_app.command(help='Run STRM server & changes monitor')
def run():
    global manager, cfg

    # check account is authorized
    if not manager.is_authorized():
        logger.error(f"You must authorize against your Google Drive account first...")
        sys.exit(1)
    else:
        logger.info(f"Google Drive account was successfully validated as authorized!")

    # load teamdrives
    if cfg.google.teamdrive:
        if not manager.load_teamdrives():
            logger.error(f"Failed to load teamdrive drive instances...")
            sys.exit(1)

    # set callbacks
    manager.set_callbacks({
        'items_added': new_items,
        'items_removed': removed_items
    })

    # start changes monitor
    if cfg.google.poll_interval:
        poller.start()

    logger.info(f"Starting STRM Server on {cfg.server.listen_ip}:{cfg.server.listen_port}")
    server = WSGIServer((cfg.server.listen_ip, cfg.server.listen_port), flask_app, log=None)
    server.serve_forever()


############################################################
# FUNCTIONS
############################################################

def new_items(items: dict = {}):
    logger.debug(f"Added: {items}")

    for file_id, file_data in items.items():
        strm.write_strms(cfg, file_id, file_data['teamdrive'], file_data['paths'])


def removed_items(items: dict = {}):
    logger.debug(f"Removed: {items}")
    remove_paths = []

    for file_id, file_paths in items.items():
        remove_paths.extend(file_paths)

    # remove strm files
    strm.remove_strms(cfg, remove_paths)
    # remove empty folders
    if cfg.strm.remove_empty_dirs:
        logger.debug(f"Removing empty directories from: {cfg.strm.root_path!r}")
        path.remove_empty_dirs(cfg.strm.root_path, cfg.strm.empty_dir_depth)


def sorted_transcodes_string(transcode_versions: dict):
    transcodes_string = 'Unknown'
    try:
        transcodes_string = ', '.join(sorted(transcode_versions.keys(), key=int, reverse=True))
    except Exception:
        pass
    return transcodes_string


############################################################
# GOOGLE <-> EMBY
############################################################

@flask_app.route('/strm/<request_file>')
def stream_bridge(request_file):
    global manager
    request_data = {}
    teamdrive_id = None

    try:
        if request.content_type == 'application/json':
            request_data = request.get_json(silent=True)
        elif request.method == 'POST':
            request_data = request.form.to_dict()
        elif request.method == 'GET':
            request_data = request.args.to_dict()
    except Exception:
        logger.exception(f"Exception parsing request data from {request.remote_addr}: ")

    if 'teamdrive_id' in request_data:
        teamdrive_id = request_data['teamdrive_id']

    item_name = manager.get_item_name_from_cache(request_file, teamdrive_id)

    # transcoded version request?
    if 'transcode' in request_data:
        transcoded_versions = manager.get_transcodes(request_file)
        if not transcoded_versions or not len(transcoded_versions):
            logger.error(f"Failed to retrieve transcoded versions for {request_file} / {item_name}")
        else:
            logger.info(f"Found {len(transcoded_versions)} transcoded versions for {request_file} / {item_name}: "
                        f"{sorted_transcodes_string(transcoded_versions)}")
            if request_data['transcode'] not in transcoded_versions:
                logger.error(
                    f"There was no {request_data['transcode']} version available for {request_file} / {item_name}")
            else:
                logger.info(f"Proxy stream request from {request.remote_addr} for {request_file} / {item_name} / "
                            f"transcode: {request_data['transcode']}")
                try:
                    return serve_partial(transcoded_versions[request_data['transcode']], request.headers.get('Range'),
                                         teamdrive_id=teamdrive_id)
                except TimeoutError:
                    pass
                except Exception:
                    logger.exception(
                        f"Exception proxying stream request from {request.remote_addr} for "
                        f"{request_file} / {item_name} / transcode: {request_data['transcode']}: ")
                return abort(500)

    # handle stream
    if (cfg.server.direct_streams and ('proxy' not in request_data or request_data['proxy'] != '1')) or (
            'direct' in request_data and request_data['direct'] == '1'):
        # we are in direct streams mode...
        direct_stream_url = manager.get_download_link(request_file, teamdrive_id)
        logger.info(
            f"Direct stream request from {request.remote_addr} for {request_file} / {item_name}")
        return redirect(direct_stream_url)
    else:
        # we are in proxy mode, lets proxy the stream
        logger.info(f"Proxy stream request from {request.remote_addr} for {request_file} / {item_name}")
        try:
            return serve_partial(request_file, request.headers.get('Range'), teamdrive_id=teamdrive_id)
        except TimeoutError:
            pass
        except Exception:
            logger.exception(
                f"Exception proxying stream request from {request.remote_addr} for {request_file} / {item_name}: ")
    return abort(500)


@stream_with_context
def generate_data_from_response(resp, chunk=250000):
    for data_chunk in resp.stream(chunk, decode_content=False):
        yield data_chunk


def serve_partial(file_id, range_header, teamdrive_id=None):
    global cfg, manager

    # Make request to Google
    headers = {'Range': range_header}
    r = manager.get_file(file_id, teamdrive_id=teamdrive_id, headers=headers, timeout=2, stream=True)

    # Build response
    rv = Response(generate_data_from_response(r.raw, chunk=cfg.strm.chunk_size), 206, direct_passthrough=True)
    rv.headers.add('Content-Range', r.headers.get('Content-Range'))
    rv.headers.add('Content-Length', r.headers.get('Content-Length'))
    rv.headers.add('Content-Type', r.headers.get('Content-Type'))
    rv.headers.add('Accept-Ranges', 'bytes')
    return rv


############################################################
# MAIN
############################################################

if __name__ == "__main__":
    click_app()
