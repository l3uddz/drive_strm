#!/usr/bin/env python3
import json
import os
import sys
import time

import click
from flask import Flask, Response, request, redirect, abort
from gevent.pywsgi import WSGIServer

############################################################
# INIT
############################################################

# Globals
flask_app = Flask(__name__)
cfg = None
log = None
drive = None
strm = None
thread = None


# Click
@click.group(help='drive_strm for Google Drive.')
@click.version_option('0.0.1', prog_name='drive_strm')
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
    '--token-path',
    envvar='DRIVE_STRM_TOKEN_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Token filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "token.json")
)
@click.option(
    '--cache-path',
    envvar='DRIVE_STRM_CACHE_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Cache filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "cache.db")
)
def click_app(config_path, log_path, token_path, cache_path):
    global cfg, log, drive, thread, strm

    # Load config
    from utils.config import Config
    cfg = Config(config_path=config_path, log_path=log_path).cfg

    # Load logger
    from utils.log import logger
    log = logger.get_logger('drive_strm')

    # Load google drive
    from utils.google import GoogleDrive
    drive = GoogleDrive(cfg, cfg.google.client_id, cfg.google.client_secret, token_path, cache_path)

    # Load threads
    from utils.threads import Thread
    thread = Thread()

    # Load strm
    from utils import strm as strm_module
    strm = strm_module


############################################################
# CLICK FUNCTIONS
############################################################

@click_app.command(help='Authorize Google Drive account')
@click.option('--auth-code', '-c', default=None, required=False, help='Authorization Code', )
@click.option('--link-only', '-l', required=False, is_flag=True, help='Authorization Link only to stdout')
def authorize(auth_code=None, link_only=False):
    if link_only:
        print(drive.get_auth_link())
        sys.exit(0)

    if not auth_code:
        log.info("Visit the link below and paste the authorization code")
        log.info(drive.get_auth_link())
        auth_code = input("Enter authorization code: ")

    log.info("Exchanging authorization code for an access token...")
    token = drive.exchange_code(auth_code)
    if not token or 'access_token' not in token:
        log.error("Failed to exchange auth code for an access token.....")
        sys.exit(1)
    else:
        log.info(f"Exchanged authorization code for an access token:\n\n{json.dumps(token, indent=2)}\n")
    sys.exit(0)


@click_app.command(help='Run STRM server & changes monitor')
def run():
    # check token exists
    if not os.path.exists(drive.token_path):
        log.error("You must authorize a Google Drive account...")
        sys.exit(1)

    # start changes monitor
    if cfg.google.poll_interval:
        thread.start(thread_monitor_changes, 'Changes_Monitor')

    log.info(f"Starting STRM Server on {cfg.server.listen_ip}:{cfg.server.listen_port}")
    server = WSGIServer((cfg.server.listen_ip, cfg.server.listen_port), flask_app, log=None)
    server.serve_forever()


############################################################
# FUNCTIONS
############################################################

def new_items(items: dict = {}):
    for file_id, file_paths in items.items():
        strm.write_strms(cfg, file_id, file_paths)


def removed_items(items: dict = {}):
    for file_id, file_paths in items.items():
        strm.remove_strms(cfg, file_paths)


def sorted_transcodes_string(transcode_versions: dict):
    transcodes_string = 'Unknown'
    try:
        transcodes_string = ', '.join(sorted(transcode_versions.keys(), key=int, reverse=True))
    except Exception:
        pass
    return transcodes_string


############################################################
# THREADS
############################################################

def thread_monitor_changes():
    log.info("Changes monitor started")

    while True:
        try:
            drive.get_changes(new_items, removed_items)
        except Exception:
            log.exception("Exception while checking for changes: ")

        # sleep before checking for more changes
        time.sleep(cfg.google.poll_interval)


############################################################
# GOOGLE <-> EMBY
############################################################

@flask_app.route('/strm/<request_file>')
def stream_bridge(request_file):
    global drive
    request_data = {}

    try:
        if request.content_type == 'application/json':
            request_data = request.get_json(silent=True)
        elif request.method == 'POST':
            request_data = request.form.to_dict()
        elif request.method == 'GET':
            request_data = request.args.to_dict()
    except Exception:
        log.exception(f"Exception parsing request data from {request.remote_addr}: ")

    item_name = drive.get_item_name_from_cache(request_file)

    # transcoded version request?
    if 'transcode' in request_data:
        transcoded_versions = drive.get_transcodes(request_file)
        if not transcoded_versions or not len(transcoded_versions):
            log.error(f"Failed to retrieve transcoded versions for {request_file} / {item_name}")
        else:
            log.info(f"Found {len(transcoded_versions)} transcoded versions for {request_file} / {item_name}: "
                     f"{sorted_transcodes_string(transcoded_versions)}")
            if request_data['transcode'] not in transcoded_versions:
                log.error(
                    f"There was no {request_data['transcode']} version available for {request_file} / {item_name}")
            else:
                log.info(f"Proxy stream request from {request.remote_addr} for {request_file} / {item_name} / "
                         f"transcode: {request_data['transcode']}")
                try:
                    return serve_partial(transcoded_versions[request_data['transcode']], request.headers.get('Range'))
                except TimeoutError:
                    pass
                except Exception:
                    log.exception(
                        f"Exception proxying stream request from {request.remote_addr} for "
                        f"{request_file} / {item_name} / transcode: {request_data['transcode']}: ")
                return abort(500)

    # handle stream
    if (cfg.server.direct_streams and ('proxy' not in request_data or request_data['proxy'] != '1')) or (
            'direct' in request_data and request_data['direct'] == '1'):
        # we are in direct streams mode...
        direct_stream_url = drive.get_stream_link(request_file)
        log.info(
            f"Direct stream request from {request.remote_addr} for {request_file} / {item_name}")
        return redirect(direct_stream_url)
    else:
        # we are in proxy mode, lets proxy the stream
        log.info(f"Proxy stream request from {request.remote_addr} for {request_file} / {item_name}")
        try:
            return serve_partial(request_file, request.headers.get('Range'))
        except TimeoutError:
            pass
        except Exception:
            log.exception(
                f"Exception proxying stream request from {request.remote_addr} for {request_file} / {item_name}: ")
    return abort(500)


def generate_data_from_response(resp, chunk=250000):
    for data_chunk in resp.stream(chunk, decode_content=False):
        yield data_chunk


def serve_partial(file_id, range_header):
    global cfg

    # Make request to Google
    headers = {'Range': range_header}
    r = drive.get_file(file_id, headers=headers, timeout=2, stream=True)

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
