#!/usr/bin/env python3
import json
import os
import sys
import time

import click
from flask import Flask, Response, stream_with_context, request, redirect, abort
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
def authorize():
    log.info("Visit the link below and paste the authorization code")
    log.info(drive.get_auth_link())
    auth_code = input("Enter authorization code: ")
    log.info("Exchanging authorization code for an access token...")
    token = drive.exchange_code(auth_code)
    if not token or 'access_token' not in token:
        log.error("Failed to exchange auth code for an access token.....")
        return
    else:
        log.info(f"Exchanged authorization code for an access token:\n\n{json.dumps(token, indent=2)}\n")
    return


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

    item_name = drive.get_item_name_from_cache(request_file)

    if cfg.server.direct_streams:
        # we are in direct streams mode...
        direct_stream_url = drive.get_stream_link(request_file)
        log.info(
            f"Direct stream request from {request.remote_addr} for {request_file} / {item_name}")
        return redirect(direct_stream_url)

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


@flask_app.after_request
def after_request(response):
    response.headers.add('Accept-Ranges', 'bytes')
    return response


def generate_data_from_response(resp, chunk=4096):
    for data_chunk in resp.iter_content(chunk_size=chunk):
        yield data_chunk


def serve_partial(file_id, range_header):
    # Make request to YouTube
    headers = {'Range': range_header}
    r = drive.get_file(file_id, headers=headers, stream=True)

    # Build response
    rv = Response(stream_with_context(generate_data_from_response(r)), 206, direct_passthrough=True)
    rv.headers.add('Content-Range', r.headers.get('Content-Range'))
    rv.headers.add('Content-Length', r.headers['Content-Length'])
    rv.headers.add('Content-Type', r.headers.get('Content-Type'))
    return rv


############################################################
# MAIN
############################################################

if __name__ == "__main__":
    click_app()
