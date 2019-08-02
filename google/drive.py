import json
import posixpath
import threading
import time
from collections import OrderedDict
from copy import copy
from threading import Lock
from urllib.parse import parse_qs

from expiringdict import ExpiringDict
from loguru import logger
from requests import Request
from requests import Response
from requests_oauthlib import OAuth2Session

from db import methods
from utils import decorators, misc


############################################################
# THREAD
############################################################

class GooglePoller(threading.Thread):
    def __init__(self, google_manager, config):
        threading.Thread.__init__(self)

        self.manager = google_manager
        self.cfg = config
        self.shutdown_event = threading.Event()

    def run(self):
        # always do a check on first start
        seconds_slept = self.cfg.google.poll_interval

        logger.info("Google Drive poller started")
        while not self.shutdown_event.is_set():
            try:
                if seconds_slept >= self.cfg.google.poll_interval:
                    # reset sleep counter
                    seconds_slept = 0
                    # poll for changes
                    self.manager.get_changes()
                else:
                    seconds_slept += 1

            except Exception:
                logger.exception(f"Exception occurred during Google Drive poller: ")

            # sleep for a second (we will handle the sleep logic ourselves for faster shutdown event handling)
            time.sleep(1)


############################################################
# GOOGLE
############################################################


class SharedOAuth2Session(OAuth2Session, metaclass=misc.Singleton):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class GoogleDriveManager:
    def __init__(self, client_id, client_secret, allowed_teamdrives=None, cfg=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.allowed_teamdrives = [] if not allowed_teamdrives else allowed_teamdrives
        self.auth_token = {}
        self.token_refresh_lock = Lock()
        self.cfg = cfg if cfg else {}
        self.drives = OrderedDict({
            'drive_root': GoogleDrive(client_id, client_secret, auth_token=self.auth_token,
                                      token_refresh_lock=self.token_refresh_lock, cfg=self.cfg)
        })
        self.transcodes_cache = ExpiringDict(max_len=5000, max_age_seconds=2 * (60 * 60))

    ############################################################
    # MANAGER METHODS
    ############################################################

    def load_teamdrives(self):
        loaded_teamdrives = 0
        if not self.allowed_teamdrives:
            return True

        teamdrives = self.drives['drive_root'].get_teamdrives()
        if not teamdrives or 'teamDrives' not in teamdrives:
            logger.error(f"Failed to retrieve teamdrive list...")
            return False

        teamdrives = teamdrives['teamDrives']
        for teamdrive in teamdrives:
            teamdrive_name = None if 'name' not in teamdrive else teamdrive['name']
            teamdrive_id = None if 'id' not in teamdrive else teamdrive['id']
            if not teamdrive_id or not teamdrive_name:
                logger.error(f"TeamDrive had insufficient data associated with it, skipping:\n{teamdrive}")
                continue
            if teamdrive_name not in self.allowed_teamdrives:
                continue

            self.drives[f"teamdrive_{teamdrive_name}"] = GoogleDrive(self.client_id, self.client_secret,
                                                                     teamdrive_id=teamdrive_id,
                                                                     auth_token=self.auth_token,
                                                                     token_refresh_lock=self.token_refresh_lock,
                                                                     cfg=self.cfg)
            logger.debug(f"Loaded TeamDrive GoogleDrive instance for: {teamdrive_name} (id = {teamdrive_id})")
            loaded_teamdrives += 1

        logger.info(f"Loaded {loaded_teamdrives} TeamDrive GoogleDrive instances")
        return True

    @decorators.timed
    def get_changes(self):
        for drive_type, drive in self.drives.items():
            if not self.cfg.google.maindrive and drive_type == 'drive_root':
                logger.trace(f"Ignoring main drive: {drive_type}")
                continue

            logger.debug(f"Retrieving changes from drive: {drive_type}")
            drive.get_changes()
        logger.debug("Finished retrieving changes from all loaded drives")

    def set_callbacks(self, callbacks):
        for drive_name, drive in self.drives.items():
            drive.set_callbacks(callbacks)

    @decorators.timed
    def build_caches(self):
        # # clear user files from database
        # if database.clear_user_files():
        #     logger.info("Cleared existing files")

        # reset page tokens for loaded drives
        for drive_type, drive in self.drives.items():
            drive.set_page_token(1)
        logger.info(f"Reset page tokens for {len(self.drives)} loaded drives")

        # # enable mem cache mode
        # database.enable_mem_cache()

        # iterate loaded drives, building the cache
        for drive_type, drive in self.drives.items():
            logger.info(f"Building cache for drive: {drive_type}")
            drive.get_changes()
            logger.info(f"Finished building cache for drive: {drive_type}")

        # # bulk insert mem cache items to database
        # database.bulk_set_from_mem_cache()
        return

    ############################################################
    # DRIVE ROOT WRAPPER METHODS
    ############################################################

    def is_authorized(self):
        try:
            return self.drives['drive_root'].validate_access_token()
        except Exception:
            logger.exception("Exception validating authentication token: ")
        return False

    def get_auth_link(self):
        try:
            return self.drives['drive_root'].get_auth_link()
        except Exception:
            logger.exception("Exception retrieving authentication link: ")
        return None

    def exchange_code(self, code: str):
        try:
            return self.drives['drive_root'].exchange_code(code)
        except Exception:
            logger.exception("Exception exchanging auth code for access token: ")
        return False

    def get_item_name_from_cache(self, item_id, teamdrive_id=None):
        try:
            return self.drives['drive_root'].get_item_name_from_cache(item_id, teamdrive_id)
        except Exception:
            pass
        return 'Unknown'

    def get_file(self, file_id, teamdrive_id=None, stream=True, headers=None, timeout=30):
        try:
            return self.drives['drive_root'].get_file(file_id, teamdrive_id=teamdrive_id, stream=stream,
                                                      headers=headers, timeout=timeout)
        except Exception:
            logger.exception(f"Exception getting file {file_id!r} - teamdrive_id {teamdrive_id}: ")
        logger.info("hmmm")
        return None

    def get_download_link(self, file_id=None, teamdrive_id=None):
        try:
            if not file_id:
                return None

            # validate / refresh current access_token
            drive_root = self.drives['drive_root']
            if not drive_root.validate_access_token():
                return None
            logger.debug("Validated access_token is current")

            # generate url
            params = {'includeTeamDriveItems': True,
                      'supportsTeamDrives': True,
                      'alt': 'media',
                      'access_token': drive_root.auth_token['access_token']}
            if teamdrive_id:
                params['teamDriveId'] = teamdrive_id

            req = Request('GET', f'{drive_root.api_url.rstrip("/")}/v2/files/{file_id}',
                          params=params).prepare()
            logger.debug(f'Direct Download URL: {req.url}')
            return req.url
        except Exception:
            logger.exception(
                f"Exception generating download link for (file_id: {file_id!r} - teamdrive_id: {teamdrive_id!r}): ")
        return None

    def get_transcodes(self, file_id):
        # do we have the transcoded versions already cached within the last 5 minutes?
        cached_transcodes = self.transcodes_cache.get(file_id, None)
        if cached_transcodes is not None and len(cached_transcodes):
            logger.debug(f"Loaded {len(cached_transcodes)} transcode streams from temporary cache for: {file_id}")
            return cached_transcodes

        # retrieve transcoded versions from google docs
        success, resp, data = self.drives['drive_root'].query(f'https://docs.google.com/get_video_info?docid={file_id}')
        if not success or (not data or 'fmt_stream_map' not in data or 'fmt_list' not in data):
            logger.error(f"Failed to find transcoded versions data for: {file_id}")
            return None

        # parse main response
        tmp = parse_qs(data)
        tmp_versions = tmp['fmt_list'][0]
        tmp_stream_map = tmp['fmt_stream_map'][0]
        drive_stream_cookie = resp.cookies.get('DRIVE_STREAM', '')

        # parse required variables
        transcode_versions = {}
        transcode_streams = {}

        # parse version list
        for version in tmp_versions.split(','):
            tmp_v = version.split('/')
            transcode_versions[tmp_v[0]] = tmp_v[1].split('x')[1]

        if not len(transcode_versions):
            logger.error(f"Failed to parse transcoded versions (fmt_list) for: {file_id}")
            return None

        # parse transcode lists
        for stream in tmp_stream_map.split(','):
            tmp_s = stream.split('|')
            transcode_streams[transcode_versions[tmp_s[0]]] = tmp_s[1]

        if not len(transcode_streams):
            logger.error(f"Failed to parse transcoded streams (fmt_stream_map) for: {file_id}")
            return None

        # cache the transcode streams for 5 minutes
        self.transcodes_cache[file_id] = transcode_streams
        logger.debug(f"Added {len(transcode_streams)} transcode streams to temporary cache for: {file_id}")
        return transcode_streams


class GoogleDrive:
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    token_url = 'https://www.googleapis.com/oauth2/v4/token'
    api_url = 'https://www.googleapis.com/drive/'
    redirect_url = 'urn:ietf:wg:oauth:2.0:oob'
    scopes = ['https://www.googleapis.com/auth/drive.readonly']

    def __init__(self, client_id, client_secret, teamdrive_id=None, auth_token=None, token_refresh_lock=None, cfg=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.drive_identifier = 'drive_root' if not teamdrive_id else f'teamdrive_{teamdrive_id}'
        self.support_team_drives = True if teamdrive_id is not None else False
        self.auth_token = {} if not auth_token else auth_token
        self.auth_token.update(self._load_auth_token())
        self.token_refresh_lock = Lock() if not token_refresh_lock else token_refresh_lock
        self.http = self._new_http_object()
        self.callbacks = {}
        self.teamdrive_id = teamdrive_id
        self.cfg = cfg if cfg else {}

    ############################################################
    # CORE CLASS METHODS
    ############################################################

    def set_page_token(self, page_token):
        try:
            methods.set_setting_value(f'page_token_{self.drive_identifier}', page_token)
        except Exception:
            pass
        return

    def set_callbacks(self, callbacks={}):
        for callback_type, callback_func in callbacks.items():
            self.callbacks[callback_type] = callback_func
        return

    def get_auth_link(self):
        auth_url, state = self.http.authorization_url(self.auth_url, access_type='offline', prompt='select_account')
        return auth_url

    def exchange_code(self, code: str):
        token = self.http.fetch_token(self.token_url, code=code, client_secret=self.client_secret)
        if 'access_token' in token:
            self._auth_token_saver(token)
            # pull in existing team drives and create cache for them
        return self.auth_token

    def query(self, path: str, method: str = 'GET', page_type='changes', fetch_all_pages: bool = False, callbacks={},
              **kwargs):
        resp: Response = None
        pages: int = 1
        resp_json = {}
        request_url = self.api_url + path.lstrip('/') if not path.startswith('http') else path

        try:

            while True:
                resp = self._do_query(request_url, method, **kwargs)
                logger.debug(f"Request URL: {resp.url}")
                logger.debug(f"Request ARG: {kwargs}")
                logger.debug(f'Response Status: {resp.status_code} {resp.reason}')

                if 'stream' in kwargs and kwargs['stream']:
                    return True, resp, None

                if 'Content-Type' in resp.headers and 'json' in resp.headers['Content-Type']:
                    if fetch_all_pages:
                        resp_json.pop('nextPageToken', None)
                    new_json = resp.json()
                    # does this page have changes
                    extended_pages = False
                    page_data = []
                    if page_type in new_json:
                        if page_type in resp_json:
                            page_data.extend(resp_json[page_type])
                        page_data.extend(new_json[page_type])
                        extended_pages = True

                    resp_json.update(new_json)
                    if extended_pages:
                        resp_json[page_type] = page_data
                else:
                    return False if resp.status_code != 200 else True, resp, resp.text

                # call page_token_callback to update cached page_token, if specified
                if page_type == 'changes' and 'page_token_callback' in callbacks:
                    if 'nextPageToken' in resp_json:
                        callbacks['page_token_callback'](resp_json['nextPageToken'])
                    elif 'newStartPageToken' in resp_json:
                        callbacks['page_token_callback'](resp_json['newStartPageToken'])

                # call data_callback, fetch_all_pages is true
                if page_type == 'changes' and fetch_all_pages and 'data_callback' in callbacks:
                    callbacks['data_callback'](resp.json())

                # handle nextPageToken
                if fetch_all_pages and 'nextPageToken' in resp_json and resp_json['nextPageToken']:
                    # there are more pages
                    pages += 1
                    logger.info(f"Fetching extra results from page {pages}")
                    if 'params' in kwargs:
                        kwargs['params'].update({'pageToken': resp_json['nextPageToken']})
                    elif 'json' in kwargs:
                        kwargs['json'].update({'pageToken': resp_json['nextPageToken']})
                    elif 'data' in kwargs:
                        kwargs['data'].update({'pageToken': resp_json['nextPageToken']})
                    continue

                break

            return True if resp_json and len(resp_json) else False, resp, resp_json if (
                    resp_json and len(resp_json)) else resp.text

        except Exception:
            logger.exception(f"Exception sending request to {request_url} with kwargs={kwargs}: ")
            return False, resp, None

    def get_file(self, file_id, teamdrive_id=None, stream=True, headers=None, timeout=30):
        req_url = '/v2/files/%s' % file_id if not file_id.startswith('http') else file_id
        params = {
            'includeTeamDriveItems': self.support_team_drives,
            'supportsTeamDrives': self.support_team_drives,
            'alt': 'media'
        }
        if teamdrive_id:
            params['teamDriveId'] = teamdrive_id

        success, resp, data = self.query(req_url, params=params, stream=stream, headers=headers, timeout=timeout)
        return resp

    ############################################################
    # DRIVE FUNCTIONS
    ############################################################

    def validate_access_token(self):
        success, resp, data = self.query('/v3/changes/startPageToken',
                                         params={'supportsTeamDrives': self.support_team_drives}, fetch_all_pages=True,
                                         page_type='auth')
        if success and resp.status_code == 200:
            if 'startPageToken' not in data:
                logger.error(f"Failed validate up to date access_token:\n\n{data}\n")
                return False
            return True
        else:
            logger.error(f"Error validating access token, status_code = {resp.status_code if resp is not None else 0}"
                         f", data =\n\n{data}\n")
        return False

    def get_changes_start_page_token(self):
        params = {
            'supportsTeamDrives': self.support_team_drives
        }

        if self.teamdrive_id is not None and self.support_team_drives:
            params['teamDriveId'] = self.teamdrive_id

        success, resp, data = self.query('/v3/changes/startPageToken',
                                         params=params, fetch_all_pages=True)
        if success and resp.status_code == 200:
            if 'startPageToken' not in data:
                logger.error(f"Failed to retrieve changes startPageToken:\n\n{data}\n")
                return None
            return data['startPageToken']
        else:
            logger.error(f"Error retrieving changes startPageToken, status_code = "
                         f"{resp.status_code if resp is not None else 0}, data =\n\n{data}\n")
        return None

    def get_teamdrives(self):
        success, resp, data = self.query('/v3/teamdrives', params={'pageSize': 100}, fetch_all_pages=True,
                                         page_type='teamDrives')
        if success and resp.status_code == 200:
            return data
        else:
            logger.error(f'Failed to retrieve teamdrives, status_code = {resp.status_code}, content =\n{resp.text}')
        return None

    def get_changes(self):
        callbacks = {'page_token_callback': self._page_token_saver,
                     'data_callback': self._process_changes}

        # get page token
        page_token = self._load_page_token()
        if not page_token:
            page_token = 1

        if not page_token:
            logger.error(f"Failed to determine a page_token to use...")
            return

        # build params
        params = {
            'pageToken': page_token, 'pageSize': 1000,
            'includeRemoved': True,
            'includeTeamDriveItems': self.support_team_drives,
            'supportsTeamDrives': self.support_team_drives,
            'fields': 'changes(file(size, md5Checksum,mimeType,modifiedTime,'
                      'name,parents,teamDriveId,trashed),'
                      'fileId,removed,teamDrive(id,name),'
                      'teamDriveId),newStartPageToken,nextPageToken'}

        if self.teamdrive_id is not None and self.support_team_drives:
            params['teamDriveId'] = self.teamdrive_id

        # make call(s)
        success, resp, data = self.query('/v3/changes', params=params, fetch_all_pages=True, callbacks=callbacks)
        return

    ############################################################
    # CACHE
    ############################################################

    def get_id_metadata(self, item_id, teamdrive_id=None):
        # return cache from metadata if available
        cached_metadata = self._get_cached_metadata(item_id, teamdrive_id)
        if cached_metadata is not None:
            return True, cached_metadata

        # does item_id match teamdrive_id?
        if teamdrive_id is not None and item_id == teamdrive_id:
            success, resp, data = self.query('v3/teamdrives/%s' % str(item_id))
            if success and resp.status_code == 200 and 'name' in data:
                # we successfully retrieved this teamdrive info, lets place a mimeType key in the result
                # so we know it needs to be cached
                data['mimeType'] = 'application/vnd.google-apps.folder'
        else:
            # retrieve file metadata
            success, resp, data = self.query('v3/files/%s' % str(item_id),
                                             params={
                                                 'supportsTeamDrives': self.support_team_drives,
                                                 'fields': 'size,id,md5Checksum,mimeType,modifiedTime,name,parents,'
                                                           'trashed,teamDriveId'})
        if success and resp.status_code == 200:
            return True, data
        else:
            logger.error(f"Error retrieving metadata for item {item_id!r}:\n\n{data}\n")
            return False, data

    def get_id_file_paths(self, item_id, teamdrive_id=None):
        file_paths = []
        added_to_cache = 0

        try:
            def get_item_paths(obj_id, path, paths, new_cache_entries, teamdrive_id=None):
                success, obj = self.get_id_metadata(obj_id, teamdrive_id)
                if not success:
                    return new_cache_entries

                teamdrive_id = teamdrive_id if 'teamDriveId' not in obj else obj['teamDriveId']

                # add item object to cache if we know its not from cache
                if 'mimeType' in obj:
                    # we know this is a new item fetched from the api, because the cache does not store this field
                    self.add_item_to_cache(obj['id'], obj['name'], [] if 'parents' not in obj else obj['parents'],
                                           obj['md5Checksum'] if 'md5Checksum' in obj else None,
                                           obj['size'] if 'size' in obj else 0, teamdrive_id)
                    new_cache_entries += 1

                if path.strip() == '':
                    path = obj['name']
                else:
                    path = posixpath.join(obj['name'], path)

                if 'parents' in obj and obj['parents']:
                    for parent in obj['parents']:
                        new_cache_entries += get_item_paths(parent, path, paths, new_cache_entries, teamdrive_id)

                if (not obj or 'parents' not in obj or not obj['parents']) and len(path):
                    paths.append(path)
                    return new_cache_entries
                return new_cache_entries

            added_to_cache += get_item_paths(item_id, '', file_paths, added_to_cache, teamdrive_id)

            if len(file_paths):
                return True, file_paths
            else:
                return False, file_paths

        except Exception:
            logger.exception(f"Exception retrieving filepaths for {item_id!r}: ")

        return False, []

    def add_item_to_cache(self, item_id, item_name, item_parents, md5_checksum, item_size=0, teamdrive_id=None):
        try:
            # update item in cache
            methods.set_file_item(file_id=item_id, file_name=item_name,
                                  file_parents=json.dumps(item_parents, separators=(',', ':')), file_hash=md5_checksum,
                                  file_size=item_size, teamdrive_id=teamdrive_id)
            # get paths
            success, item_paths = self.get_id_file_paths(item_id, teamdrive_id)
            if success and item_paths:
                methods.set_file_item(file_id=item_id, file_name=item_name,
                                      file_parents=json.dumps(item_parents, separators=(',', ':')),
                                      file_hash=md5_checksum, file_paths=json.dumps(item_paths, separators=(',', ':')),
                                      file_size=item_size, teamdrive_id=teamdrive_id)

            return True, [] if (not success or not item_paths) else item_paths
        except Exception:
            pass

        return False, []

    def remove_item_from_cache(self, item_id, teamdrive_id=None):
        try:
            if methods.delete_file_item(file_id=item_id, teamdrive_id=teamdrive_id):
                return True
        except Exception:
            pass
        return False

    def get_item_name_from_cache(self, item_id, teamdrive_id=None):
        try:
            cache_item = methods.get_file_item(file_id=item_id, teamdrive_id=teamdrive_id)
            if cache_item is not None and 'item_name' in cache_item:
                return cache_item['item_name']
        except Exception:
            pass
        return 'Unknown'

    ############################################################
    # INTERNALS
    ############################################################

    def _do_query(self, request_url: str, method: str, **kwargs):
        tries: int = 0
        max_tries: int = 2
        lock_acquirer: bool = False
        resp: Response = None
        use_timeout: int = 30

        # override default timeout
        if 'timeout' in kwargs and isinstance(kwargs['timeout'], int):
            use_timeout = kwargs['timeout']
            kwargs.pop('timeout', None)

        # remove un-needed kwargs
        kwargs.pop('fetch_all_pages', None)
        kwargs.pop('page_token_callback', None)

        # do query
        while tries < max_tries:
            if self.token_refresh_lock.locked() and not lock_acquirer:
                logger.debug("Token refresh lock is currently acquired... trying again in 500ms")
                time.sleep(0.5)
                continue

            if method == 'POST':
                resp = self.http.post(request_url, timeout=use_timeout, **kwargs)
            elif method == 'PATCH':
                resp = self.http.patch(request_url, timeout=use_timeout, **kwargs)
            elif method == 'DELETE':
                resp = self.http.delete(request_url, timeout=use_timeout, **kwargs)
            else:
                resp = self.http.get(request_url, timeout=use_timeout, **kwargs)
            tries += 1

            if resp.status_code == 401 and tries < max_tries:
                # unauthorized error, lets refresh token and retry
                self.token_refresh_lock.acquire(False)
                lock_acquirer = True
                logger.warning(f"Unauthorized Response (Attempts {tries}/{max_tries})")
                self.auth_token['expires_at'] = time.time() - 10
                self.http = self._new_http_object()
            else:
                break

        return resp

    def _load_auth_token(self):
        try:
            try:
                token = methods.get_setting_value('auth_token')
                logger.trace(f"Loaded auth_token: {token}")
                if not token:
                    return {}

                return json.loads(token)
            except Exception:
                return {}
        except Exception:
            logger.exception("Exception loading auth_token from cache: ")
        return {}

    def _dump_auth_token(self):
        try:
            if methods.set_setting_value('auth_token', json.dumps(self.auth_token, separators=(',', ':'))):
                return True
        except Exception:
            logger.exception("Exception dumping auth_token to cache: ")
        return False

    def _auth_token_saver(self, token: dict):
        # update internal token dict
        self.auth_token.update(token)
        try:
            if self.token_refresh_lock.locked():
                self.token_refresh_lock.release()
        except Exception:
            logger.exception("Exception releasing token_refresh_lock: ")
        self._dump_auth_token()
        logger.info("Renewed auth_token!")
        return

    def _load_page_token(self):
        try:
            page_token = methods.get_setting_value(f'page_token_{self.drive_identifier}')
            logger.trace(f"Loaded page_token: {page_token}")
            return page_token
        except Exception:
            pass
        return None

    def _page_token_saver(self, page_token: str):
        try:
            # get
            if methods.set_setting_value(f'page_token_{self.drive_identifier}', page_token):
                logger.trace(f"Updated page_token: {page_token}")
            else:
                logger.error(f"Failed updating page_token to {page_token!r}...")
            return
        except Exception:
            logger.exception(f"Exception updating page_token to {page_token!r}: ")
        return

    def _new_http_object(self):
        return SharedOAuth2Session(client_id=self.client_id, redirect_uri=self.redirect_url, scope=self.scopes,
                                   auto_refresh_url=self.token_url,
                                   auto_refresh_kwargs={'client_id': self.client_id,
                                                        'client_secret': self.client_secret},
                                   token_updater=self._auth_token_saver, token=self.auth_token)

    def _get_cached_metadata(self, item_id, teamdrive_id=None):
        try:
            item = methods.get_file_item(file_id=item_id, teamdrive_id=teamdrive_id)
            # if item is not None:
            #    logger.info(f"Loaded: {item_id!r} from cache: {item!r}")
            return {'id': item['item_id'], 'teamDriveId': item['drive_id'], 'name': item['item_name'],
                    'md5Checksum': item['item_hash'], 'parents': json.loads(item['item_parents']),
                    'paths': json.loads(item['item_paths']), 'size': item['item_size']}
        except Exception:
            pass
        return None

    def _remove_unwanted_paths(self, paths_list: list, mime_type: str):
        # remove paths that were not allowed - this is always enabled
        for item_path in copy(paths_list):
            allowed_path = False
            for allowed_file_path in self.cfg.google.allowed.file_paths:
                if item_path.lower().startswith(allowed_file_path.lower()):
                    allowed_path = True
                    break
            if not allowed_path:
                logger.debug(f"Ignoring {item_path!r} because its not an allowed path")
                paths_list.remove(item_path)
                continue

        # remove unallowed extensions
        if self.cfg.google.allowed.file_extensions and paths_list:
            for item_path in copy(paths_list):
                allowed_file = False
                for allowed_extension in self.cfg.google.allowed.file_extensions_list:
                    if item_path.lower().endswith(allowed_extension.lower()):
                        allowed_file = True
                        break
                if not allowed_file:
                    logger.debug(f"Ignoring {item_path!r} because it was not an allowed extension")
                    paths_list.remove(item_path)

        # remove unallowed mimes
        if self.cfg.google.allowed.mime_types and paths_list:
            allowed_file = False
            for allowed_mime in self.cfg.google.allowed.mime_types_list:
                if allowed_mime.lower() in mime_type.lower():
                    if 'video' in mime_type.lower():
                        # we want to validate this is not a .sub file, which for some reason, google shows as video/MP2G
                        double_checked_allowed = True
                        for item_path in paths_list:
                            if item_path.lower().endswith('.sub'):
                                double_checked_allowed = False
                        if double_checked_allowed:
                            allowed_file = True
                            break
                    else:
                        allowed_file = True
                        break

            if not allowed_file:
                logger.debug(f"Ignoring {paths_list!r} because it was not an allowed mime: {mime_type}")
                for item_path in copy(paths_list):
                    paths_list.remove(item_path)

    def _process_changes(self, data: dict):
        added_file_paths = {}
        removed_file_items = {}
        ignored_file_paths = {}
        removed_file_paths = {}
        removes = 0
        moves = 0

        if not data or 'changes' not in data:
            logger.error("There were no changes to process")
            return
        logger.info(f"Processing {len(data['changes'])} changes")

        # process changes
        for change in data['changes']:
            file_item = None
            if 'fileId' in change and 'removed' in change and 'file' not in change:
                # this is a strange remove - lets account for it
                self.remove_item_from_cache(change['fileId'],
                                            change['teamDriveId'] if 'teamDriveId' in change else None)
                removes += 1
                continue
            elif 'file' in change and 'fileId' in change:
                # generate file item
                if 'name' in change['file'] and 'size' in change['file']:
                    file_item = {
                        'name': change['file']['name'],
                        'size': change['file']['size'],
                        'teamdrive_id': change['file']['teamDriveId'] if 'teamDriveId' in change['file'] else None
                    }

                # retrieve item from cache
                existing_cache_item = self._get_cached_metadata(change['fileId'],
                                                                change['file']['teamDriveId'] if 'teamDriveId' in
                                                                                                 change['file']
                                                                else None)

                # dont consider trashed/removed events for processing
                if ('trashed' in change['file'] and change['file']['trashed']) or (
                        'removed' in change and change['removed']):
                    # remove item from cache
                    self.remove_item_from_cache(change['fileId'],
                                                change['file']['teamDriveId'] if 'teamDriveId' in change['file']
                                                else None)

                    # add item to removed_file_items
                    if 'md5Checksum' in change['file'] and file_item is not None:
                        if change['file']['md5Checksum'] in removed_file_items:
                            removed_file_items[change['file']['md5Checksum']].append(file_item)
                        else:
                            removed_file_items[change['file']['md5Checksum']] = [file_item]

                    if existing_cache_item and 'paths' in existing_cache_item \
                            and existing_cache_item['paths']:
                        if change['fileId'] in removed_file_paths:
                            removed_file_paths[change['fileId']].extend(existing_cache_item['paths'])
                        else:
                            removed_file_paths[change['fileId']] = existing_cache_item['paths']

                    removes += 1
                    continue

                # we always want to add changes to the cache so renames etc can be reflected inside the cache
                success, item_paths = self.add_item_to_cache(change['fileId'], change['file']['name'],
                                                             [] if 'parents' not in change['file'] else
                                                             change['file']['parents'],
                                                             change['file']['md5Checksum'] if 'md5Checksum' in
                                                                                              change[
                                                                                                  'file'] else None,
                                                             change['file']['size'] if 'size' in change[
                                                                 'file'] else 0,
                                                             change['file']['teamDriveId'] if 'teamDriveId' in
                                                                                              change[
                                                                                                  'file'] else None)

                # dont process folder events
                if 'mimeType' in change['file'] and 'vnd.google-apps.folder' in change['file']['mimeType']:
                    # ignore this change as we dont want to scan folders
                    logger.debug(f"Ignoring {item_paths!r} because its a folder")
                    if change['fileId'] in ignored_file_paths:
                        ignored_file_paths[change['fileId']].extend(item_paths)
                    else:
                        ignored_file_paths[change['fileId']] = item_paths
                    continue

                if success and len(item_paths):
                    self._remove_unwanted_paths(item_paths, change['file']['mimeType'] if 'mimeType' in change[
                        'file'] else 'Unknown')

                # was this an existing item?
                if existing_cache_item is not None and (success and len(item_paths)):
                    # this was an existing item, and we are re-processing it again
                    # we need to determine if this file has changed (md5Checksum)
                    if 'md5Checksum' in change['file'] and 'md5Checksum' in existing_cache_item:
                        # compare this changes md5Checksum and the existing cache item
                        if change['file']['md5Checksum'] != existing_cache_item['md5Checksum']:
                            # the file was modified
                            if change['fileId'] in added_file_paths:
                                added_file_paths[change['fileId']]['paths'].extend(item_paths)
                            else:
                                added_file_paths[change['fileId']] = {'paths': item_paths, 'teamdrive': change['file'][
                                    'teamDriveId'] if 'teamDriveId' in change['file'] else None}

                        elif 'paths' in existing_cache_item and not self._list_matches(item_paths,
                                                                                       existing_cache_item['paths']):
                            # the paths of the existing items have changed...
                            # we must remove the old ones and add the new ones
                            logger.debug(f"Server-side move or rename was detected for "
                                         f"{existing_cache_item['paths']} to: {item_paths}")

                            if change['fileId'] in added_file_paths:
                                added_file_paths[change['fileId']]['paths'].extend(item_paths)
                            else:
                                added_file_paths[change['fileId']] = {'paths': item_paths, 'teamdrive': change['file'][
                                    'teamDriveId'] if 'teamDriveId' in change['file'] else None}

                            if change['fileId'] in removed_file_paths:
                                removed_file_paths[change['fileId']].extend(existing_cache_item['paths'])
                            else:
                                removed_file_paths[change['fileId']] = existing_cache_item['paths']

                            moves += len(existing_cache_item['paths'])

                        else:
                            logger.debug(f"Ignoring {item_paths!r} because the md5Checksum was the same as cache: "
                                         f"{existing_cache_item['md5Checksum']}")
                            if change['fileId'] in ignored_file_paths:
                                ignored_file_paths[change['fileId']].extend(item_paths)
                            else:
                                ignored_file_paths[change['fileId']] = item_paths
                    else:
                        logger.error(
                            f"No md5Checksum for cache item:\n{existing_cache_item}")

                elif success and len(item_paths):
                    # these are new paths/files that were not already in the cache
                    if change['fileId'] in added_file_paths:
                        added_file_paths[change['fileId']]['paths'].extend(item_paths)
                    else:
                        added_file_paths[change['fileId']] = {'paths': item_paths, 'teamdrive': change['file'][
                            'teamDriveId'] if 'teamDriveId' in change['file'] else None}

            elif 'teamDriveId' in change:
                # this is a teamdrive change
                # dont consider trashed/removed events for processing
                if 'removed' in change and change['removed']:
                    # remove item from cache
                    self.remove_item_from_cache(change['teamDriveId'])
                    removes += 1
                    continue

                if 'teamDrive' in change and 'id' in change['teamDrive'] and 'name' in change['teamDrive']:
                    # we always want to add changes to the cache so renames etc can be reflected inside the cache
                    self.add_item_to_cache(change['teamDrive']['id'], change['teamDrive']['name'], [], None, 0,
                                           change['teamDrive']['id'])
                    continue

        # always dump the cache after running changes

        # display logging
        logger.trace(f"Added: {added_file_paths}")
        logger.trace(f"Ignored: {ignored_file_paths}")
        logger.trace(f"Removed: {removed_file_items}")

        logger.info(
            f'{len(added_file_paths)} added / {removes} removed / {moves} moved / {len(ignored_file_paths)} ignored')

        # call further callbacks
        self._do_callback('items_removed', removed_file_paths)
        self._do_callback('items_added', added_file_paths)
        return

    def _do_callback(self, callback_type, callback_data):
        if callback_type in self.callbacks and callback_data:
            self.callbacks[callback_type](callback_data)
        return

    @staticmethod
    def _list_matches(list_master, list_check):
        try:
            for item in list_master:
                if item not in list_check:
                    return False
            return True
        except Exception:
            logger.exception('Exception checking if lists match: ')
        return False
