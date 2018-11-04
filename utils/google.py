import json
import logging
import os
from copy import copy
from threading import Lock
from time import time

from requests import Response, Request
from requests_oauthlib import OAuth2Session
from sqlitedict import SqliteDict

from utils.log import logger

log: logging.Logger = logger.get_logger(__name__)


class GoogleDrive:
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    token_url = 'https://www.googleapis.com/oauth2/v4/token'
    api_url = 'https://www.googleapis.com/drive/'
    redirect_url = 'urn:ietf:wg:oauth:2.0:oob'
    scopes = ['https://www.googleapis.com/auth/drive.readonly']

    def __init__(self, config, client_id: str, client_secret: str, token_path: str, cache_path: str):
        self.cfg = config
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_path = token_path
        self.cache_path = cache_path
        self.cache = SqliteDict(self.cache_path, tablename='cache', encode=json.dumps, decode=json.loads,
                                autocommit=False)
        self.token = self._load_token()
        self.query_lock = Lock()
        self.http = self._new_http_object()

    ############################################################
    # CORE CLASS METHODS
    ############################################################

    def get_auth_link(self):
        auth_url, state = self.http.authorization_url(self.auth_url, access_type='offline', prompt='select_account')
        return auth_url

    def exchange_code(self, code: str):
        token = self.http.fetch_token(self.token_url, code=code, client_secret=self.client_secret)
        if 'access_token' in token:
            self._token_saver(token)
        return self.token

    def query(self, path: str, method: str = 'GET', fetch_all_pages: bool = False, callbacks={}, **kwargs):
        resp: Response = None
        pages: int = 1
        resp_json = {}
        request_url = self.api_url + path.lstrip('/') if not path.startswith('http') else path

        try:
            while True:
                resp = self._do_query(request_url, method, **kwargs)
                log.debug(f"Request URL: {resp.url}")
                log.debug(f"Request ARG: {kwargs}")
                log.debug(f'Response Status: {resp.status_code} {resp.reason}')

                if 'stream' in kwargs and kwargs['stream']:
                    return True, resp, None

                if 'Content-Type' in resp.headers and 'json' in resp.headers['Content-Type']:
                    if fetch_all_pages:
                        resp_json.pop('nextPageToken', None)
                    new_json = resp.json()
                    # does this page have changes
                    extended_changes = False
                    changes = []
                    if 'changes' in new_json:
                        if 'changes' in resp_json:
                            changes.extend(resp_json['changes'])
                        changes.extend(new_json['changes'])
                        extended_changes = True

                    resp_json.update(new_json)
                    if extended_changes:
                        resp_json['changes'] = changes
                else:
                    return False if resp.status_code != 200 else True, resp, resp.text

                # call page_token_callback to update cached page_token, if specified
                if 'page_token_callback' in callbacks:
                    if 'nextPageToken' in resp_json:
                        callbacks['page_token_callback'](resp_json['nextPageToken'])
                    elif 'newStartPageToken' in resp_json:
                        callbacks['page_token_callback'](resp_json['newStartPageToken'])

                # call data_callback, fetch_all_pages is true
                if fetch_all_pages and 'data_callback' in callbacks:
                    callbacks['data_callback'](resp.json(), callbacks)

                # handle nextPageToken
                if fetch_all_pages and 'nextPageToken' in resp_json and resp_json['nextPageToken']:
                    # there are more pages
                    pages += 1
                    log.info("Fetching extra results from page %d", pages)
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
            log.exception(f"Exception sending request to {request_url} with kwargs={kwargs}: ")
            return False, resp, None

    ############################################################
    # DRIVE FUNCTIONS
    ############################################################

    def validate_access_token(self):
        success, resp, data = self.query('/v3/changes/startPageToken',
                                         params={'supportsTeamDrives': self.cfg.google.teamdrive})
        if success and resp.status_code == 200:
            if 'startPageToken' not in data:
                log.error("Failed validate up to date access_token:\n\n%s\n", data)
                return False
            return True
        else:
            log.error("Error validating access token, status_code = %d, data =\n\n%s\n",
                      resp.status_code if resp is not None else 0, data)
        return False

    def get_changes(self, new_items_callback=None, removed_items_callback=None):
        callbacks = {'page_token_callback': self._page_token_saver,
                     'data_callback': self._process_changes}

        if new_items_callback:
            callbacks['new_items_callback'] = new_items_callback
        if removed_items_callback:
            callbacks['removed_items_callback'] = removed_items_callback

        success, resp, data = self.query('/v3/changes', params={
            'pageToken': self.token['page_token'] if 'page_token' in self.token else '1', 'pageSize': 1000,
            'includeRemoved': True,
            'includeTeamDriveItems': self.cfg.google.teamdrive,
            'supportsTeamDrives': self.cfg.google.teamdrive,
            'fields': 'changes(file(md5Checksum,mimeType,modifiedTime,'
                      'name,parents,teamDriveId,trashed),'
                      'fileId,removed,teamDrive(id,name),'
                      'teamDriveId),newStartPageToken,nextPageToken'}, fetch_all_pages=True,
                                         callbacks=callbacks)
        return

    def get_file(self, file_id, stream=True, headers=None):
        success, resp, data = self.query('/v2/files/%s' % file_id, params={
            'includeTeamDriveItems': self.cfg.google.teamdrive,
            'supportsTeamDrives': self.cfg.google.teamdrive,
            'alt': 'media'
        }, stream=stream, headers=headers)
        return resp

    def get_stream_link(self, file_id):
        # validate / refersh current access_token
        if not self.validate_access_token():
            return ''
        log.debug("Validated access_token is current")

        # generate url
        req = Request('GET', f'{self.api_url.rstrip("/")}/v2/files/{file_id}',
                      params={'includeTeamDriveItems': self.cfg.google.teamdrive,
                              'supportsTeamDrives': self.cfg.google.teamdrive,
                              'alt': 'media',
                              'access_token': self.token['access_token']}).prepare()
        log.debug(f'Direct Stream URL: {req.url}')
        return req.url

    ############################################################
    # CACHE
    ############################################################

    def get_id_metadata(self, item_id, teamdrive_id=None):
        # return cache from metadata if available
        cached_metadata = self._get_cached_metdata(item_id)
        if cached_metadata:
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
                                                 'supportsTeamDrives': self.cfg.google.teamdrive,
                                                 'fields': 'id,md5Checksum,mimeType,modifiedTime,name,parents,'
                                                           'trashed,teamDriveId'})
        if success and resp.status_code == 200:
            return True, data
        else:
            log.error("Error retrieving metadata for item %r:\n\n%s\n", item_id, data)
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
                    self.add_item_to_cache(obj['id'], obj['name'], [] if 'parents' not in obj else obj['parents'])
                    new_cache_entries += 1

                if path.strip() == '':
                    path = obj['name']
                else:
                    path = os.path.join(obj['name'], path)

                if 'parents' in obj and obj['parents']:
                    for parent in obj['parents']:
                        new_cache_entries += get_item_paths(parent, path, paths, new_cache_entries, teamdrive_id)

                if (not obj or 'parents' not in obj or not obj['parents']) and len(path):
                    paths.append(path)
                    return new_cache_entries
                return new_cache_entries

            added_to_cache += get_item_paths(item_id, '', file_paths, added_to_cache, teamdrive_id)
            if added_to_cache:
                log.debug("Dumping cache due to new entries!")
                self._dump_cache()

            if len(file_paths):
                return True, file_paths
            else:
                return False, file_paths

        except Exception:
            log.exception("Exception retrieving filepaths for '%s': ", item_id)

        return False, []

    def add_item_to_cache(self, item_id, item_name, item_parents):
        if item_id not in self.cache:
            log.debug("Added '%s' to cache: %s", item_id, item_name)
        self.cache[item_id] = {'name': item_name, 'parents': item_parents}
        return

    def remove_item_from_cache(self, item_id):
        if self.cache.pop(item_id, None):
            return True
        return False

    def get_item_name_from_cache(self, item_id):
        try:
            item = self.cache.get(item_id)
            return item['name'] if isinstance(item, dict) else 'Unknown'
        except Exception:
            pass
        return 'Unknown'

    def get_item_from_cache(self, item_id):
        try:
            item = self.cache.get(item_id, None)
            return item
        except Exception:
            pass
        return None

    ############################################################
    # INTERNALS
    ############################################################

    def _do_query(self, request_url: str, method: str, **kwargs):
        tries: int = 0
        max_tries: int = 2
        resp: Response = None

        # remove un-needed kwargs
        kwargs.pop('fetch_all_pages', None)
        kwargs.pop('page_token_callback', None)

        # acquire query_lock
        # we do this, so only 1 thread can query at the same time, this will allow us
        # to maintain / refresh the tokens only in one thread
        with self.query_lock:
            # do query
            while tries < max_tries:
                if method == 'POST':
                    resp = self.http.post(request_url, timeout=30, **kwargs)
                elif method == 'PATCH':
                    resp = self.http.patch(request_url, timeout=30, **kwargs)
                elif method == 'DELETE':
                    resp = self.http.delete(request_url, timeout=30, **kwargs)
                else:
                    resp = self.http.get(request_url, timeout=30, **kwargs)
                tries += 1

                if resp.status_code == 401 and tries < max_tries:
                    # unauthorized error, lets refresh token and retry
                    log.warning(f"Unauthorized Response (Attempts {tries}/{max_tries})")
                    self.token['expires_at'] = time() - 10
                    self.http = self._new_http_object()
                else:
                    break

        return resp

    def _load_token(self):
        try:
            if not os.path.exists(self.token_path):
                return {}

            with open(self.token_path, 'r') as fp:
                return json.load(fp)
        except Exception:
            log.exception(f"Exception loading token from {self.token_path}: ")
        return {}

    def _dump_token(self):
        try:
            with open(self.token_path, 'w') as fp:
                json.dump(self.token, fp, indent=2)
            return True
        except Exception:
            log.exception(f"Exception dumping token to {self.token_path}: ")
        return False

    def _token_saver(self, token: dict):
        # update internal token dict
        self.token.update(token)
        self._dump_token()
        log.info("Renewed access token!")
        return

    def _page_token_saver(self, page_token: str):
        # update internal token dict
        self.token['page_token'] = page_token
        self._dump_token()
        return

    def _new_http_object(self):
        return OAuth2Session(client_id=self.client_id, redirect_uri=self.redirect_url, scope=self.scopes,
                             auto_refresh_url=self.token_url, auto_refresh_kwargs={'client_id': self.client_id,
                                                                                   'client_secret': self.client_secret},
                             token_updater=self._token_saver, token=self.token)

    def _get_cached_metdata(self, item_id):
        if item_id in self.cache:
            return self.cache[item_id]
        return None

    def _dump_cache(self):
        self.cache.commit()
        return

    def _remove_unwanted_paths(self, paths_list: list, mime_type: str):
        # remove ignored paths - this is always enabled
        for item_path in copy(paths_list):
            for ignore_path in self.cfg.google.ignore_paths:
                if item_path.lower().startswith(ignore_path.lower()):
                    log.debug("Ignoring %r because it starts with %r", item_path, ignore_path)
                    paths_list.remove(item_path)
                    continue

        # remove unallowed extensions
        if self.cfg.google.use_allowed_extensions:
            for item_path in copy(paths_list):
                allowed_file = False
                for allowed_extension in self.cfg.google.allowed_extensions:
                    if item_path.lower().endswith(allowed_extension.lower()):
                        allowed_file = True
                        break
                if not allowed_file:
                    log.debug("Ignoring %r because it was not an allowed extension", item_path)
                    paths_list.remove(item_path)

        # remove unallowed mimes
        if self.cfg.google.use_allowed_mimes:
            allowed_file = False
            for allowed_mime in self.cfg.google.allowed_mimes:
                if allowed_mime.lower() in mime_type.lower():
                    allowed_file = True
                    break
            if not allowed_file:
                log.debug("Ignoring %s because it was not an allowed mime: %s", paths_list, mime_type)
                for item_path in copy(paths_list):
                    paths_list.remove(item_path)

    def _process_changes(self, data: dict, callbacks: dict = {}):
        removed_file_paths = {}
        added_file_paths = {}
        if not data or 'changes' not in data:
            log.error("There were no changes to process")
            return
        log.info("Processing %d changes", len(data['changes']))

        # process changes
        for change in data['changes']:
            if 'file' in change and 'fileId' in change:
                # dont consider trashed/removed events for processing
                if ('trashed' in change['file'] and change['file']['trashed']) or (
                        'removed' in change and change['removed']):
                    # store the removed file paths - only if we have this item cached, otherwise we are not interested
                    # as we would not have stored it anyway...
                    item_exists = self.get_item_from_cache(change['fileId'])
                    if item_exists is not None:
                        success, item_paths = self.get_id_file_paths(change['fileId'],
                                                                     change['file']['teamDriveId'] if 'teamDriveId'
                                                                                                      in
                                                                                                      change['file']
                                                                     else None)
                        self._remove_unwanted_paths(item_paths, change['file']['mimeType'] if 'mimeType' in change[
                            'file'] else 'Unknown')
                        if success and len(item_paths):
                            if change['fileId'] in removed_file_paths:
                                removed_file_paths[change['fileId']].extend(item_paths)
                            else:
                                removed_file_paths[change['fileId']] = item_paths

                    # remove item from cache
                    if self.remove_item_from_cache(change['fileId']):
                        log.debug("Removed '%s' from cache: %s", change['fileId'], change['file']['name'])

                    continue

                existing_cache_item = self.get_item_from_cache(change['fileId'])
                existing_success, existing_cache_item_paths = self.get_id_file_paths(change['fileId'],
                                                                                     change['file']['teamDriveId']
                                                                                     if 'teamDriveId' in change[
                                                                                         'file'] else None) if \
                    existing_cache_item is not None else (None, None)

                # we always want to add changes to the cache so renames etc can be reflected inside the cache
                self.add_item_to_cache(change['fileId'], change['file']['name'],
                                       [] if 'parents' not in change['file'] else change['file']['parents'])

                # dont process folder events
                if 'mimeType' in change['file'] and 'vnd.google-apps.folder' in change['file']['mimeType']:
                    # ignore this change as we dont want to scan folders
                    continue

                # get this files paths
                success, item_paths = self.get_id_file_paths(change['fileId'],
                                                             change['file']['teamDriveId'] if 'teamDriveId' in change[
                                                                 'file'] else None)

                # remove unwanted paths
                if existing_success and len(existing_cache_item_paths):
                    self._remove_unwanted_paths(existing_cache_item_paths,
                                                change['file']['mimeType'] if 'mimeType' in change[
                                                    'file'] else 'Unknown')
                if success and len(item_paths):
                    self._remove_unwanted_paths(item_paths, change['file']['mimeType'] if 'mimeType' in change[
                        'file'] else 'Unknown')

                # was this an existing item?
                if (existing_cache_item is not None and existing_success and len(existing_cache_item_paths)) and (
                        success and len(item_paths)):
                    # this was an existing item, and we are re-processing it again
                    # we need to find the differences between the before and after paths.
                    existing_path_set = set(existing_cache_item_paths)
                    new_path_set = set(item_paths)

                    removed_item_paths = existing_path_set.difference(new_path_set)
                    added_item_paths = new_path_set.difference(existing_path_set)

                    if len(removed_item_paths):
                        if change['fileId'] in removed_file_paths:
                            removed_file_paths[change['fileId']].extend(list(removed_item_paths))
                        else:
                            removed_file_paths[change['fileId']] = list(removed_item_paths)
                    if len(added_item_paths):
                        if change['fileId'] in added_file_paths:
                            added_file_paths[change['fileId']].extend(list(added_item_paths))
                        else:
                            added_file_paths[change['fileId']] = list(added_item_paths)

                elif success and len(item_paths):
                    # these are new paths/files that were not already in the cache
                    if change['fileId'] in added_file_paths:
                        added_file_paths[change['fileId']].extend(item_paths)
                    else:
                        added_file_paths[change['fileId']] = item_paths

            elif 'teamDrive' in change and 'teamDriveId' in change:
                # this is a teamdrive change
                # dont consider trashed/removed events for processing
                if 'removed' in change and change['removed']:
                    # remove item from cache
                    if self.remove_item_from_cache(change['teamDriveId']):
                        log.info("Removed teamDrive '%s' from cache: %s", change['teamDriveId'],
                                 change['teamDrive']['name'] if 'name' in change[
                                     'teamDrive'] else 'Unknown teamDrive')
                    continue

                if 'id' in change['teamDrive'] and 'name' in change['teamDrive']:
                    # we always want to add changes to the cache so renames etc can be reflected inside the cache
                    self.add_item_to_cache(change['teamDrive']['id'], change['teamDrive']['name'], [])
                    continue

        # always dump the cache after running changes
        self._dump_cache()
        log.info('%d added / %d removed', len(added_file_paths), len(removed_file_paths))

        # call further callbacks
        if len(removed_file_paths) and 'removed_items_callback' in callbacks:
            callbacks['removed_items_callback'](removed_file_paths)
        if len(added_file_paths) and 'new_items_callback' in callbacks:
            callbacks['new_items_callback'](added_file_paths)

        return
