import json
import multiprocessing
import os
from math import log as m_log

from loguru import logger

try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)

        return cls._instances[cls]


def quote_string(string_to_quote):
    return cmd_quote(string_to_quote)


def seconds_to_string(elapsed_seconds):
    """ reference: https://codereview.stackexchange.com/a/120595 """
    resp = ''
    try:
        seconds, milliseconds = divmod(elapsed_seconds, 1)
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        if days:
            resp += '%d days' % days
        if hours:
            if len(resp):
                resp += ', '
            resp += '%d hours' % hours
        if minutes:
            if len(resp):
                resp += ', '
            resp += '%d minutes' % minutes
        if seconds:
            if len(resp):
                resp += f"{' and' if not milliseconds else ','} "
            resp += '%d seconds' % seconds
        if milliseconds > 0.000:
            if len(resp):
                resp += ' and '
            resp += '%.3f milliseconds' % milliseconds

    except Exception:
        logger.exception(f"Exception occurred converting {elapsed_seconds} seconds to readable string: ")
        resp = '%d seconds' % elapsed_seconds
    return resp


def pretty_size(n, pow=0, b=1024, u='B', pre=[''] + [p + 'i' for p in 'KMGTPEZY']):
    """ origin: https://stackoverflow.com/a/31178618 """
    try:
        if isinstance(n, str):
            n = int(n)
        pow, n = min(int(m_log(max(n * b ** pow, 1), b)), len(pre) - 1), n * b ** pow
        return "%%.%if %%s%%s" % abs(pow % (-pow - 1)) % (n / b ** float(pow), pre[pow], u)
    except Exception:
        logger.exception(f"Exception determining pretty size for {n} {u}: ")
    return f'{n} {u}'


class JSONEncoderWithDictProxy(json.JSONEncoder):
    """ Credits: https://stackoverflow.com/a/44267287 """

    def default(self, o):
        if isinstance(o, multiprocessing.managers.DictProxy):
            return dict(o)
        return json.JSONEncoder.default(self, o)


def dictproxy_to_dict(dict_proxy):
    try:
        # this is a nasty hack (temporary until better solution is found)
        serialized_dict_proxy = json.dumps(dict_proxy, cls=JSONEncoderWithDictProxy)
        return json.loads(serialized_dict_proxy)
    except Exception:
        logger.exception(f"Exception converting DictProxy to Dict: ")
    return {}


def proxy_file_download_link(cfg):
    try:
        download_link = f'{cfg.api.public_url.rstrip("/")}/{cfg.api.download_key}'
        return download_link
    except Exception:
        logger.exception(f"Exception generating proxy file download link: ")
    return None


def list_folders_in_path(path):
    try:
        return [os.path.join(path, d) for d in os.listdir(path) if os.path.isdir(os.path.join(path, d))]
    except Exception:
        logger.exception(f"Exception listing folders in {path!r}: ")
    return []
