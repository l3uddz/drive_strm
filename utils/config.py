import json
import os
import sys
from collections import OrderedDict

from attrdict import AttrDict

json.encoder.c_make_encoder = None


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)

        return cls._instances[cls]


class AttrConfig(AttrDict):
    """
    Simple AttrDict subclass to return None when requested attribute does not exist
    """

    def __init__(self, config):
        super().__init__(config)

    def __getattr__(self, item):
        try:
            return super().__getattr__(item)
        except AttributeError:
            pass
        # Default behaviour
        return None


class Config(object, metaclass=Singleton):
    base_config = OrderedDict({
        # core
        'core': {
            'debug': False
        },
        # server
        'server': {
            'listen_ip': '0.0.0.0',
            'listen_port': 7294,
            'direct_streams': False
        },
        # strm
        'strm': {
            'access_url': 'http://reachable.url.com',
            'root_path': '/strm',
            'show_transcodes': False,
            'chunk_size': 1000000
        },
        # google
        'google': {
            'allowed': {
                'file_paths': [],
                'file_extensions': False,
                'file_extensions_list': [],
                'mime_types': True,
                'mime_types_list': []
            },
            'client_id': '',
            'client_secret': '',
            'poll_interval': 120,
            'teamdrive': False
        }
    })

    def __init__(self, config_path, log_path):
        """Initializes config"""
        self.conf = OrderedDict({})

        self.config_path = config_path
        self.log_path = log_path

    @property
    def cfg(self):
        # Return existing loaded config
        if self.conf:
            return self.conf

        # Built initial config if it doesn't exist
        if self.build_config():
            print("Please edit the default configuration before running again!")
            sys.exit(0)
        # Load config, upgrade if necessary
        else:
            tmp = self.load_config()
            self.conf, upgraded = self.upgrade_settings(tmp)

            # Save config if upgraded
            if upgraded:
                self.dump_config()
                print("New config options were added, adjust and restart!")
                sys.exit(0)

            return self.conf

    @property
    def default_config(self):
        config = self.base_config

        # example google
        config['google']['allowed']['file_paths'] = ['My Drive/Media/Movies/', 'My Drive/Media/TV/']
        config['google']['allowed']['file_extensions_list'] = ['webm', 'mkv', 'flv', 'vob', 'ogv', 'ogg', 'drc', 'gif',
                                                               'gifv', 'mng', 'avi', 'mov', 'qt', 'wmv', 'yuv', 'rm',
                                                               'rmvb', 'asf', 'amv', 'mp4', 'm4p', 'm4v', 'mpg', 'mp2',
                                                               'mpeg', 'mpe', 'mpv', 'm2v', 'm4v', 'svi', '3gp', '3g2',
                                                               'mxf', 'roq', 'nsv', 'f4v', 'f4p', 'f4a', 'f4b', 'mp3',
                                                               'flac', 'ts']
        config['google']['allowed']['mime_types_list'] = ['video']

        return config

    @property
    def logfile(self):
        return self.log_path

    def build_config(self):
        if not os.path.exists(self.config_path):
            print("Dumping default config to: %s" % self.config_path)
            with open(self.config_path, 'w') as fp:
                json.dump(self.default_config, fp, sort_keys=False, indent=2, default=str)
            return True
        else:
            return False

    def dump_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, 'w') as fp:
                json.dump(self.conf, fp, sort_keys=False, indent=2, default=str)
            return True
        else:
            return False

    def load_config(self):
        with open(self.config_path, 'r') as fp:
            return AttrConfig(json.load(fp, object_hook=OrderedDict))

    def __inner_upgrade(self, settings1, settings2, key=None, overwrite=False):
        sub_upgraded = False
        merged = settings2.copy()

        if isinstance(settings1, dict):
            for k, v in settings1.items():
                # missing k
                if k not in settings2:
                    merged[k] = v
                    sub_upgraded = True
                    if not key:
                        print("Added %r config option: %s" % (str(k), str(v)))
                    else:
                        print("Added %r to config option %r: %s" % (str(k), str(key), str(v)))
                    continue

                # iterate children
                if isinstance(v, dict) or isinstance(v, list):
                    merged[k], did_upgrade = self.__inner_upgrade(settings1[k], settings2[k], key=k,
                                                                  overwrite=overwrite)
                    sub_upgraded = did_upgrade if did_upgrade else sub_upgraded
                elif settings1[k] != settings2[k] and overwrite:
                    merged = settings1
                    sub_upgraded = True
        elif isinstance(settings1, list) and key:
            for v in settings1:
                if v not in settings2:
                    merged.append(v)
                    sub_upgraded = True
                    print("Added to config option %r: %s" % (str(key), str(v)))
                    continue

        return merged, sub_upgraded

    def upgrade_settings(self, currents):
        upgraded_settings, upgraded = self.__inner_upgrade(self.base_config, currents)
        return AttrConfig(upgraded_settings), upgraded

    def merge_settings(self, settings_to_merge):
        upgraded_settings, upgraded = self.__inner_upgrade(settings_to_merge, self.conf, overwrite=True)

        self.conf = upgraded_settings

        if upgraded:
            self.dump_config()

        return AttrConfig(upgraded_settings), upgraded
