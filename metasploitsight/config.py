#! /usr/bin/env python

"""This module is responsible for loading the configuration variables.
"""

import importlib.util
import os


def load_config(path):
    spec = importlib.util.spec_from_file_location("config", path)
    if spec:
        config = importlib.util.module_from_spec(spec)
        if spec.loader:
            spec.loader.exec_module(config)
    return config


conf = None
try:
    conf = load_config(os.environ.get("METASPLOITSIGHT_CONFIG", "metasploitsight/conf_sample.py"))
except Exception as exc:
    raise Exception("No configuration file provided.") from exc
finally:
    if not conf:
        raise Exception("No configuration file provided.")


VULNERABILITY_LOOKUP_BASE_URL = conf.VULNERABILITY_LOOKUP_BASE_URL
VULNERABILITY_LOOKUP_AUTH_TOKEN = conf.VULNERABILITY_LOOKUP_AUTH_TOKEN

GIT_REPOSITORY = conf.GIT_REPOSITORY

SIGHTING_TYPE = conf.SIGHTING_TYPE


try:
    HEARTBEAT_ENABLED = conf.HEARTBEAT_ENABLED
    VALKEY_HOST = conf.VALKEY_HOST
    VALKEY_PORT = conf.VALKEY_PORT
    EXPIRATION_PERIOD = conf.EXPIRATION_PERIOD
except Exception:
    HEARTBEAT_ENABLED = False
