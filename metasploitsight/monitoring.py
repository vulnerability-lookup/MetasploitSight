import time

import valkey

from metasploitsight import config

if config.HEARTBEAT_ENABLED:
    valkey_client = valkey.Valkey(config.VALKEY_HOST, config.VALKEY_PORT)


def heartbeat(key="process_heartbeat_MetasploitSight") -> None:
    """Sends a heartbeat in the Valkey datastore."""
    if not config.HEARTBEAT_ENABLED:
        return
    try:
        valkey_client.set(
            key,
            time.time(),
            ex=config.EXPIRATION_PERIOD,
        )
    except Exception as e:
        print(f"Heartbeat error: {e}")


def log(level="warning", message="", key="process_logs_MetasploitSight") -> None:
    """Reports an error or warning in the Valkey datastore."""
    if not config.HEARTBEAT_ENABLED:
        return
    timestamp = time.time()
    log_entry = {"timestamp": timestamp, "level": level, "message": message}
    try:
        # Add the log entry to a list, so multiple messages are preserved
        valkey_client.rpush(key, str(log_entry))
        valkey_client.expire(key, 86400)  # Expire after 24 hours
    except Exception as e:
        print(f"Error reporting failure: {e}")
