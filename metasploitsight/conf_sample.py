VULNERABILITY_LOOKUP_BASE_URL = "https://vulnerability.circl.lu/"
VULNERABILITY_LOOKUP_AUTH_TOKEN = ""

GIT_REPOSITORY = "metasploit-repository"

SIGHTING_TYPE = "seen"

# When True, the content of the originating modules  is included
# in sightings pushed to Vulnerability-Lookup.
push_sighting_content = False

# Hearbeat mechanism
HEARTBEAT_ENABLED = False
VALKEY_HOST = "127.0.0.1"
VALKEY_PORT = 10002
EXPIRATION_PERIOD = 18000
