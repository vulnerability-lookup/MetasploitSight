import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone

from pyvulnerabilitylookup import PyVulnerabilityLookup

from metasploitsight import config
from metasploitsight.monitoring import heartbeat, log

REPO_PATH = config.GIT_REPOSITORY
MODULES = "db/modules_metadata_base.json"  # Path to check for Metasploit modules
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")  # Pattern for CVE identifiers
SINCE_DAYS = "4 day ago"  # same window used in get_new_commits()


# small in-memory cache (module_key -> (commit_hash, iso_date))
_module_first_commit_cache = {}


def git_pull():
    """Pull the latest changes from the Git repository."""
    try:
        subprocess.run(["git", "pull"], cwd=REPO_PATH, check=True, text=True)
        print("Git repository updated successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to update Git repository: {e}")
        return False
    return True


def run_git(args):
    """Run a git command (list of args) in REPO_PATH and return stdout (or raise)."""
    result = subprocess.run(
        ["git"] + args, cwd=REPO_PATH, check=True, text=True, capture_output=True
    )
    return result.stdout


def get_commits_touching_file(since=SINCE_DAYS):
    """
    Return a list of commit hashes (most recent first) that touched MODULES since given period.
    """
    try:
        # list commits touching the file since the period, each line a commit hash
        out = run_git(
            ["log", f"--since='{since}'", "--pretty=format:%H", "--", MODULES]
        )
        commits = [line.strip() for line in out.splitlines() if line.strip()]
        return commits
    except subprocess.CalledProcessError:
        return []


def build_first_commit_map():
    """
    Build a mapping {module_key: (commit_hash, iso_date)} for the current modules in the
    working tree by scanning the history of MODULES from oldest to newest and marking
    the first commit where each key appears.

    Returns the mapping (dict).
    """
    print("Building a mapping for the current modules in the working tree…")
    # If already built in memory, return it (for later…)
    if _module_first_commit_cache:
        return _module_first_commit_cache

    # Load current module keys from working tree
    try:
        with open(os.path.join(REPO_PATH, MODULES), "r", encoding="utf-8") as fh:
            current = json.load(fh)
    except Exception:
        # If we can't load current file, return empty map
        return {}

    all_keys = set(current.keys())
    first_seen = {}

    # Get commits touching MODULES, oldest first
    try:
        commits_out = run_git(
            ["log", "--pretty=format:%H", "--reverse", "--", MODULES]
        ).strip()
    except subprocess.CalledProcessError:
        return {}

    if not commits_out:
        return {}

    for commit in commits_out.splitlines():
        # Load the file content at this commit once
        try:
            content = run_git(["show", f"{commit}:{MODULES}"])
        except subprocess.CalledProcessError:
            # skip problematic commit
            continue

        try:
            obj = json.loads(content)
        except Exception:
            continue

        # For every key present in obj but not already recorded, record this commit
        for key in obj.keys():
            if key in first_seen:
                continue
            if key in all_keys:
                iso_date = get_commit_date_iso(commit)
                first_seen[key] = (commit, iso_date)

        # If we've found first-seen for all current keys, stop early
        if len(first_seen) >= len(all_keys):
            break

    # Populate the cache and return
    # For keys not found in history, we'll leave them absent (caller will fallback)
    for k, v in first_seen.items():
        _module_first_commit_cache[k] = v

    return _module_first_commit_cache


def load_json_at_commit(commit):
    """
    Return Python dict parsed from MODULES file at given commit.
    If file doesn't exist at that commit, return empty dict.
    """
    try:
        content = run_git(["show", f"{commit}:{MODULES}"])
        return json.loads(content)
    except subprocess.CalledProcessError:
        # file didn't exist at that commit
        return {}
    except json.JSONDecodeError as e:
        print(f"JSON decode error for commit {commit}: {e}")
        return {}


def get_commit_parent(commit):
    """
    Return the parent commit hash for the given commit, or None if no parent.
    """
    try:
        out = run_git(["rev-list", "--parents", "-n", "1", commit]).strip()
        parts = out.split()
        if len(parts) >= 2:
            # first is commit, second is parent
            return parts[1]
        return None
    except subprocess.CalledProcessError:
        return None


def get_commit_date_iso(commit):
    """
    Return commit committer date in ISO 8601 (string). Falls back to now if parsing fails.
    """
    try:
        out = run_git(["show", "-s", "--format=%cI", commit]).strip()
        if out:
            # %cI returns strict ISO-8601 (e.g. 2025-05-21T08:32:40+00:00)
            return out
    except subprocess.CalledProcessError:
        pass
    # fallback
    return datetime.now(timezone.utc).isoformat()


def find_cves_in_entry(entry_obj):
    """
    Given a module entry (dict), find CVEs in references (or anywhere else) and return a set of CVE strings.
    """
    cves = set()

    # Prefer references field if present and iterable
    refs = entry_obj.get("references")
    if isinstance(refs, list):
        for r in refs:
            if not isinstance(r, str):
                continue
            for m in CVE_PATTERN.findall(r):
                cves.add(m.upper())

    # As a fallback, search the entire JSON dump for CVEs (less precise)
    if not cves:
        dumped = json.dumps(entry_obj)
        for m in CVE_PATTERN.findall(dumped):
            cves.add(m.upper())

    return cves


def to_datetime(value: str) -> datetime:
    """Convert an ISO 8601 string to a timezone-aware datetime object."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        # If the string had no timezone info, assume UTC
        from datetime import timezone

        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def push_sighting_to_vulnerability_lookup(source, vulnerability, creation_date):
    """Create a sighting from an incoming status and push it to the Vulnerability-Lookup instance."""
    print("Pushing sighting to Vulnerability-Lookup…")
    vuln_lookup = PyVulnerabilityLookup(
        config.VULNERABILITY_LOOKUP_BASE_URL,
        token=config.VULNERABILITY_LOOKUP_AUTH_TOKEN,
    )

    # Create the sighting
    sighting = {
        "type": config.SIGHTING_TYPE,
        "source": source,
        "vulnerability": vulnerability,
        "creation_timestamp": to_datetime(creation_date),
    }

    # Post the JSON to Vulnerability-Lookup
    try:
        r = vuln_lookup.create_sighting(sighting=sighting)
        if "message" in r:
            print(r["message"])
            if "duplicate" in r["message"]:
                level = "info"
            else:
                level = "warning"
            log(level, f"push_sighting_to_vulnerability_lookup: {r['message']}")
    except Exception as e:
        print(
            f"Error when sending POST request to the Vulnerability-Lookup server:\n{e}"
        )
        log(
            "info",
            f"Error when sending POST request to the Vulnerability-Lookup server: {e}",
        )

    print("\n")


def process_added_entries(added_keys, entries_dict, commit_iso):
    """
    For each added module key, detect CVEs and push sightings.
    The creation date for sightings is the commit_iso (the commit that introduced the keys
    in db/modules_metadata_base.json).
    """
    for key in added_keys:
        entry = entries_dict.get(key, {})

        cves = find_cves_in_entry(entry)
        if not cves:
            # no CVE found, skip
            continue

        module_path = entry.get("path", "")
        if module_path:
            source = f"https://github.com/rapid7/metasploit-framework/blob/master{module_path}"
        else:
            source = f"Metasploit ({key})"

        # The module was added in the commit whose ISO date we received
        creation_date = commit_iso

        for cve in sorted(cves):
            print(
                f"Found {cve} in {key} (commit date {creation_date}) -> pushing sighting"
            )
            push_sighting_to_vulnerability_lookup(source, cve, creation_date)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="MetasploitSight",
        description="Find Metasploit modules from the official Metasploit repository.",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Find modules even if no new commits were detected. For the first run.",
    )

    arguments = parser.parse_args()

    # Log the launch of the script
    log("info", "Starting MetasploitSight…")

    # Sends a heartbeat when the script launches
    heartbeat()

    if not git_pull():
        log("info", "No new commit. MetasploitSight execution completed.")
        return

    commits = get_commits_touching_file()
    if not commits and not arguments.init:
        print(
            "No commits touching modules file in the window and not --init; nothing to do."
        )
        log("info", "No relevant commits found. MetasploitSight execution completed.")
        return

    # Bootstrap mode: treat all entries in the working tree copy as "added"
    if arguments.init:
        try:
            with open(os.path.join(REPO_PATH, MODULES), encoding="utf-8") as fh:
                current = json.load(fh)
        except Exception as e:
            print(f"Failed to load current {MODULES}: {e}")
            return

        # Build the first-commit map once
        first_commit_map = build_first_commit_map()

        added_keys = list(current.keys())
        for key in added_keys:
            entry = current.get(key, {})
            module_path = entry.get("path", "")
            if module_path:
                source = f"https://github.com/rapid7/metasploit-framework/blob/master{module_path}"
            else:
                source = f"Metasploit ({key})"

            # get creation date from the map; fallback to now if missing
            commit_hash, creation_date = first_commit_map.get(key, (None, None))
            if not creation_date:
                creation_date = datetime.now(timezone.utc).isoformat()

            cves = find_cves_in_entry(entry)
            if not cves:
                continue

            for cve in sorted(cves):
                print(
                    f"[init] Found {cve} in {key} (file creation date {creation_date}) -> pushing sighting"
                )
                push_sighting_to_vulnerability_lookup(source, cve, creation_date)

        log("info", "Init run completed.")
        return

    # Process each commit that touched the file.
    # We process commits from oldest to newest so that sightings reflect chronological order.
    for commit in reversed(commits):
        parent = get_commit_parent(commit)
        this_version = load_json_at_commit(commit)
        parent_version = load_json_at_commit(parent) if parent else {}
        # keys present in this_version but not in parent_version -> added in commit
        added = set(this_version.keys()) - set(parent_version.keys())
        if not added:
            print(f"No added entries in commit {commit}")
            continue
        commit_iso = get_commit_date_iso(commit)
        print(f"Commit {commit} added {len(added)} entries. Processing…")
        process_added_entries(added, this_version, commit_iso)

    log("info", "MetasploitSight execution completed.")


if __name__ == "__main__":
    # Point of entry in execution mode
    main()
