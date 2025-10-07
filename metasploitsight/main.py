import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from pyvulnerabilitylookup import PyVulnerabilityLookup

from metasploitsight import config
from metasploitsight.monitoring import heartbeat, log

REPO_PATH = config.GIT_REPOSITORY
MODULES = "db/modules_metadata_base.json"  # Path to check for Metasploit modules
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")  # Pattern for CVE identifiers
SINCE_DAYS = "4 day ago"  # same window used in get_new_commits()


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


def parse_mod_time_to_iso(mod_time_str):
    """
    Parse mod_time like '2025-05-21 08:32:40 +0000' to ISO 8601 string.
    Return None if parsing fails.
    """
    if not mod_time_str:
        return None
    try:
        dt = datetime.strptime(mod_time_str, "%Y-%m-%d %H:%M:%S %z")
        return dt.isoformat()
    except Exception:
        # try email.utils parser
        try:
            dt = parsedate_to_datetime(mod_time_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            return None


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


def get_file_creation_commit_and_date(file_path: str):
    """
    Return (commit_hash, ISO8601_date_string) of the commit that added the file.
    Returns (None, None) if not found.
    """
    try:
        # Always use a path relative to the repository root
        rel_path = os.path.relpath(file_path, REPO_PATH)

        out = run_git(
            [
                "log",
                "--diff-filter=A",  # only additions
                "--follow",  # track renames
                "--format=%H %cI",  # commit hash and ISO date
                "--",
                rel_path,
            ]
        ).strip()

        if not out:
            return None, None

        # take the *last* line (oldest addition)
        first_commit_line = out.splitlines()[-1]
        commit_hash, iso_date = first_commit_line.split(maxsplit=1)
        return commit_hash, iso_date
    except subprocess.CalledProcessError:
        return None, None


def process_added_entries(added_keys, entries_dict, commit_iso):
    """
    For each added module key, detect CVEs and push sightings.
    The creation date for sightings is the Git addition date of the file.
    """
    for key in added_keys:
        entry = entries_dict.get(key, {})

        cves = find_cves_in_entry(entry)
        if not cves:
            # no CVE found, skip
            # print(f"No CVE found for {key}, skipping.")
            continue

        module_path = entry.get("path", "")
        if module_path:
            source = f"https://github.com/rapid7/metasploit-framework/blob/master{module_path}"
            # get the commit and date where this file first appeared
            _, creation_date = get_file_creation_commit_and_date(
                os.path.join(REPO_PATH, module_path.lstrip("/"))
            )
        else:
            source = f"Metasploit ({key})"
            creation_date = None

        # fallback if date not found
        if not creation_date:
            creation_date = commit_iso

        for cve in sorted(cves):
            print(
                f"Found {cve} in {key} (file creation date {creation_date}) -> pushing sighting"
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

        added_keys = list(current.keys())
        for key in added_keys:
            entry = current.get(key, {})
            module_path = entry.get("path", "")
            if module_path:
                source = f"https://github.com/rapid7/metasploit-framework/blob/master{module_path}"
                _, creation_date = get_file_creation_commit_and_date(
                    os.path.join(REPO_PATH, module_path.lstrip("/"))
                )
            else:
                source = f"Metasploit ({key})"
                creation_date = None

            # fallback if no git info
            if not creation_date:
                creation_date = datetime.now(timezone.utc).isoformat()

            cves = find_cves_in_entry(entry)
            if not cves:
                # no CVE found, skip
                # print(f"No CVE found for {key}, skipping.")
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
        print(f"Commit {commit} added {len(added)} entries. Processing...")
        process_added_entries(added, this_version, commit_iso)

    log("info", "MetasploitSight execution completed.")


if __name__ == "__main__":
    # Point of entry in execution mode
    main()
