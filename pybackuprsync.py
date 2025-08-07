# =============================================================================
# SOURCES AND REFERENCES USED IN THIS SCRIPT
# =============================================================================
# - Python Standard Library:
#   • argparse – for command-line interface parsing
#     https://docs.python.org/3/library/argparse.html
#   • threading – for concurrent execution of backup jobs
#     https://docs.python.org/3/library/threading.html
#   • subprocess – for executing and capturing rsync commands
#     https://docs.python.org/3/library/subprocess.html
#   • hashlib – for generating SHA256 hashes of file content
#     https://docs.python.org/3/library/hashlib.html
#   • json – for reading and writing persistent hash cache files
#     https://docs.python.org/3/library/json.html
#   • pathlib – for robust cross-platform file path manipulation
#     https://docs.python.org/3/library/pathlib.html
#   • datetime – for timestamps in log and report files
#     https://docs.python.org/3/library/datetime.html
#   • os – for filesystem interaction (e.g., deleting files)
#     https://docs.python.org/3/library/os.html
#
# - Rsync command line utility:
#   • rsync command reference and flags documentation
#     https://linux.die.net/man/1/rsync
#
# - Cryptographic best practices:
#   • SHA256 hash comparison to detect content-based changes
#     https://csrc.nist.gov/publications/detail/fips/180/4/final
#
# - Hash caching pattern:
#   • Use of mtime + hash to avoid rehashing unchanged files
#     Inspired by tools like restic, rsync checksum mode, and content-based versioning
#
# - Logging best practices for threaded apps:
#   • Thread-safe file writing using threading.Lock
#     https://docs.python.org/3/library/threading.html#lock-objects
#
# - Backup design inspiration:
#   • Incremental/differential backup concepts
#     https://www.borgbackup.org/manual.html
#     https://restic.readthedocs.io/en/latest/
#
# - Author: ChatGPT (OpenAI), conversation with user (Scott), August 2025
# =============================================================================

#! /usr/bin/env python3
import argparse
import hashlib
import subprocess
import datetime
import json
import os
from pathlib import Path
from threading import Thread, Lock

log_lock = Lock()
hash_lock = Lock()
report_lock = Lock()

def log(message: str, log_path: Path = None):
    with log_lock:
        print(message)
        if log_path:
            with open(log_path, "a") as f:
                f.write(f"{message}\n")

def report(message: str, report_path: Path):
    with report_lock:
        with open(report_path, "a") as f:
            f.write(f"{message}\n")

def hash_file(path: Path) -> str:
    """Return SHA256 hash of a file."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def load_hash_cache(cache_path: Path) -> dict:
    if cache_path.exists():
        with open(cache_path, "r") as f:
            return json.load(f)
    return {}

def save_hash_cache(cache: dict, cache_path: Path):
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)

def compare_by_hash_with_cache(src_file: Path, dest_file: Path, cache: dict, backed_up: list, skipped: list) -> bool:
    key = str(src_file)
    src_mtime = src_file.stat().st_mtime

    cached = cache.get(key)
    if cached and cached["mtime"] == src_mtime:
        skipped.append(str(src_file))
        return False  # Cached and unchanged

    file_hash = hash_file(src_file)
    if not file_hash:
        backed_up.append(str(src_file))
        return True  # Treat error as changed

    if not dest_file.exists():
        backed_up.append(str(src_file))
        return True

    dest_hash = hash_file(dest_file)
    if file_hash != dest_hash:
        backed_up.append(str(src_file))
        return True

    with hash_lock:
        cache[key] = {"mtime": src_mtime, "hash": file_hash}

    skipped.append(str(src_file))
    return False

def gather_changed_files_with_cache(source: Path, dest: Path, cache: dict, backed_up: list, skipped: list) -> list:
    changed_files = []
    for src_file in source.rglob("*"):
        if src_file.is_file():
            relative = src_file.relative_to(source)
            dest_file = dest / relative
            if compare_by_hash_with_cache(src_file, dest_file, cache, backed_up, skipped):
                changed_files.append(str(relative))
    return changed_files

def build_rsync_flags(dry_run: bool, compress: bool) -> list:
    flags = ["-avh", "--delete", "--update", "--progress"]
    if dry_run:
        flags.append("--dry-run")
    if compress:
        flags.append("-z")
    return flags

def run_backup(source: Path, dest: Path, flags: list, log_path: Path, cache: dict, cache_path: Path, report_path: Path):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"\n[{timestamp}] Backing up from {source} to {dest}", log_path)

    if not source.exists():
        log(f"Source folder does not exist: {source}", log_path)
        return

    dest.mkdir(parents=True, exist_ok=True)

    log("Comparing files using hash cache...", log_path)
    backed_up_files = []
    skipped_files = []
    changed_files = gather_changed_files_with_cache(source, dest, cache, backed_up_files, skipped_files)

    if not changed_files:
        log("No changed files detected. Skipping rsync.", log_path)
    else:
        rsync_cmd = ["rsync"] + flags + [str(source) + "/", str(dest)]
        log(f"Executing: {' '.join(rsync_cmd)}", log_path)

        try:
            process = subprocess.Popen(
                rsync_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            for line in process.stdout:
                log(line.strip(), log_path)
            process.wait()
            if process.returncode == 0:
                status = "Backup completed." if "--dry-run" not in flags else "Dry-run completed."
                log(status, log_path)
            else:
                log(f"Rsync exited with code {process.returncode}", log_path)
        except Exception as e:
            log(f"Rsync failed: {e}", log_path)

    with hash_lock:
        save_hash_cache(cache, cache_path)

    # Write report
    report(f"\n--- Backup Report for {source} → {dest} ---", report_path)
    report(f"Files backed up: {len(backed_up_files)}", report_path)
    for file in backed_up_files:
        report(f"[BACKED UP] {file}", report_path)
    report(f"Files skipped (unchanged): {len(skipped_files)}", report_path)
    for file in skipped_files:
        report(f"[SKIPPED]   {file}", report_path)

def load_jobs_from_json(json_path: str):
    with open(json_path, "r") as f:
        return json.load(f)

def flush_cache(cache_path: Path):
    if cache_path.exists():
        print("\n!!! WARNING: You have requested to flush the hash cache. !!!")
        print("This will force all files to be re-evaluated and re-hashed.")
        print("This is typically used when changing backup structure or policies.\n")
        confirm = input("Are you SURE you want to delete the cache file? Type YES to continue: ").strip()
        if confirm == "YES":
            cache_path.unlink()
            print(f"Cache file {cache_path} deleted.\n")
        else:
            print("Cache flush aborted by user.\n")

def main():
    parser = argparse.ArgumentParser(description="Threaded rsync backup with hash cache and reporting.")
    parser.add_argument("--json", help="Path to JSON file with backup jobs")
    parser.add_argument("--dry-run", action="store_true", help="Only simulate changes")
    parser.add_argument("--compress", action="store_true", help="Enable compression")
    parser.add_argument("--flush-cache", action="store_true", help="Delete and reset the hash cache file")
    parser.add_argument("--log-file", default=f"backup_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", help="Log file path")
    parser.add_argument("--report-file", default="backup_report.txt", help="Report file listing files backed up vs skipped")
    parser.add_argument("--hash-cache", default="hash_cache.json", help="Path to hash cache file")
    parser.add_argument("--source", help="Single source path")
    parser.add_argument("--dest", help="Single destination path")

    args = parser.parse_args()
    log_path = Path(args.log_file)
    report_path = Path(args.report_file)
    cache_path = Path(args.hash_cache)

    if args.flush_cache:
        flush_cache(cache_path)

    rsync_flags = build_rsync_flags(args.dry_run, args.compress)
    hash_cache = load_hash_cache(cache_path)

    jobs = []
    if args.json:
        job_entries = load_jobs_from_json(args.json)
        for entry in job_entries:
            jobs.append((Path(entry["source"]), Path(entry["dest"])))
    elif args.source and args.dest:
        jobs.append((Path(args.source), Path(args.dest)))
    else:
        parser.error("Must provide either --json or both --source and --dest.")

    log(f"Backup session started at {datetime.datetime.now()}", log_path)
    threads = []
    for src, dst in jobs:
        t = Thread(target=run_backup, args=(src, dst, rsync_flags, log_path, hash_cache, cache_path, Path(report_path)))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    log("All threaded backup jobs completed.", log_path)
    print(f"\nReport saved to: {report_path}")

if __name__ == "__main__":
    main()
