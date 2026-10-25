import argparse
import hashlib
import hmac
import json
import os
from datetime import datetime

BASELINE = "baseline.json"
KEY = os.environ.get("FIM_KEY", "").encode()


# ---------- Hashing ----------
def hash_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def file_info(path):
    st = os.stat(path)
    return {
        "hash": hash_file(path),
        "mode": oct(st.st_mode & 0o777),
        "uid": st.st_uid,
        "mtime": int(st.st_mtime),
    }


# ---------- Scanning ----------
def scan_folder(folder):
    result = {}
    for root, _, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            try:
                result[path] = file_info(path)
            except (PermissionError, FileNotFoundError) as e:
                print(f"[!] Skipped {path}: {e}")
    return result


# ---------- Baseline (signed) ----------
def sign(data):
    return hmac.new(KEY, data.encode(), hashlib.sha256).hexdigest()


def save_baseline(info):
    data = json.dumps(info, indent=4, sort_keys=True)
    with open(BASELINE, "w") as f:
        f.write(data)
    with open(BASELINE + ".sig", "w") as f:
        f.write(sign(data))


def load_baseline():
    try:
        with open(BASELINE) as f:
            data = f.read()
        with open(BASELINE + ".sig") as f:
            sig = f.read()
    except FileNotFoundError:
        print("[!] Baseline or signature missing. Run 'baseline' first.")
        return None
    if not hmac.compare_digest(sig, sign(data)):
        print("[!] ALERT: baseline has been TAMPERED with!")
        return None
    return json.loads(data)


# ---------- Compare ----------
def compare(old, new):
    modified = [p for p in new if p in old and new[p]["hash"] != old[p]["hash"]]
    meta = [
        p for p in new
        if p in old and new[p]["hash"] == old[p]["hash"]
        and (new[p]["mode"] != old[p]["mode"]
             or new[p]["uid"] != old[p]["uid"]
             or new[p]["mtime"] != old[p]["mtime"])
    ]
    added = [p for p in new if p not in old]
    deleted = [p for p in old if p not in new]
    return modified, added, deleted, meta


# ---------- Logging ----------
def log(message):
    with open("fim.log", "a") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n")


# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("mode", choices=["baseline", "check"])
    parser.add_argument("folder")
    args = parser.parse_args()

    if not KEY:
        print("[!] Set the secret key first: set FIM_KEY=your-secret")
        return
    if not os.path.isdir(args.folder):
        print(f"[!] Folder not found: {args.folder}")
        return

    current = scan_folder(args.folder)

    if args.mode == "baseline":
        save_baseline(current)
        print(f"[+] Baseline saved for {len(current)} files.")
        log(f"BASELINE created ({len(current)} files)")
        return

    old = load_baseline()
    if old is None:
        return

    modified, added, deleted, meta = compare(old, current)

    for p in modified:
        print(f"[MODIFIED] {p}")
        log(f"MODIFIED {p}")
    for p in added:
        print(f"[ADDED]    {p}")
        log(f"ADDED {p}")
    for p in deleted:
        print(f"[DELETED]  {p}")
        log(f"DELETED {p}")
    for p in meta:
        print(f"[METADATA] {p}")
        log(f"METADATA {p}")

    if not (modified or added or deleted or meta):
        print("[OK] No changes detected.")


if __name__ == "__main__":
    main()