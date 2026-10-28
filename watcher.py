import os
import threading
import time
from collections import deque

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from alerts import send_alert
from config import load_config, should_ignore
from database import add_event, init_db
from fim import hash_file


class BurstDetector:
    """Raises an alert when many different files change in a short time."""

    def __init__(self, threshold=20, window=10, cooldown=60):
        self.threshold = threshold
        self.window = window
        self.cooldown = cooldown
        self.events = deque()
        self.last_alert = 0
        self.lock = threading.Lock()

    def add(self, path):
        """Returns the number of changed files if a burst is detected, else 0."""
        now = time.time()
        with self.lock:
            self.events.append((now, path))
            while self.events and now - self.events[0][0] > self.window:
                self.events.popleft()
            unique_files = len({p for _, p in self.events})
            if unique_files >= self.threshold and now - self.last_alert >= self.cooldown:
                self.last_alert = now
                self.events.clear()
                return unique_files
        return 0


class FimHandler(FileSystemEventHandler):
    def __init__(self, config, severity, burst):
        self.config = config
        self.severity = severity
        self.burst = burst
        self.last_seen = {}
        self.last_hash = {}

    def safe_hash(self, path):
        # Downloads may still be locked, so retry a few times
        for _ in range(5):
            try:
                return hash_file(path)
            except (PermissionError, FileNotFoundError):
                time.sleep(0.5)
        return ""

    def record(self, event_type, path, compute_hash=True):
        if should_ignore(path, self.config):
            return
        now = time.time()
        key = (event_type, path)
        if now - self.last_seen.get(key, 0) < 1:
            return  # duplicate event within 1 second
        self.last_seen[key] = now

        file_hash = self.safe_hash(path) if compute_hash else ""
        if event_type == "MODIFIED" and file_hash and self.last_hash.get(path) == file_hash:
            return  # content did not really change
        if file_hash:
            self.last_hash[path] = file_hash

        add_event(event_type, path, file_hash, self.severity)
        print(f"[{event_type}] ({self.severity}) {path}")

        if self.severity == "critical":
            send_alert(event_type, path, self.severity)

        count = self.burst.add(path)
        if count:
            message = f"{count} files changed within {self.burst.window} seconds"
            add_event("BURST", message, "", "critical")
            print(f"[BURST] (critical) {message} - possible ransomware-like activity")
            send_alert("BURST", message, "critical")

    def on_created(self, event):
        if not event.is_directory:
            self.record("ADDED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.record("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.record("DELETED", event.src_path, compute_hash=False)

    def on_moved(self, event):
        if not event.is_directory:
            self.record("MOVED", event.dest_path)


def main():
    config = load_config()
    if config is None:
        return
    init_db()

    settings = config.get("burst_detection", {})
    burst = BurstDetector(
        threshold=settings.get("threshold", 20),
        window=settings.get("window_seconds", 10),
        cooldown=settings.get("cooldown_seconds", 60),
    )
    print(f"[+] Burst detection: {burst.threshold} files in {burst.window}s")

    observer = Observer()
    watching = 0
    for item in config.get("monitored_folders", []):
        folder = item["path"]
        severity = item.get("severity", "normal")
        if not os.path.isdir(folder):
            print(f"[!] Folder not found, skipped: {folder}")
            continue
        observer.schedule(FimHandler(config, severity, burst), folder, recursive=True)
        print(f"[+] Watching: {folder} ({severity})")
        watching += 1

    if watching == 0:
        print("[!] No valid folders to watch. Check config.json.")
        return

    observer.start()
    print("Real-time monitoring started. Press Ctrl + C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopped.")
    observer.join()


if __name__ == "__main__":
    main()