"""Log file follower / tailer handling real-time streaming, file growth, and rotation."""

import os
import time
from typing import Generator, Optional


class LogTailer:
    """Continuously follows and yields new lines added to a log file, similar to `tail -F`."""

    def __init__(self, filepath: str, from_beginning: bool = False, poll_interval: float = 0.2):
        self.filepath = filepath
        self.from_beginning = from_beginning
        self.poll_interval = poll_interval
        self._running = False
        self._current_inode: Optional[int] = None

    def _get_file_stat(self):
        try:
            return os.stat(self.filepath)
        except OSError:
            return None

    def follow(self) -> Generator[str, None, None]:
        """Yield lines from the log file as they are appended."""
        self._running = True

        # Wait until the file exists if starting up before web server creates it
        while self._running and not os.path.exists(self.filepath):
            time.sleep(self.poll_interval)

        if not self._running:
            return

        stat = self._get_file_stat()
        self._current_inode = stat.st_ino if stat and hasattr(stat, "st_ino") else None

        with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
            if not self.from_beginning:
                f.seek(0, os.SEEK_END)

            while self._running:
                line = f.readline()
                if line:
                    yield line.rstrip("\r\n")
                else:
                    # Check if file has been truncated or rotated
                    current_stat = self._get_file_stat()
                    if current_stat is None:
                        # File might have been temporarily deleted/rotated
                        time.sleep(self.poll_interval)
                        continue

                    # Condition 1: File size decreased (truncation / copytruncate)
                    if current_stat.st_size < f.tell():
                        f.seek(0, os.SEEK_SET)
                        continue

                    # Condition 2: File inode changed (logrotate create/rename)
                    current_inode = current_stat.st_ino if hasattr(current_stat, "st_ino") else None
                    if current_inode is not None and self._current_inode is not None and current_inode != self._current_inode:
                        f.close()
                        f = open(self.filepath, "r", encoding="utf-8", errors="replace")
                        self._current_inode = current_inode
                        continue

                    time.sleep(self.poll_interval)

    def stop(self):
        """Signal the tailer loop to terminate."""
        self._running = False
