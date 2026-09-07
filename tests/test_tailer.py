import os
import tempfile
import threading
import time
import unittest
from logsentinel.tailer import LogTailer


class TestLogTailer(unittest.TestCase):
    def setUp(self):
        try:
            self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        except TypeError:
            self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = os.path.join(self.temp_dir.name, "test_access.log")
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("line 1\n")

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_tail_from_beginning(self):
        tailer = LogTailer(self.log_file, from_beginning=True, poll_interval=0.05)
        lines = []

        def reader():
            for line in tailer.follow():
                lines.append(line)
                if len(lines) >= 3:
                    tailer.stop()

        t = threading.Thread(target=reader)
        t.start()

        time.sleep(0.1)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write("line 2\n")
            f.flush()
            time.sleep(0.1)
            f.write("line 3\n")
            f.flush()

        t.join(timeout=3)
        self.assertEqual(lines, ["line 1", "line 2", "line 3"])

    def test_tail_truncation_handling(self):
        tailer = LogTailer(self.log_file, from_beginning=True, poll_interval=0.05)
        lines = []

        def reader():
            for line in tailer.follow():
                lines.append(line)
                if line == "after truncate":
                    tailer.stop()

        t = threading.Thread(target=reader)
        t.start()

        time.sleep(0.1)
        # Truncate file to 0 bytes
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("")
        time.sleep(0.15)

        # Write new content after truncation
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write("after truncate\n")
            f.flush()

        t.join(timeout=3)
        self.assertIn("after truncate", lines)
