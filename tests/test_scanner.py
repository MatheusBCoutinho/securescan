from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from securescan.scanner import scan_file, scan_path


class ScannerTests(unittest.TestCase):
    def test_detects_eval_and_secret(self):
        with TemporaryDirectory() as folder:
            file = Path(folder) / "bad.py"
            file.write_text('password = "verysecretpassword"\neval("2+2")\n')
            rules = {finding["rule"] for finding in scan_file(file)}
            self.assertIn("POSSIBLE_SECRET", rules)
            self.assertIn("DYNAMIC_EXEC", rules)

    def test_clean_file(self):
        with TemporaryDirectory() as folder:
            file = Path(folder) / "clean.py"
            file.write_text('print("hello")\n')
            self.assertEqual(scan_path(file), [])

    def test_skip_virtualenv(self):
        with TemporaryDirectory() as folder:
            hidden = Path(folder) / ".venv"
            hidden.mkdir()
            (hidden / "bad.py").write_text('eval("1")')
            self.assertEqual(scan_path(Path(folder)), [])


if __name__ == "__main__":
    unittest.main()
