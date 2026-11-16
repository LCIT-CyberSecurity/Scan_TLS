from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReportNavigationTests(unittest.TestCase):
    def test_endpoint_drawer_does_not_block_report_section_links(self):
        css = (ROOT / "tls_scanner/exports/assets/html/css/report.css").read_text()
        script = (ROOT / "tls_scanner/exports/assets/html/js/report.js").read_text()

        shell = re.search(r"\.app-shell\.drawer-open\s*\{[^}]*z-index:\s*(\d+)", css)
        backdrop = re.search(r"\.drawer-backdrop\s*\{[^}]*z-index:\s*(\d+)", css)
        self.assertIsNotNone(shell)
        self.assertIsNotNone(backdrop)
        self.assertGreater(int(shell.group(1)), int(backdrop.group(1)))
        self.assertIn("links.forEach((link) => link.addEventListener('click', closeDrawer))", script)
        self.assertGreaterEqual(script.count("classList.add('drawer-open')"), 2)
        self.assertIn("classList.remove('drawer-open')", script)


if __name__ == "__main__":
    unittest.main()
