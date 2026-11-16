import sqlite3, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import logsentinel as ls


class TestParsers(unittest.TestCase):
    def test_failed_invalid_user(self):
        r = ls.parse_auth_line("Nov 14 03:12:01 web01 sshd[99]: Failed password for invalid user bob "
                               "from 203.0.113.5 port 4444 ssh2", 2026)
        self.assertEqual(r[3], "FAILED")
        self.assertEqual(r[4], "bob")
        self.assertEqual(r[5], "203.0.113.5")
        self.assertEqual(r[0], "2026-11-14T03:12:01")

    def test_accepted(self):
        r = ls.parse_auth_line("Nov 14 03:12:01 web01 sshd[99]: Accepted publickey for martin from 10.0.0.5 "
                               "port 5 ssh2", 2026)
        self.assertEqual((r[3], r[6]), ("ACCEPTED", "publickey"))

    def test_access(self):
        r = ls.parse_access_line('192.0.2.1 - - [14/Nov/2026:09:00:07 +0200] "GET /.env HTTP/1.1" 200 812 "-" "curl/8"')
        self.assertEqual(r[1:5], ("192.0.2.1", "GET", "/.env", 200))


class TestHunt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.con = ls.connect(Path(cls.tmp.name) / "t.db")
        ls.C.off()
        ls.ingest(cls.con, [ROOT / "samples/auth.log", ROOT / "samples/access.log"], 2026)
        cls.res = {r.id: rows for r, _, rows in ls.run_rules(cls.con, ls.load_rules(ROOT / "rules"))}

    def test_compromise_detected(self):
        self.assertEqual(self.res["R03"][0][0], "203.0.113.66")

    def test_spraying_detected(self):
        self.assertEqual(self.res["R02"][0][0], "198.51.100.23")

    def test_env_leak_detected(self):
        self.assertTrue(any(r[1] == "/.env" for r in self.res["R09"]))

    def test_all_rules_have_metadata(self):
        for r in ls.load_rules(ROOT / "rules"):
            self.assertIn(r.severity, ls.SEV_ORDER)
            self.assertTrue(r.mitre.startswith("T"))


if __name__ == "__main__":
    unittest.main()
