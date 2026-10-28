import os, sys, tempfile, time, unittest, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import timelock_core as c


def tree(p):
    return {str(f.relative_to(p)): f.read_bytes() for f in Path(p).rglob("*") if f.is_file()}


class T(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.t = Path(self.td.name)
        self.src = self.t / "src"
        (self.src / "sub").mkdir(parents=True)
        (self.src / "a.txt").write_text("hello")
        (self.src / "sub" / "b.bin").write_bytes(os.urandom(3_000_000))
        (self.src / "empty").mkdir()
        self.state = self.t / "state.json"
        self.before = tree(self.src)

    def tearDown(self):
        self.td.cleanup()

    def lock(self, ts=None, pw="correct horse"):
        v = self.t / "v.tlvault"
        c.lock_folder(self.src, v, pw, ts or time.time() + 3600)
        return v

    def test_roundtrip_and_originals_untouched(self):
        v = self.lock()
        self.assertEqual(self.before, tree(self.src))
        out = self.t / "out"
        c.unlock_vault(v, "correct horse", out, now=time.time() + 7200, state_path=self.state)
        self.assertEqual(self.before, tree(out))
        self.assertTrue((out / "empty").is_dir())
        self.assertEqual(self.before, tree(self.src))

    def test_too_early(self):
        v = self.lock()
        with self.assertRaises(c.TooEarlyError):
            c.unlock_vault(v, "correct horse", self.t / "o", state_path=self.state)
        self.assertFalse((self.t / "o").exists())

    def test_wrong_password(self):
        v = self.lock()
        with self.assertRaises(c.WrongPasswordError):
            c.unlock_vault(v, "nope nope nope", self.t / "o", now=time.time() + 7200, state_path=self.state)

    def test_header_tamper_detected(self):
        v = self.lock()
        data = bytearray(v.read_bytes())
        hdr, _, _ = c.read_header(v)
        i = data.find(b'"unlock_ts":' + str(hdr["unlock_ts"]).encode())
        data[i + 12] ^= 1  # flip a digit
        v.write_bytes(bytes(data))
        with self.assertRaises(c.TimeLockError):
            c.unlock_vault(v, "correct horse", self.t / "o", now=time.time() + 10**9, state_path=self.state)

    def test_truncation_and_corruption(self):
        v = self.lock()
        data = v.read_bytes()
        (self.t / "t.tlvault").write_bytes(data[:-5000])
        (self.t / "c.tlvault").write_bytes(data[:-100] + bytes(x ^ 1 for x in data[-100:]))
        for n in ("t", "c"):
            with self.assertRaises(c.TimeLockError):
                c.unlock_vault(self.t / f"{n}.tlvault", "correct horse", self.t / f"o{n}",
                               now=time.time() + 7200, state_path=self.state)

    def test_refuses_overwrite_and_nonempty_dest(self):
        v = self.lock()
        with self.assertRaises(c.TimeLockError):
            c.lock_folder(self.src, v, "correct horse", time.time() + 3600)
        with self.assertRaises(c.TimeLockError):
            c.unlock_vault(v, "correct horse", self.src, now=time.time() + 7200, state_path=self.state)

    def test_vault_inside_source_and_short_password_and_past_time(self):
        for args in [(self.src / "x.tlvault", "correct horse", time.time() + 3600),
                     (self.t / "y.tlvault", "short", time.time() + 3600),
                     (self.t / "z.tlvault", "correct horse", time.time() + 5)]:
            with self.assertRaises(c.TimeLockError):
                c.lock_folder(self.src, *args)
        self.assertEqual(self.before, tree(self.src))

    def test_zip_slip_blocked(self):
        z = self.t / "evil.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("../evil.txt", "x")
        v = self.t / "e.tlvault"
        c._encrypt_file(z, v, "correct horse", time.time() - 10, "evil")
        with self.assertRaises(c.TimeLockError):
            c.unlock_vault(v, "correct horse", self.t / "o", state_path=self.state)
        self.assertFalse((self.t / "evil.txt").exists())

    def test_clock_rollback(self):
        c.record_time_seen(self.state, now=time.time() + 86400)
        v = self.lock()
        with self.assertRaises(c.TimeLockError):
            c.unlock_vault(v, "correct horse", self.t / "o", now=time.time() + 7200, state_path=self.state)

    def test_not_a_vault(self):
        (self.t / "n.tlvault").write_bytes(b"junk")
        with self.assertRaises(c.TimeLockError):
            c.read_header(self.t / "n.tlvault")


if __name__ == "__main__":
    unittest.main(verbosity=2)
