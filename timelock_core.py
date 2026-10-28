"""
Time-Lock Folder - core engine (Level 1: local encrypted folder locker).

!! SECURITY LEVEL 1 - BYPASSABLE BY DESIGN !!
The unlock time is enforced only by this program, using the PC's clock.
Anyone who knows the password (or can change the clock / write a small script)
can open the vault early. This is a self-discipline tool, NOT protection
against a determined attacker.

SAFETY GUARANTEES
 * Original files are NEVER deleted, moved or modified.
 * Only temporary files this program itself created are removed.
 * Existing vaults / non-empty folders are never overwritten.
 * Every new vault is fully re-read and authenticated before it is accepted.

VAULT FORMAT (.tlvault)
 MAGIC(8) | header_len(4, big-endian) | header(JSON) | chunks...
 chunk = length(4) | AES-256-GCM(ciphertext+tag); key = scrypt(password, salt)
 AAD of each chunk = header bytes + chunk counter + final flag, so editing the
 header (e.g. the unlock time), reordering or truncating chunks is detected.
"""
import base64, json, os, secrets, struct, tempfile, time, unicodedata, zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"TLVAULT1"
CHUNK = 1024 * 1024
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MIN_PASSWORD_LEN = 8
MIN_LEAD_SECONDS = 60
EXT = ".tlvault"


class TimeLockError(Exception):
    pass


class TooEarlyError(TimeLockError):
    def __init__(self, unlock_ts):
        self.unlock_ts = unlock_ts
        super().__init__("This vault is still locked.")


class WrongPasswordError(TimeLockError):
    pass


def _noop(frac, text):
    pass


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_delta(seconds):
    seconds = max(0, int(seconds))
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    return f"{d}d {h:02d}h {m:02d}m {s:02d}s"


# ---------------------------------------------------------------- clock guard
def _state_path():
    base = os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "TimeLockFolder" / "state.json"


def record_time_seen(state_path=None, now=None):
    """Remember the latest clock reading (best-effort clock-rollback hint)."""
    p = Path(state_path) if state_path else _state_path()
    now = time.time() if now is None else now
    try:
        seen = json.loads(p.read_text()).get("max_seen", 0) if p.exists() else 0
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"max_seen": max(seen, now)}))
    except Exception:
        pass  # purely advisory


def clock_rolled_back(state_path=None, now=None, tolerance=300):
    p = Path(state_path) if state_path else _state_path()
    now = time.time() if now is None else now
    try:
        seen = json.loads(p.read_text()).get("max_seen", 0)
    except Exception:
        return False
    return now < seen - tolerance


# --------------------------------------------------------------------- crypto
def _derive(password, salt, n, r, p):
    pw = unicodedata.normalize("NFC", password).encode("utf-8")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(pw)


def _nonce(prefix, counter):
    return prefix + counter.to_bytes(8, "big")


def _aad(hb, counter, final):
    return hb + counter.to_bytes(8, "big") + (b"\x01" if final else b"\x00")


def read_header(vault_path):
    """Read the (unauthenticated) header. Safe to show to the user; no password needed."""
    with open(vault_path, "rb") as f:
        if f.read(len(MAGIC)) != MAGIC:
            raise TimeLockError("This is not a Time-Lock vault file (wrong file type).")
        raw = f.read(4)
        if len(raw) < 4:
            raise TimeLockError("Vault file is damaged (header too short).")
        (hl,) = struct.unpack(">I", raw)
        if hl > 65536:
            raise TimeLockError("Vault file is damaged (bad header size).")
        hb = f.read(hl)
        if len(hb) != hl:
            raise TimeLockError("Vault file is damaged (header truncated).")
        try:
            header = json.loads(hb)
        except ValueError:
            raise TimeLockError("Vault file is damaged (unreadable header).")
        return header, hb, len(MAGIC) + 4 + hl


def _encrypt_file(plain_path, out_path, password, unlock_ts, source_name, progress=_noop, files=None):
    salt, prefix = secrets.token_bytes(16), secrets.token_bytes(4)
    header = {
        "v": 1, "source_name": source_name, "created_ts": int(time.time()),
        "unlock_ts": int(unlock_ts), "files": files, "kdf": "scrypt",
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "salt": base64.b64encode(salt).decode(), "nonce_prefix": base64.b64encode(prefix).decode(),
    }
    hb = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    aes = AESGCM(_derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P))
    total = max(1, os.path.getsize(plain_path))
    done = 0
    with open(plain_path, "rb") as src, open(out_path, "xb") as out:
        out.write(MAGIC + struct.pack(">I", len(hb)) + hb)
        cur, counter = src.read(CHUNK), 0
        while True:
            nxt = src.read(CHUNK)
            final = not nxt
            ct = aes.encrypt(_nonce(prefix, counter), cur, _aad(hb, counter, final))
            out.write(struct.pack(">I", len(ct)) + ct)
            done += len(cur)
            progress(done / total, "Encrypting...")
            if final:
                break
            cur, counter = nxt, counter + 1
        out.flush()
        os.fsync(out.fileno())


def _decrypt_stream(vault_path, password, sink, progress=_noop, label="Decrypting..."):
    """Decrypt + authenticate every chunk; sink(bytes) receives plaintext."""
    header, hb, offset = read_header(vault_path)
    try:
        salt = base64.b64decode(header["salt"])
        prefix = base64.b64decode(header["nonce_prefix"])
        key = _derive(password, salt, int(header["n"]), int(header["r"]), int(header["p"]))
    except (KeyError, ValueError, TypeError):
        raise TimeLockError("Vault file is damaged (bad header fields).")
    aes = AESGCM(key)
    size = os.path.getsize(vault_path)
    with open(vault_path, "rb") as f:
        f.seek(offset)
        counter = 0
        while f.tell() < size:
            raw = f.read(4)
            if len(raw) < 4:
                raise TimeLockError("Vault file is truncated or damaged.")
            (ln,) = struct.unpack(">I", raw)
            if ln > CHUNK + 64:
                raise TimeLockError("Vault file is damaged (bad chunk size).")
            ct = f.read(ln)
            if len(ct) != ln:
                raise TimeLockError("Vault file is truncated or damaged.")
            final = f.tell() == size
            try:
                sink(aes.decrypt(_nonce(prefix, counter), ct, _aad(hb, counter, final)))
            except InvalidTag:
                if counter == 0:
                    raise WrongPasswordError(
                        "Wrong password - or the vault file was modified or damaged.")
                raise TimeLockError("Vault is damaged or truncated (integrity check failed).")
            counter += 1
            progress(f.tell() / size, label)
        if counter == 0:
            raise TimeLockError("Vault file contains no data.")
    return header


def verify_vault(vault_path, password, progress=_noop):
    return _decrypt_stream(vault_path, password, lambda b: None, progress, "Verifying backup copy...")


# ----------------------------------------------------------------- operations
def lock_folder(src, vault_path, password, unlock_ts, progress=_noop, min_lead=MIN_LEAD_SECONDS):
    """Encrypt a COPY of `src` into `vault_path`. Originals are left untouched."""
    src = Path(src).resolve()
    vault = Path(vault_path).resolve()
    if not src.is_dir():
        raise TimeLockError("The folder to lock does not exist.")
    if vault.suffix.lower() != EXT:
        raise TimeLockError(f"The vault file name must end with {EXT}")
    if vault.exists():
        raise TimeLockError("A file with that vault name already exists. Choose a new name - existing files are never overwritten.")
    if not vault.parent.is_dir():
        raise TimeLockError("The vault's destination folder does not exist.")
    if vault.is_relative_to(src):
        raise TimeLockError("The vault file must be saved OUTSIDE the folder you are locking.")
    if len(password) < MIN_PASSWORD_LEN:
        raise TimeLockError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if unlock_ts < time.time() + min_lead:
        raise TimeLockError("The unlock time must be at least 1 minute in the future.")

    partial = vault.with_name(vault.name + ".partial")
    if partial.exists():
        raise TimeLockError(f"Leftover file {partial.name} exists. Please inspect/rename it manually.")
    files = skipped = 0
    try:
        with tempfile.TemporaryDirectory(prefix="timelock_") as tmp:
            zpath = Path(tmp) / "data.zip"
            entries = []
            for root, dirs, fnames in os.walk(src, followlinks=False):
                keep = []
                for d in dirs:
                    if os.path.islink(os.path.join(root, d)):
                        skipped += 1
                    else:
                        keep.append(d)
                dirs[:] = keep
                entries.append((root, None))
                entries += [(root, n) for n in fnames]
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for i, (root, name) in enumerate(entries):
                    full = os.path.join(root, name) if name else root
                    arc = os.path.relpath(full, src)
                    if name is None:
                        if arc != ".":
                            zf.write(full, arc + "/")
                    elif os.path.islink(full):
                        skipped += 1
                    else:
                        zf.write(full, arc)
                        files += 1
                    progress(0.3 * (i + 1) / len(entries), "Reading files (copy only)...")
            _encrypt_file(zpath, partial, password, unlock_ts, src.name,
                          lambda f, t: progress(0.3 + 0.4 * f, t), files=files)
        verify_vault(partial, password, lambda f, t: progress(0.7 + 0.3 * f, t))
        os.replace(partial, vault)  # partial is our own file; target does not exist
    except BaseException:
        try:
            if partial.exists():
                partial.unlink()  # only our own unfinished output
        except OSError:
            pass
        raise
    progress(1.0, "Done")
    return {"vault": str(vault), "files": files, "skipped_links": skipped,
            "bytes": vault.stat().st_size}


def _safe_extract(zip_path, dest, progress=_noop):
    dest = Path(dest).resolve()
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        for i, info in enumerate(infos):
            target = (dest / info.filename).resolve()
            if not target.is_relative_to(dest):
                raise TimeLockError("Vault contains an unsafe path; extraction stopped.")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as s, open(target, "xb") as d:
                    while True:
                        b = s.read(CHUNK)
                        if not b:
                            break
                        d.write(b)
            progress(i + 1, len(infos))


def unlock_vault(vault_path, password, dest, progress=_noop, now=None, state_path=None):
    """Decrypt into `dest` (must be new or empty) once the deadline has passed."""
    header, _, _ = read_header(vault_path)
    now = time.time() if now is None else now
    if clock_rolled_back(state_path, now):
        raise TimeLockError("Your system clock appears to have been set backwards. "
                            "Unlock refused. Fix the clock and try again.")
    if now < header.get("unlock_ts", 0):
        raise TooEarlyError(header["unlock_ts"])
    dest = Path(dest)
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise TimeLockError("Destination must be a NEW or EMPTY folder (nothing is ever overwritten).")
    with tempfile.TemporaryDirectory(prefix="timelock_") as tmp:
        zpath = Path(tmp) / "data.zip"
        with open(zpath, "wb") as zf:
            _decrypt_stream(vault_path, password, zf.write,
                            lambda f, t: progress(0.6 * f, t))
        dest.mkdir(parents=True, exist_ok=True)
        _safe_extract(zpath, dest, lambda i, n: progress(0.6 + 0.4 * i / max(1, n), "Extracting..."))
    restored = sum(1 for p in dest.rglob("*") if p.is_file())
    expected = header.get("files")
    if expected is not None and restored != expected:
        raise TimeLockError(f"Restored {restored} files but the vault holds {expected}. "
                            f"Check {dest} and keep the vault file.")
    progress(1.0, "Done")
    return {"dest": str(dest), "restored": restored, "expected": expected}


# ------------------------------------------------------------ diagnostics
def log_path():
    return _state_path().with_name("log.txt")


def log_error(text):
    try:
        p = log_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"[{fmt_ts(time.time())}]\n{text}\n\n")
    except Exception:
        pass


def self_test():
    """Full lock -> early-refuse -> wrong-password -> unlock -> compare, in a temp folder.
    Uses fake test data only; never touches your real files. Returns (ok, report)."""
    import hashlib, platform, sys, traceback
    lines = [f"Python {sys.version.split()[0]} on {platform.platform()}"]
    try:
        with tempfile.TemporaryDirectory(prefix="timelock_selftest_") as td:
            t = Path(td)
            src = t / "Test Folder ü"
            (src / "sub dir").mkdir(parents=True)
            (src / "empty").mkdir()
            (src / "a.txt").write_text("hello ü")
            (src / "sub dir" / "big.bin").write_bytes(os.urandom(2_500_000))
            digest = lambda d: {str(f.relative_to(d)): hashlib.sha256(f.read_bytes()).hexdigest()
                                for f in Path(d).rglob("*") if f.is_file()}
            v, st = t / "t.tlvault", t / "state.json"
            lock_folder(src, v, "selftest-pass", time.time() + 5, min_lead=0)
            lines.append("OK  vault created and verified")
            try:
                unlock_vault(v, "selftest-pass", t / "o1", state_path=st)
                return False, "\n".join(lines + ["FAIL vault opened BEFORE deadline"])
            except TooEarlyError:
                lines.append("OK  early unlock refused")
            try:
                unlock_vault(v, "wrong-pass-xx", t / "o2", now=time.time() + 60, state_path=st)
                return False, "\n".join(lines + ["FAIL wrong password accepted"])
            except WrongPasswordError:
                lines.append("OK  wrong password refused")
            unlock_vault(v, "selftest-pass", t / "o3", now=time.time() + 60, state_path=st)
            same = digest(src) == digest(t / "o3") and (t / "o3" / "empty").is_dir()
            lines.append(("OK  " if same else "FAIL ") + "restored files are identical to the originals")
            return same, "\n".join(lines)
    except Exception:
        return False, "\n".join(lines + ["FAIL unexpected error:", traceback.format_exc()])


if __name__ == "__main__":
    ok, rep = self_test()
    print(rep)
    print("\nSELF-TEST " + ("PASSED" if ok else "FAILED"))
