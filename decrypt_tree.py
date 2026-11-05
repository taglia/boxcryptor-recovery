#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography>=41"]
# ///
"""
decrypt_tree.py -- offline, standalone decryption of a whole Boxcryptor 2.x tree (contents AND names).

    python3 -I decrypt_tree.py [options] <ENCRYPTED_ROOT_DIR>      # any Python 3.10+ with `cryptography`
    uv run decrypt_tree.py [options] <ENCRYPTED_ROOT_DIR>          # or let uv read the inline metadata above

Defaults: `key.bckey` is looked up in the current directory, then next to this script.  The password is
prompted for (never echoed) unless a file is given with --password-file.
Output goes to a SIBLING of ENCRYPTED_ROOT_DIR named with the decrypted folder name
(e.g.  .../倐姁宸壮凕娗吓墭塽堦䃸/  ->  .../My Backup/), unless --dest-parent is given.

Options:
  --key FILE             key export (.bckey)                 [./key.bckey or <script dir>/key.bckey]
  --password-file FILE   read the password from this file (first line) instead of prompting
  --dest-parent DIR      where to create the decrypted root  [parent of ENCRYPTED_ROOT_DIR]
  --workers N            parallel content-decryption processes [number of CPUs]
  --dry-run              only resolve names and print the plan; write nothing
  --overwrite            re-decrypt files that already exist with the right size (default: skip = resume)
  --no-copy-plain        do not copy non-.bc files (FolderKey.bch is never copied)
  --no-preserve-mtime    do not copy modification times
  --verbose              print every decrypted file on the console (always written to the log file)
  --log FILE             log file                            [<dest root>/_boxcryptor_decrypt.log]

The console shows a progress bar by number of files (plus bytes, throughput and ETA); the log file has one
line per file with the encrypted -> decrypted name, size and SHA-256 prefix.

Format (verified on real data, see the repo NOTES.md):
  * key export: UTF-8 BOM JSON; PBKDF2-HMAC-SHA512(password, salt, kdfIterations) -> 64 B = AES|HMAC key pair.
    "Wrapped blob" = IV[16] | HMAC-SHA256(ct)[32] | AES-256-CBC/PKCS7 ct.  Password pair decrypts privateKey
    (base64 PKCS#8 DER) and wrappingKey (64 B pair); the wrappingKey pair decrypts keys.filename (64 B pair).
  * .bc / .bch container: "bc01" | u32 core_len | u32 pad_len | u32 cipher_pad | 32 B; JSON header at 48;
    data blocks of `blockSize` from offset 48+core+pad; per-block IV = HMAC-SHA256(K, iv || LE64(block))[:16];
    AES-256-CBC with K = RSA-OAEP-SHA1(encryptedFileKeys[user].value)[32:64]; PKCS7 only on the last block.
  * names: Base4K(legacy alphabet) of  01 | fold8(userId) | HMAC-SHA256(Kh, name)[:5] | FilenameCipher(name)
    where (Ke, Kh) = keys.filename pair; FilenameCipher = two passes of AES-256-CFB128 with XOR chaining and
    64-byte chunk reversal, IVs derived from the 5-byte tag.  "~$" prefix and ".bc" suffix stay in clear.

Security: never prints or logs passwords or key material. Output files are created mode 0600 (dirs 0700).
"""
import argparse
import base64
import getpass
import concurrent.futures as cf
import hashlib
import hmac as _hmac
import json
import os
import shutil
import struct
import sys
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
try:
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB   # cryptography >= 48
except ImportError:                                                     # older releases
    _CFB = modes.CFB

_B = default_backend()
BC_EXT = ".bc"
FOLDER_KEY_FILE = "FolderKey.bch"
READ_BLOCKS = 256          # blocks per read from the (network) source: 256 * 4096 = 1 MiB


# ============================================================================================ Base4K
_B4K_FLAG, _B4K_FLAG_SIZE, _B4K_SIZE = 0x4000, 0x100, 0x5000
_B4K_BASES = (0x6000, 0x5000)   # current alphabet first, then legacy (what Boxcryptor 2.x actually wrote)


class Base4KError(ValueError):
    pass


def _b4k_decode(s, base):
    out, code, n = bytearray(), 0, len(s)
    for i, ch in enumerate(s):
        prev, code = code, ord(ch)
        if not (base <= code < base + _B4K_SIZE):
            if i < n - 1 or not (_B4K_FLAG <= code < _B4K_FLAG + _B4K_FLAG_SIZE):
                raise Base4KError("invalid code point U+%04X" % code)
        if code >= base:
            code -= base
        else:
            code -= _B4K_FLAG
            out.append(code & 0xFF if i % 2 == 0 else ((prev << 4) | (code & 0x0F)) & 0xFF)
            break
        if i % 2 == 0:
            out.append((code >> 4) & 0xFF)
        else:
            out.append(((prev << 4) | ((code & 0x0F00) >> 8)) & 0xFF)
            out.append(code & 0xFF)
    return bytes(out)


def base4k_decode(s):
    for base in _B4K_BASES:
        try:
            return _b4k_decode(s, base)
        except Base4KError:
            pass
    raise Base4KError("not a Base4K string")


def base4k_encode(data, legacy=True):
    """Port of the reference encoder (secomba/base4k). legacy=True -> the 0x5000 alphabet Boxcryptor 2.x wrote."""
    base = 0x5000 if legacy else 0x6000
    out, n, i = [], len(data), 0
    while i < n * 2 - 2:
        if i % 2 == 0:
            off = ((data[i >> 1] << 4) | ((data[(i >> 1) + 1] >> 4) & 0x0F)) & 0x0FFF
        else:
            off = ((data[(i - 1) >> 1] << 8) | (data[(i + 1) >> 1] & 0xFF)) & 0x0FFF
        out.append(chr(off + base))
        i += 3
    if (n << 1) % 3 == 2:
        out.append(chr((data[n - 1] & 0xFF) + _B4K_FLAG))
    elif (n << 1) % 3 == 1:
        out.append(chr((data[n - 1] & 0x0F) + _B4K_FLAG))
    return "".join(out)


# ========================================================================================= key chain
def load_user(bckey_path):
    with open(bckey_path, encoding="utf-8-sig") as f:
        kj = json.load(f)
    users = kj.get("users", [])
    if len(users) != 1:
        sys.exit("STOP: key file has %d users; this tool handles exactly one" % len(users))
    if kj.get("groups") or kj.get("groupMemberships") or kj.get("organization", {}).get("keys"):
        sys.exit("STOP: key file contains group/organization keys; not supported")
    return users[0]


def decrypt_wrapped(blob, aes_key, mac_key):
    iv, mac, ct = blob[:16], blob[16:48], blob[48:]
    h = hmac.HMAC(mac_key, hashes.SHA256(), _B)
    h.update(ct)
    h.verify(mac)
    dec = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=_B).decryptor()
    pt = dec.update(ct) + dec.finalize()
    pad = pt[-1]
    if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad PKCS7 padding")
    return pt[:-pad]


def unwrap_user_keys(user, password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=base64.b64decode(user["salt"]),
                     iterations=user["kdfIterations"], backend=_B)
    pk = kdf.derive(password.encode("utf-8"))
    aes_k, mac_k = pk[:32], pk[32:]
    priv_b64 = decrypt_wrapped(base64.b64decode(user["privateKey"]), aes_k, mac_k)
    priv = serialization.load_der_private_key(base64.b64decode(priv_b64), None, _B)
    pub = serialization.load_der_public_key(base64.b64decode(user["publicKey"]), _B)
    if priv.public_key().public_numbers() != pub.public_numbers():
        sys.exit("STOP: decrypted private key does not match publicKey (wrong password?)")
    wrapping = decrypt_wrapped(base64.b64decode(user["wrappingKey"]), aes_k, mac_k)
    fn_wrapped = user.get("keys", {}).get("filename")
    fn_key = decrypt_wrapped(base64.b64decode(fn_wrapped), wrapping[:32], wrapping[32:64]) if fn_wrapped else None
    return priv, fn_key


def unwrap_file_key(priv, header, user_id):
    for efk in header.get("encryptedFileKeys", []):
        if efk.get("id") == user_id:
            return priv.decrypt(base64.b64decode(efk["value"]),
                                apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
    return None


# ======================================================================================= name cipher
def _fold_ulong(b):
    arr = bytearray(8)
    for i in range(len(b) - 1):       # the client skips the last byte
        arr[i % 8] ^= b[i]
    return int.from_bytes(arr, "big")


def key_holder_hash(key_holder_id):
    n = _fold_ulong(key_holder_id.encode("utf-8"))
    n = ((n >> 32) ^ n) & 0xFFFFFFFF
    n = ((n >> 16) ^ n) & 0xFFFF
    return ((n >> 8) ^ n) & 0xFF


def _h256(key, data):
    return _hmac.new(key, data, hashlib.sha256).digest()


def _setivec(ivbase, seed, enc_key):
    return _h256(enc_key, ivbase + (seed & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))[:16]


def _cfb_dec(k, iv, data):
    d = Cipher(algorithms.AES(k), _CFB(iv), backend=_B).decryptor()
    return d.update(data) + d.finalize()


def _unxor_chain(b):
    b = bytearray(b)
    for n in range(len(b) - 1, 0, -1):
        b[n] ^= b[n - 1]
    return bytes(b)


def _rev64(b):
    return b"".join(b[i:i + 64][::-1] for i in range(0, len(b), 64))


class NameError_(ValueError):
    pass


def decrypt_name(encoded, fn_key, user_id):
    enc_k, hash_k = fn_key[:32], fn_key[32:]
    raw = base4k_decode(encoded)
    if len(raw) < 8 or raw[0] != 1:
        raise NameError_("not a v1 encrypted name")
    if raw[1] != key_holder_hash(user_id):
        raise NameError_("encrypted for another key holder")
    mac5, ct = raw[2:7], raw[7:]
    ivbase = _h256(hash_k, mac5)[:16]
    n = _fold_ulong(ivbase)
    p = _rev64(_unxor_chain(_cfb_dec(enc_k, _setivec(ivbase, n + 1, enc_k), ct)))
    p = _unxor_chain(_cfb_dec(enc_k, _setivec(ivbase, n, enc_k), p))
    if _h256(hash_k, p)[:5] != mac5:
        raise NameError_("name MAC mismatch")
    return p.decode("utf-8")


def _cfb_enc(k, iv, data):
    e = Cipher(algorithms.AES(k), _CFB(iv), backend=_B).encryptor()
    return e.update(data) + e.finalize()


def _xor_chain(b):
    b = bytearray(b)
    for i in range(len(b) - 1):
        b[i + 1] ^= b[i]
    return bytes(b)


def encrypt_name(plain, fn_key, user_id, legacy=True):
    """Inverse of decrypt_name (what the client does). Used by the tests and to build synthetic vaults."""
    enc_k, hash_k = fn_key[:32], fn_key[32:]
    p = plain.encode("utf-8")
    mac5 = _h256(hash_k, p)[:5]
    ivbase = _h256(hash_k, mac5)[:16]
    n = _fold_ulong(ivbase)
    c = _cfb_enc(enc_k, _setivec(ivbase, n, enc_k), _xor_chain(p))
    c = _cfb_enc(enc_k, _setivec(ivbase, n + 1, enc_k), _xor_chain(_rev64(c)))
    return base4k_encode(bytes([1, key_holder_hash(user_id)]) + mac5 + c, legacy=legacy)


def sanitize(name):
    name = name.replace("/", "_").replace("\0", "")
    if name in ("", ".", ".."):
        name = "_" + name
    return name


# ======================================================================================== container
def read_header(path):
    with open(path, "rb") as f:
        raw = f.read(16)
        if raw[:4] != b"bc01":
            raise ValueError("not a bc01 container")
        core, pad, cpad = struct.unpack("<III", raw[4:16])
        f.seek(48)
        hdr = json.loads(f.read(core))
    return hdr, 48 + core + pad, cpad


_PRIV = None          # per worker process: the user's RSA private key (loaded once by _init_worker)


def _init_worker(priv_der):
    global _PRIV
    _PRIV = serialization.load_der_private_key(priv_der, None, _B)


def decrypt_content(src, dst, offset, cpad, iv, efk_b64, blocksize, mtime, preserve_mtime):
    """Worker: RSA-OAEP unwrap of the file key, then AES-256-CBC per block with HMAC-derived IVs.
    Returns (bytes_written, sha256hex)."""
    key = _PRIV.decrypt(base64.b64decode(efk_b64),
                        apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))[32:64]
    size = os.path.getsize(src)
    enc_len = max(0, size - offset)
    nblocks = (enc_len + blocksize - 1) // blocksize
    aes = algorithms.AES(key)
    sha = hashlib.sha256()
    written = 0
    tmp = dst + ".part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(src, "rb") as fin, os.fdopen(fd, "wb", buffering=1 << 20) as fout:
        fin.seek(offset)
        b = 0
        while b < nblocks:
            chunk = fin.read(blocksize * min(READ_BLOCKS, nblocks - b))
            if not chunk:
                raise IOError("short read in %s" % src)
            for o in range(0, len(chunk), blocksize):
                block = chunk[o:o + blocksize]
                biv = _h256(key, iv + b.to_bytes(8, "little"))[:16]
                d = Cipher(aes, modes.CBC(biv), backend=_B).decryptor()
                pt = d.update(block) + d.finalize()
                b += 1
                if b == nblocks and cpad:
                    if pt[-1] != cpad or pt[-cpad:] != bytes([cpad]) * cpad:
                        raise ValueError("bad PKCS7 tail (wrong key or corrupt file)")
                    pt = pt[:-cpad]
                sha.update(pt)
                fout.write(pt)
                written += len(pt)
    os.replace(tmp, dst)
    if preserve_mtime:
        os.utime(dst, (mtime, mtime))
    return written, sha.hexdigest()


# ============================================================================================= main
class Log:
    """Lines go to the log file; to the console too unless console=False. Keeps a progress bar tidy."""

    def __init__(self, path):
        self.f = None
        self.bar_shown = False
        if path:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self.f = os.fdopen(fd, "a", encoding="utf-8")

    def __call__(self, msg, console=True):
        line = time.strftime("%H:%M:%S ") + msg
        if console:
            if self.bar_shown:
                sys.stderr.write("\r\033[K")
            print(line, flush=True)
        if self.f:
            self.f.write(line + "\n")
            self.f.flush()

    def bar(self, i, n, done_bytes, total_bytes, t0, current):
        """Progress bar by number of files, with byte throughput and ETA."""
        cols = shutil.get_terminal_size((100, 20)).columns
        width = 30
        filled = int(width * i / n) if n else width
        el = time.time() - t0
        rate = done_bytes / el if el > 0 else 0.0
        eta = (total_bytes - done_bytes) / rate if rate > 0 else 0.0
        head = "[%s%s] %d/%d files  %s/%s  %s/s  ETA %dm%02ds  " % (
            "#" * filled, "-" * (width - filled), i, n, fmt(done_bytes), fmt(total_bytes), fmt(rate),
            int(eta) // 60, int(eta) % 60)
        room = max(0, cols - len(head) - 1)
        cur = current if len(current) <= room else ("…" + current[-(room - 1):] if room > 1 else "")
        sys.stderr.write("\r\033[K" + head + cur)
        sys.stderr.flush()
        self.bar_shown = True

    def end_bar(self):
        if self.bar_shown:
            sys.stderr.write("\n")
            sys.stderr.flush()
            self.bar_shown = False


def find_default(name, explicit):
    if explicit:
        return explicit
    for d in (os.getcwd(), os.path.dirname(os.path.abspath(__file__))):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            return p
    sys.exit("cannot find %s (use the matching option)" % name)


def fmt(n):
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or u == "TiB":
            return "%.1f %s" % (n, u) if u != "B" else "%d B" % n
        n /= 1024.0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src_root")
    ap.add_argument("--key")
    ap.add_argument("--password-file")
    ap.add_argument("--dest-parent")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 2)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--overwrite", action="store_true")
    ap.add_argument("--no-copy-plain", action="store_true")
    ap.add_argument("--no-preserve-mtime", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--log")
    a = ap.parse_args()
    os.umask(0o077)

    src_root = os.path.abspath(a.src_root.rstrip("/"))
    if not os.path.isdir(src_root):
        sys.exit("not a directory: %s" % src_root)
    user = load_user(find_default("key.bckey", a.key))
    if a.password_file:
        with open(a.password_file, encoding="utf-8") as f:
            password = f.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Boxcryptor account password: ")
    priv, fn_key = unwrap_user_keys(user, password)
    password = None
    uid = user["id"]

    def name_of(encoded):
        """on-disk name -> (plaintext name, ok). Keeps '~$' prefix, strips '.bc'."""
        prefix, core, suffix = "", encoded, ""
        if core.startswith("~$"):
            prefix, core = "~$", core[2:]
        if core.endswith(BC_EXT):
            suffix, core = BC_EXT, core[:-len(BC_EXT)]
        if fn_key is not None:
            try:
                return prefix + sanitize(decrypt_name(core, fn_key, uid)), True
            except (Base4KError, NameError_, UnicodeDecodeError):
                pass
        return prefix + core, False     # not an encrypted name (or filename encryption off): keep, minus .bc

    root_name, ok = name_of(os.path.basename(src_root))
    if not ok:
        root_name += "_decrypted"
    dest_parent = os.path.abspath(a.dest_parent) if a.dest_parent else os.path.dirname(src_root)
    dest_root = os.path.join(dest_parent, root_name)
    if os.path.realpath(dest_root).startswith(os.path.realpath(src_root) + os.sep) or os.path.realpath(dest_root) == os.path.realpath(src_root):
        sys.exit("destination would be inside the source tree")

    if not a.dry_run:
        os.makedirs(dest_root, mode=0o700, exist_ok=True)
    log = Log(None if a.dry_run else (a.log or os.path.join(dest_root, "_boxcryptor_decrypt.log")))
    log("source : %s" % src_root)
    log("dest   : %s" % dest_root)
    log("user   : %s (filename key: %s)" % (uid, "yes" if fn_key is not None else "NO -- names will stay encrypted"))
    log("mode   : %s, workers=%d" % ("DRY RUN" if a.dry_run else "decrypt", a.workers))

    # ---- pass 1: walk the tree; headers/stat are read by I/O threads (SMB latency bound); RSA happens in pass 2
    tasks, plain_copies, skipped, bad_names, total_bytes = [], [], [], 0, 0
    dir_map = {src_root: dest_root}
    t_scan = time.time()
    scanned = [0]

    def scan_bar(msg):
        el = time.time() - t_scan
        sys.stderr.write("\r\033[Kscanning: %d files, %d dirs, %d .bc queued  [%.0f files/s]  %s"
                         % (scanned[0], len(dir_map), len(pending), scanned[0] / el if el > 0 else 0, msg))
        sys.stderr.flush()
        log.bar_shown = True

    def prep_bc(sp, dcur, fnm):
        st = os.stat(sp)
        hdr, offset, cpad = read_header(sp)
        return sp, dcur, fnm, hdr, offset, cpad, st.st_size, st.st_mtime

    def plain_dest_size(dp):
        try:
            return os.path.getsize(dp)
        except OSError:
            return -1

    pending = []
    with cf.ThreadPoolExecutor(max_workers=max(8, 4 * a.workers)) as tex:
        for cur, dirs, files in os.walk(src_root):
            dirs.sort(); files.sort()
            dcur = dir_map[cur]
            for d in dirs:
                dn, ok = name_of(d)
                bad_names += 0 if ok else 1
                target = os.path.join(dcur, dn)
                while target in dir_map.values() or (os.path.exists(target) and not os.path.isdir(target)):
                    target += "~"
                dir_map[os.path.join(cur, d)] = target
            for fnm in files:
                sp = os.path.join(cur, fnm)
                scanned[0] += 1
                if fnm == FOLDER_KEY_FILE:
                    skipped.append((sp, "folder key container")); continue
                if not fnm.endswith(BC_EXT):
                    if os.path.islink(sp):
                        skipped.append((sp, "symlink")); continue
                    dp = os.path.join(dcur, name_of(fnm)[0])
                    if a.no_copy_plain:
                        skipped.append((sp, "not .bc"))
                    elif not a.overwrite and plain_dest_size(dp) == os.path.getsize(sp):
                        skipped.append((sp, "already decrypted (size matches)"))
                    else:
                        plain_copies.append((sp, dp))
                    continue
                pending.append((sp, tex.submit(prep_bc, sp, dcur, fnm)))
                if scanned[0] % 100 == 0:
                    scan_bar(os.path.relpath(cur, src_root)[-40:])
        scan_bar("walk done, waiting for header reads")
        for i, (sp, fut) in enumerate(pending, 1):
            try:
                sp, dcur, fnm, hdr, offset, cpad, size, mtime = fut.result()
            except Exception as e:
                skipped.append((sp, "unreadable header: %s" % e)); continue
            dn, ok = name_of(fnm)
            if not ok:   # fall back to the name stored in the header
                hv = hdr.get("metadata", {}).get("name", {})
                if hv.get("value") and hv.get("encrypted") in (True, "true"):
                    dn2, ok2 = name_of(hv["value"])
                    if ok2:
                        dn, ok = dn2, True
                if not ok:
                    bad_names += 1
            c = hdr["cipher"]
            if (c["algorithm"], c["mode"], c["padding"]) != ("AES", "CBC", "PKCS7"):
                skipped.append((sp, "unexpected cipher %r" % (c,))); continue
            efk = next((e["value"] for e in hdr.get("encryptedFileKeys", []) if e.get("id") == uid), None)
            if efk is None:
                skipped.append((sp, "no file key for this user")); continue
            plain_len = max(0, size - offset) - cpad
            dp = os.path.join(dcur, dn)
            if not a.overwrite and plain_dest_size(dp) == plain_len:
                skipped.append((sp, "already decrypted (size matches)")); continue
            total_bytes += plain_len
            tasks.append((sp, dp, offset, cpad, base64.b64decode(c["iv"]), efk, int(c["blockSize"]),
                          mtime, not a.no_preserve_mtime, fnm, dn, plain_len))
            if i % 500 == 0:
                scan_bar("resolving names %d/%d" % (i, len(pending)))
    log.end_bar()
    log("scanned: %d files in %.0fs" % (scanned[0], time.time() - t_scan))
    log("found  : %d .bc files to decrypt (%s), %d plain files to copy, %d skipped, %d undecryptable names, %d dirs"
        % (len(tasks), fmt(total_bytes), len(plain_copies), len(skipped), bad_names, len(dir_map)))
    for sp, why in skipped:
        if "already decrypted" not in why:
            log("skip   : %s  (%s)" % (os.path.relpath(sp, src_root), why))
    if a.dry_run:
        for s, d in sorted(dir_map.items()):
            log("dir    : %s  ->  %s" % (os.path.relpath(s, os.path.dirname(src_root)), os.path.relpath(d, dest_parent)))
        for t in tasks:
            log("file   : %s  ->  %s  (%s)" % (os.path.relpath(t[0], src_root), os.path.relpath(t[1], dest_root), fmt(t[11])))
        for s, d in plain_copies:
            log("copy   : %s  ->  %s" % (os.path.relpath(s, src_root), os.path.relpath(d, dest_root)))
        return 0

    # ---- pass 2: create dirs, copy plain files, decrypt in parallel
    for s, d in dir_map.items():
        os.makedirs(d, mode=0o700, exist_ok=True)
    for s, d in plain_copies:
        shutil.copyfile(s, d)
        os.chmod(d, 0o600)
        if not a.no_preserve_mtime:
            shutil.copystat(s, d)
        log("copied : %s  ->  %s" % (os.path.relpath(s, src_root), os.path.relpath(d, dest_root)), console=a.verbose)

    done_bytes, failures, t0 = 0, 0, time.time()
    if tasks:
        log.bar(0, len(tasks), 0, total_bytes, t0, "starting %d workers" % a.workers)
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    with cf.ProcessPoolExecutor(max_workers=a.workers, initializer=_init_worker, initargs=(priv_der,)) as ex:
        futs = {ex.submit(decrypt_content, *t[:9]): t for t in tasks}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            t = futs[fut]
            rel_src, rel_dst = os.path.relpath(t[0], src_root), os.path.relpath(t[1], dest_root)
            try:
                written, digest = fut.result()
                if written != t[11]:
                    raise ValueError("size mismatch: wrote %d, expected %d" % (written, t[11]))
                done_bytes += written
                log("ok %5d/%d: %s  ->  %s  (%s, sha256 %s…)" % (i, len(tasks), rel_src, rel_dst, fmt(written), digest[:12]),
                    console=a.verbose)
            except Exception as e:
                failures += 1
                log("FAIL %4d/%d: %s  ->  %s  (%s)" % (i, len(tasks), rel_src, rel_dst, e))
            log.bar(i, len(tasks), done_bytes, total_bytes, t0, rel_dst)
    log.end_bar()
    if not a.no_preserve_mtime:
        for s, d in dir_map.items():
            try:
                st = os.stat(s); os.utime(d, (st.st_atime, st.st_mtime))
            except OSError:
                pass
    log("done   : %d files, %s in %.0fs, %d failures, %d names left encrypted"
        % (len(tasks) - failures, fmt(done_bytes), time.time() - t0, failures, bad_names))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
