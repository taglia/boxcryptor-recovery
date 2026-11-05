# boxcryptor-recovery

Offline decryption of a whole [Boxcryptor](https://en.wikipedia.org/wiki/Boxcryptor) 2.x folder tree:
file **contents** and encrypted file and folder **names**, with nothing but your key export and your password.

## Why this exists

I had an old backup that I had encrypted with Boxcryptor years ago and then forgotten about. When I needed it
again, Boxcryptor no longer existed: the company had been acquired by Dropbox and the service, including the
servers the client needs to log in, had been shut down. I still had the installer, a key export and the password,
but no working software. The official single-file decryptor and the community tools I found could decrypt file
contents one file at a time, yet every file and folder in my backup had a name made of Chinese-looking
characters, because I had enabled filename encryption. Nothing documented how those names were encrypted.

This repository is the result: the name encoding and cipher, worked out from the Windows client and verified
against real data, plus one script that walks an encrypted tree and writes a plaintext copy next to it.

## What you need

1. **Your key export, a `.bckey` file.** Boxcryptor could export your keys from the desktop app
   (account settings, key export). The export is a JSON file containing your public key, your encrypted private
   key, the key-wrapping material and the filename key, all protected by your account password. If you never
   exported your keys while the service was alive, this tool cannot help: the private key only ever existed in
   the export and on Boxcryptor's servers. Check old backups, password managers and mail attachments; the file
   is small (a few kilobytes) and is usually called `<something>.bckey`.
2. **Your Boxcryptor account password.** It is used to derive the key that unlocks the export.
3. **The encrypted folder.** A Boxcryptor 2.x tree: files ending in `.bc`, folders containing a
   `FolderKey.bch`, and, if filename encryption was on, names such as `倐嚵厪克峗哌䂶`.
4. **Nix** (with flakes), or any Python 3.10+ with the [`cryptography`](https://cryptography.io) package.

Supported: one user (no groups or organisation keys), AES-256-CBC files, filename encryption on or off.
The tool refuses to run on an export with more than one user rather than guess.

## Where to keep the key

The `.bckey` export plus your password is everything an attacker needs to read your data. Treat them like the
data itself:

- Keep `key.bckey` **in the same directory as the encrypted folder**, on the same encrypted disk or share,
  with restrictive permissions (`chmod 600 key.bckey`). The tool looks for it in the current directory.
- Prefer typing the password when prompted. If you must script it, put it alone in a file called `pass.txt`
  next to the key, `chmod 600`, and delete it afterwards.
- **Never put the key, the password or the data inside a copy of this repository**, and never run `nix develop`
  or `nix run .` from a directory that contains them: a path flake is copied into `/nix/store`, which is
  world-readable. Run the tool *from* the data directory and point it at the repository, as shown below.
- The tool never prints or logs the password, private key or any derived key. The log in the output directory
  contains only file names, sizes and SHA-256 prefixes of the decrypted files.

## Usage

From the directory that holds `key.bckey` and the encrypted folder:

```sh
# plan only: resolves every name, decrypts nothing
nix run github:taglia/boxcryptor-recovery -- --dry-run '倐姁宸壮凕娗吓墭塽堦䃸'

# decrypt into a sibling folder named with the decrypted root name
nix run github:taglia/boxcryptor-recovery -- '倐姁宸壮凕娗吓墭塽堦䃸'
```

Without Nix:

```sh
python3 -I /path/to/boxcryptor-recovery/decrypt_tree.py --dry-run '<encrypted root dir>'
```

The decrypted tree appears next to the encrypted one. Files you already decrypted are skipped on a rerun, so
an interrupted run can simply be restarted. Options:

| Option | Meaning |
|---|---|
| `--key FILE` | key export (default: `./key.bckey`) |
| `--password-file FILE` | password file (default: `./pass.txt` if present, else prompt) |
| `--dest-parent DIR` | create the decrypted root here instead of next to the source |
| `--workers N` | parallel decryption processes (default: CPU count) |
| `--dry-run` | print the plan, write nothing |
| `--overwrite` | redo files that already exist |
| `--no-copy-plain` | do not copy files that are not `.bc` |
| `--no-preserve-mtime` | do not copy modification times |
| `--verbose` | print every file on the console (always in the log) |

The console shows a scan counter, then a progress bar by file count with bytes, throughput and ETA.
A per-file log is written to `<decrypted root>/_boxcryptor_decrypt.log`.

### Performance

Decryption itself runs at several hundred MB/s per core. Over a network share the limit is the per-file
round trips: budget roughly 10 ms per file plus the raw transfer time, twice (read and write back).

## How it works

See [FORMAT.md](FORMAT.md) for the byte-level description of the key export, the `.bc` container, the Base4K
name encoding and the filename cipher. In short:

- `PBKDF2-HMAC-SHA512(password, salt)` yields an AES key and an HMAC key that unlock the private key and the
  *wrapping key*; the wrapping key unlocks the *filename key*. Each of these is an `IV | HMAC | AES-CBC` blob.
- Every file carries its own key, RSA-OAEP-wrapped for the user, in a JSON header; the content is AES-256-CBC
  in 4096-byte blocks with per-block HMAC-derived IVs.
- Names are Base4K-encoded (Secomba's open-source 12-bits-per-character encoding) bytes: a tag, a one-byte
  hash of the key holder, a 5-byte HMAC of the plain name, and the name encrypted with two passes of
  AES-256-CFB keyed by the filename key.

The filename cipher is not published anywhere I could find; it was recovered by reading the (decompiled)
Boxcryptor 2.47 Windows client and re-implemented from scratch here. No vendor code is included.

## Tests

```sh
nix develop -c python3 -I -m unittest discover -s tests -v
```

The tests use the public Base4K test vectors and synthetic vaults built with freshly generated keys; no real
key or data is needed or included.

## Related work

- [secomba/boxcryptor-single-file-decryptor](https://github.com/secomba/boxcryptor-single-file-decryptor):
  the vendor's reference for file contents (C#, C++, Java). No filenames, one file at a time.
- [secomba/base4k](https://github.com/secomba/base4k): the name encoding, open-sourced by the vendor in 2014.
- [janiko71/boxcryptor-decryptor](https://github.com/janiko71/boxcryptor-decryptor): a Python port of the
  content decryption, which this project started from.

## License

MIT. Boxcryptor is a trademark of its owner; this project is not affiliated with Secomba GmbH or Dropbox.
