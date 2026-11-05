# Boxcryptor 2.x on-disk formats

Everything below was verified against a real Boxcryptor 2.x vault (client 2.47, Windows) and is implemented
in `decrypt_tree.py`. Byte offsets are 0-based. "u32" means little-endian unsigned 32-bit.

## 1. Key export (`.bckey`)

A JSON document, **with a UTF-8 BOM** (read it with `encoding="utf-8-sig"`). Relevant part:

```json
{
  "artifact": "keyfile", "version": 1,
  "users": [{
    "id": "<decimal user id>", "username": "...",
    "publicKey":  "<base64 DER SubjectPublicKeyInfo, RSA-4096>",
    "privateKey": "<base64 wrapped blob -> base64 text of a PKCS#8 DER private key>",
    "aesKey":     "<base64 RSA-OAEP ciphertext -> 96 bytes>",
    "wrappingKey":"<base64 wrapped blob -> 64 bytes>",
    "keys": { "filename": "<base64 wrapped blob -> 64 bytes>",
              "groupMembership": "...", "analytics": "..." },
    "salt": "<base64, 24 bytes>", "kdfIterations": 10000,
    "password": "<hash, unused for decryption>"
  }],
  "groups": [], "groupMemberships": [], "organization": { "id": "...", "keys": {} }
}
```

### Password key

```
PBKDF2-HMAC-SHA512(password as UTF-8, salt, kdfIterations) -> 64 bytes
  [0:32]  pwAES   (AES-256 key)
  [32:64] pwHMAC  (HMAC-SHA256 key)
```

### Wrapped blob

Used for `privateKey`, `wrappingKey` and every entry of `keys`:

```
[0:16]   IV
[16:48]  HMAC-SHA256(hmacKey, ciphertext)
[48:]    AES-256-CBC(aesKey, IV, PKCS7) ciphertext
```

Verify the HMAC before decrypting. Which pair unlocks what:

| blob | aesKey / hmacKey | plaintext |
|---|---|---|
| `privateKey` | pwAES / pwHMAC | base64 **text** of a PKCS#8 DER RSA private key |
| `wrappingKey` | pwAES / pwHMAC | 64 bytes = wAES `[0:32]` \| wHMAC `[32:64]` |
| `keys.filename` | wAES / wHMAC | 64 bytes = the user's AES key: ForEncryption `[0:32]` \| ForHashing `[32:64]` |
| `keys.*` (others) | wAES / wHMAC | 64 bytes each |

### Boxcryptor "AesKey" objects

The client's `AesKey` holds `2 * keyLength` bytes: the first half is used for encryption, the second half for
hashing (HMAC). RSA-wrapped keys (`aesKey`, and `encryptedFileKeys[].value` in file headers) decrypt to
**96 bytes**; bytes `[32:96]` are the 64-byte `AesKey` (so the AES key is `[32:64]` and the HMAC key `[64:96]`).
Bytes `[0:32]` were not needed for decryption. The user's `aesKey[32:96]` equals the `keys.filename` plaintext.

RSA unwrapping is RSA-OAEP with MGF1-SHA1 and SHA1.

## 2. Encrypted file (`*.bc`) and folder key (`FolderKey.bch`)

```
[0:4]    "bc01"
[4:8]    u32 header_core_length     (length of the JSON header)
[8:12]   u32 header_padding_length  (NUL padding after the JSON)
[12:16]  u32 cipher_padding_length  (PKCS7 pad count in the last data block)
[16:48]  32 bytes (hash; not needed for decryption)
[48:48+core]            JSON header, UTF-8
[..offset]              NUL padding; offset = 48 + core + padding (4096 in practice)
[offset:]               data blocks
```

JSON header:

```json
{ "artifact": "header", "version": 1,
  "cipher": { "algorithm": "AES", "mode": "CBC", "padding": "PKCS7", "keySize": 256,
              "blockSize": 4096, "iv": "<base64, 16 bytes>", "mac": { "enabled": "false" } },
  "metadata": { "name": { "value": "<the file's own (encrypted) name>", "encrypted": true } },
  "encryptedFileKeys": [ { "type": "data", "id": "<user id>", "value": "<base64 RSA-OAEP -> 96 bytes>" } ] }
```

Content decryption, with `K = fileKey[32:64]`:

```
for block i = 0, 1, ... (each `blockSize` bytes of ciphertext, the last one may be shorter):
    IV_i = HMAC-SHA256(K, iv || u64le(i))[0:16]
    P_i  = AES-256-CBC-decrypt(K, IV_i, C_i)
strip cipher_padding_length bytes of PKCS7 from the last block only
```

`FolderKey.bch` is the same container with no data blocks; it exists so a folder has a key. Folder keys are
**not** used for name encryption in a single-user vault, so the tool only skips these files.

## 3. Encrypted names

### Base4K encoding

Names are Secomba's open-source [Base4K](https://github.com/secomba/base4k): 12 bits per character.

```
value v in 0..4095  ->  U+5000 + v   (legacy alphabet, what Boxcryptor 2.x wrote)
                        U+6000 + v   (current alphabet; decoders accept both)
trailing partial group  ->  U+4000 + byte   (even position)  or  U+4000 + low nibble (odd position)
```

Three bytes become two characters. The reference decoder is ported verbatim in `decrypt_tree.py`.

### Decoded layout

```
[0]     0x01  tag / version
[1]     fold8(UTF-8(key holder id))   one-byte XOR fold, see below
[2:7]   HMAC-SHA256(ForHashing, UTF-8(plain name))[0:5]      ("mac5")
[7:]    ciphertext, same length as the UTF-8 plain name
```

`fold8(b)`: XOR bytes `b[0..len-2]` (the last byte is skipped) into an 8-byte array at `i % 8`, read it as a
big-endian u64, then XOR-fold to 32, 16 and 8 bits.

The key is the key holder's `AesKey` (ForEncryption `Ke` = `[0:32]`, ForHashing `Kh` = `[32:64]`). For a
single-user vault that is the `keys.filename` plaintext.

### Cipher

```
ivbase       = HMAC-SHA256(Kh, mac5)[0:16]
n            = fold64(ivbase)                       # XOR bytes [0..14] into 8 bytes, big-endian u64
setivec(s)   = HMAC-SHA256(Ke, ivbase || u64le(s))[0:16]
CFB          = AES-256-CFB with 128-bit feedback, no padding (length preserving)
xor_chain(b) : for i in 0..len-2: b[i+1] ^= b[i]
rev64(b)     : reverse every 64-byte chunk in place

encrypt:  c1 = CFB_enc(Ke, setivec(n),   xor_chain(p))
          c  = CFB_enc(Ke, setivec(n+1), xor_chain(rev64(c1)))
decrypt:  p1 = rev64(unxor_chain(CFB_dec(Ke, setivec(n+1), c)))
          p  = unxor_chain(CFB_dec(Ke, setivec(n), p1))
          check HMAC-SHA256(Kh, p)[0:5] == mac5
```

`unxor_chain` is the inverse of `xor_chain`: for i from len-1 down to 1: `b[i] ^= b[i-1]`.

Affixes stay in clear: a leading `~$` (Office lock files) and the trailing `.bc`. The folder's own name is
also stored, encrypted the same way, in `FolderKey.bch` under `metadata.name.value`.

## Not covered

Multi-user and group key holders (the `[1]` byte selects among a user's key holders), MAC-enabled files
(`mac.enabled: "true"`), and files whose plaintext length is an exact multiple of the block size (the padding
convention for that case was not observed in the test vault).
