# CryptoAgility42

CryptoAgility42 is a .NET 8 command-line sample that encrypts and decrypts files with versioned, self-describing crypto blobs. Each `.enc` file includes the metadata needed to decrypt it later with the correct password: format magic, version number, PBKDF2 iteration count, salt, IV or nonce, wrapped data encryption key, ciphertext, and authentication data.

## Requirements

- .NET 8 SDK or later

## Build

```powershell
dotnet build
```

## Usage

```powershell
Crypto encrypt <v1|v2|v3> <password> <filename>
Crypto decrypt <filename.enc>
```

Encrypting writes a new file named `<filename>.enc` and never overwrites an existing output file.

Decrypting prompts for the password, reads the metadata from the `.enc` file, and writes the original filename by removing the `.enc` suffix. If the input file does not end in `.enc`, decrypting writes `<filename>.dec`.

Example:

```powershell
dotnet run -- encrypt v3 "correct horse battery staple" .\message.txt
dotnet run -- decrypt .\message.txt.enc
```

## Crypto versions

| Version | Password KDF | Key wrap | Content encryption | Authentication |
| --- | --- | --- | --- | --- |
| v1 | PBKDF2-SHA1, 10,000 iterations | AES-128-KW | AES-128-CBC with PKCS#7 padding | HMAC-SHA1, encrypt-then-MAC |
| v2 | PBKDF2-SHA256, 100,000 iterations | AES-128-KW | AES-128-GCM | AES-GCM tag |
| v3 | PBKDF2-SHA384, 300,000 iterations | AES-256-KW | AES-256-GCM | AES-GCM tag |

All versions use a two-layer key hierarchy:

- A random per-file DEK encrypts the file contents.
- A password-derived KEK wraps the DEK with AES Key Wrap (RFC 3394).

The plaintext DEK is never stored in the `.enc` file.

## File format

All encrypted files start with a four-byte magic value, followed by a version byte and big-endian PBKDF2 iteration count.

```text
v1: CA42 || version || iterations || salt || iv    || wrappedDek || ciphertext || hmacSha1
v2: CA42 || version || iterations || salt || nonce || wrappedDek || ciphertext || gcmTag
v3: CA42 || version || iterations || salt || nonce || wrappedDek || ciphertext || gcmTag
```

Lengths:

| Field | v1 | v2 | v3 |
| --- | ---: | ---: | ---: |
| Magic | 4 | 4 | 4 |
| Version | 1 | 1 | 1 |
| Iterations | 4 | 4 | 4 |
| Salt | 16 | 16 | 16 |
| IV / nonce | 16-byte IV | 12-byte nonce | 12-byte nonce |
| Wrapped DEK | 24 | 24 | 40 |
| Auth data | 20-byte HMAC-SHA1 | 16-byte GCM tag | 16-byte GCM tag |

## Notes

This is an educational crypto-agility sample, not a hardened production file-encryption tool. The encrypt command accepts the password as a command-line argument to match the sample interface, which can expose it through shell history or process listings on some systems.
