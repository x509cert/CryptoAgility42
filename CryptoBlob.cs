using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Crypto;

/// <summary>
/// Cryptographic algorithm selection by security version.
///
/// Two-layer key hierarchy in every version:
///   DEK (data encryption key) — encrypts the payload; random, per-message.
///   KEK (key encryption key)  — wraps the DEK; derived from the password via PBKDF2.
/// The DEK is never stored or transmitted in plaintext. Key wrapping is AES-KW (RFC 3394).
///
/// Wire format — magic, version byte, common metadata, then version-specific metadata and body:
///
///   v1 [magic:4][ver:1][iter:4][salt:16][iv:16][wrappedDek:24][ciphertext:..][hmacSha1:20]
///        PBKDF2-SHA1 → KEK(16)‖MacKey(16); AES-128-KW; AES-128-CBC; encrypt-then-MAC.
///        HMAC covers everything before it (header + ciphertext).
///
///   v2 [magic:4][ver:1][iter:4][salt:16][nonce:12][wrappedDek:24][ciphertext:..][gcmTag:16]
///        PBKDF2-SHA256 → KEK(16); AES-128-KW; AES-128-GCM. Header is GCM-AAD.
///
///   v3 [magic:4][ver:1][iter:4][salt:16][nonce:12][wrappedDek:40][ciphertext:..][gcmTag:16]
///        PBKDF2-SHA384 → KEK(32); AES-256-KW; AES-256-GCM. Header is GCM-AAD.
///        Grover halves symmetric strength → key sizes doubled. No asymmetric/KEM ops.
///
/// AES-KW (RFC 3394) adds one 64-bit integrity block: a 16-byte key wraps to 24,
/// a 32-byte key wraps to 40.
/// </summary>
public enum CryptoVersion : byte
{
    V1     = 1,
    V2     = 2,
    V3     = 3,
    Latest = V3,
}

public static class CryptoBlob
{
    private const int MagicLen = 4;
    private const int IterationLen = 4;
    private const int SaltLen  = 16;   // 128-bit salt (all versions)
    private const int IvLen     = 16;  // AES-CBC IV (v1)
    private const int NonceLen  = 12;  // 96-bit GCM nonce (v2/v3)
    private const int TagLen     = 16; // AES-GCM tag (v2/v3)
    private const int MacLen     = 20; // HMAC-SHA1 (v1)
    private const int MinIterations = 1_000;
    private const int MaxIterations = 1_000_000;

    private static ReadOnlySpan<byte> Magic => "CA42"u8;

    // ── Public API ────────────────────────────────────────────────────────────

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> password,
                                 CryptoVersion version = CryptoVersion.Latest) => version switch
    {
        CryptoVersion.V1 => EncryptV1(plaintext, password),
        CryptoVersion.V2 => EncryptGcm(plaintext, password, CryptoVersion.V2),
        CryptoVersion.V3 => EncryptGcm(plaintext, password, CryptoVersion.V3),
        _ => throw new ArgumentOutOfRangeException(nameof(version), version, "Unknown crypto version."),
    };

    public static byte[] Decrypt(ReadOnlySpan<byte> blob, ReadOnlySpan<char> password)
    {
        if (blob.Length < MagicLen + 1)
            throw new ArgumentException("Blob is too short.", nameof(blob));

        if (!blob[..MagicLen].SequenceEqual(Magic))
            throw new CryptographicException("Unsupported blob format.");

        return (CryptoVersion)blob[MagicLen] switch
        {
            CryptoVersion.V1 => DecryptV1(blob, password),
            CryptoVersion.V2 => DecryptGcm(blob, password, CryptoVersion.V2),
            CryptoVersion.V3 => DecryptGcm(blob, password, CryptoVersion.V3),
            var v => throw new CryptographicException($"Unsupported blob version {(byte)v}."),
        };
    }

    // ── v1: PBKDF2-SHA1 / AES-128-KW / AES-128-CBC / HMAC-SHA1 ──────────────────

    private static byte[] EncryptV1(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> password)
    {
        var (iterations, hash, keyLen) = Params(CryptoVersion.V1);

        Span<byte> salt = stackalloc byte[SaltLen];
        Span<byte> iv   = stackalloc byte[IvLen];
        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(iv);

        // PBKDF2 output is split into KEK ‖ MAC key (key separation).
        Span<byte> keyMaterial = stackalloc byte[16 + 16];
        Rfc2898DeriveBytes.Pbkdf2(password, salt, keyMaterial, iterations, hash);
        ReadOnlySpan<byte> kek    = keyMaterial[..keyLen];
        ReadOnlySpan<byte> macKey = keyMaterial[keyLen..];

        Span<byte> dek = stackalloc byte[16];
        RandomNumberGenerator.Fill(dek);
        byte[] wrappedDek = AesKw.Wrap(kek, dek);   // 24 bytes

        using var aes = Aes.Create();
        aes.Key = dek.ToArray();
        byte[] ciphertext = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

        int bodyLen = MagicLen + 1 + IterationLen + SaltLen + IvLen + wrappedDek.Length + ciphertext.Length;
        var blob = new byte[bodyLen + MacLen];
        var w = new SpanWriter(blob);
        w.Write(Magic);
        w.Byte((byte)CryptoVersion.V1);
        w.Int32(iterations);
        w.Write(salt);
        w.Write(iv);
        w.Write(wrappedDek);
        w.Write(ciphertext);

        // Encrypt-then-MAC over the entire body, tag appended at the end.
        // CA5350: HMAC-SHA1 is intentional here — v1 is the legacy-compat tier only.
#pragma warning disable CA5350
        HMACSHA1.HashData(macKey, blob.AsSpan(0, bodyLen), blob.AsSpan(bodyLen, MacLen));
#pragma warning restore CA5350

        CryptographicOperations.ZeroMemory(dek);
        CryptographicOperations.ZeroMemory(keyMaterial);
        return blob;
    }

    private static byte[] DecryptV1(ReadOnlySpan<byte> blob, ReadOnlySpan<char> password)
    {
        if (blob.Length < MagicLen + 1 + IterationLen + SaltLen + IvLen + 24 + MacLen)
            throw new CryptographicException("v1 blob is truncated.");

        var r = new SpanReader(blob[(MagicLen + 1)..]);
        int iterations = ValidateIterations(r.Take(IterationLen), CryptoVersion.V1);
        ReadOnlySpan<byte> salt       = r.Take(SaltLen);
        ReadOnlySpan<byte> iv         = r.Take(IvLen);
        ReadOnlySpan<byte> wrappedDek = r.Take(24);
        ReadOnlySpan<byte> ciphertext = r.Rest[..^MacLen];
        ReadOnlySpan<byte> storedMac  = blob[^MacLen..];

        var (_, hash, keyLen) = Params(CryptoVersion.V1);
        Span<byte> keyMaterial = stackalloc byte[16 + 16];
        Rfc2898DeriveBytes.Pbkdf2(password, salt, keyMaterial, iterations, hash);
        ReadOnlySpan<byte> kek    = keyMaterial[..keyLen];
        ReadOnlySpan<byte> macKey = keyMaterial[keyLen..];

        // Verify MAC over the body (everything except the trailing tag) before touching keys.
        // CA5350: HMAC-SHA1 is intentional here — v1 is the legacy-compat tier only.
        Span<byte> computedMac = stackalloc byte[MacLen];
#pragma warning disable CA5350
        HMACSHA1.HashData(macKey, blob[..^MacLen], computedMac);
#pragma warning restore CA5350
        if (!CryptographicOperations.FixedTimeEquals(computedMac, storedMac))
        {
            CryptographicOperations.ZeroMemory(keyMaterial);
            throw new CryptographicException("v1 HMAC verification failed — blob corrupt, tampered, or wrong password.");
        }

        byte[] dek = AesKw.Unwrap(kek, wrappedDek);
        try
        {
            using var aes = Aes.Create();
            aes.Key = dek;
            return aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(keyMaterial);
        }
    }

    // ── v2 / v3: PBKDF2 / AES-KW / AES-GCM (header authenticated as AAD) ─────────

    private static byte[] EncryptGcm(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> password, CryptoVersion version)
    {
        var (iterations, hash, keyLen) = Params(version);

        Span<byte> salt  = stackalloc byte[SaltLen];
        Span<byte> nonce = stackalloc byte[NonceLen];
        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> kek = stackalloc byte[32];                 // sized for the largest version
        Rfc2898DeriveBytes.Pbkdf2(password, salt, kek[..keyLen], iterations, hash);

        Span<byte> dek = stackalloc byte[32];
        RandomNumberGenerator.Fill(dek[..keyLen]);
        byte[] wrappedDek = AesKw.Wrap(kek[..keyLen], dek[..keyLen]);   // 24 or 40 bytes

        int headerLen = MagicLen + 1 + IterationLen + SaltLen + NonceLen + wrappedDek.Length;
        var blob = new byte[headerLen + plaintext.Length + TagLen];

        var w = new SpanWriter(blob);
        w.Write(Magic);
        w.Byte((byte)version);
        w.Int32(iterations);
        w.Write(salt);
        w.Write(nonce);
        w.Write(wrappedDek);

        // Bind the whole header to the ciphertext via AAD; write ct + tag straight into the blob.
        ReadOnlySpan<byte> aad = blob.AsSpan(0, headerLen);
        Span<byte> ctDst  = blob.AsSpan(headerLen, plaintext.Length);
        Span<byte> tagDst = blob.AsSpan(headerLen + plaintext.Length, TagLen);

        using var gcm = new AesGcm(dek[..keyLen], TagLen);
        gcm.Encrypt(nonce, plaintext, ctDst, tagDst, aad);

        CryptographicOperations.ZeroMemory(dek);
        CryptographicOperations.ZeroMemory(kek);
        return blob;
    }

    private static byte[] DecryptGcm(ReadOnlySpan<byte> blob, ReadOnlySpan<char> password, CryptoVersion version)
    {
        var (_, hash, keyLen) = Params(version);
        int wrappedLen = keyLen + 8;   // RFC 3394 overhead

        if (blob.Length < MagicLen + 1 + IterationLen + SaltLen + NonceLen + wrappedLen + TagLen)
            throw new CryptographicException($"{version} blob is truncated.");

        var r = new SpanReader(blob[(MagicLen + 1)..]);
        int iterations = ValidateIterations(r.Take(IterationLen), version);
        ReadOnlySpan<byte> salt       = r.Take(SaltLen);
        ReadOnlySpan<byte> nonce      = r.Take(NonceLen);
        ReadOnlySpan<byte> wrappedDek = r.Take(wrappedLen);
        int headerLen = MagicLen + 1 + IterationLen + SaltLen + NonceLen + wrappedLen;

        ReadOnlySpan<byte> body = r.Rest;
        ReadOnlySpan<byte> ciphertext = body[..^TagLen];
        ReadOnlySpan<byte> tag        = body[^TagLen..];
        ReadOnlySpan<byte> aad        = blob[..headerLen];

        Span<byte> kek = stackalloc byte[32];
        Rfc2898DeriveBytes.Pbkdf2(password, salt, kek[..keyLen], iterations, hash);

        byte[] dek = AesKw.Unwrap(kek[..keyLen], wrappedDek);
        try
        {
            var plaintext = new byte[ciphertext.Length];
            using var gcm = new AesGcm(dek, TagLen);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);   // throws on auth failure
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private static int ValidateIterations(ReadOnlySpan<byte> encodedIterations, CryptoVersion version)
    {
        int iterations = BinaryPrimitives.ReadInt32BigEndian(encodedIterations);
        if (iterations is < MinIterations or > MaxIterations)
            throw new CryptographicException($"{version} PBKDF2 iteration count is outside the supported range.");

        return iterations;
    }

    private static (int Iterations, HashAlgorithmName Hash, int KeyLen) Params(CryptoVersion v) => v switch
    {
        CryptoVersion.V1 => (10_000, HashAlgorithmName.SHA1, 16),
        CryptoVersion.V2 => (100_000, HashAlgorithmName.SHA256, 16),
        CryptoVersion.V3 => (300_000, HashAlgorithmName.SHA384, 32),
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };
}

/// <summary>
/// AES Key Wrap, RFC 3394. Implemented directly on the AES block primitive so there is
/// no dependency on any specific BCL key-wrap surface. Wraps/unwraps keys that are a
/// positive multiple of 8 bytes; output is the input plus one 64-bit integrity block.
/// </summary>
internal static class AesKw
{
    private const ulong DefaultIv = 0xA6A6A6A6A6A6A6A6UL;

    public static byte[] Wrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> key)
    {
        if (key.Length is 0 || key.Length % 8 != 0)
            throw new ArgumentException("Key to wrap must be a positive multiple of 8 bytes.", nameof(key));

        int n = key.Length / 8;
        var output = new byte[key.Length + 8];
        Span<byte> r = output.AsSpan(8);   // R[1..n] live in the tail; A[0..8] filled at the end
        key.CopyTo(r);

        ulong a = DefaultIv;
        using var aes = Aes.Create();
        aes.Key = kek.ToArray();

        Span<byte> block = stackalloc byte[16];
        for (int j = 0; j < 6; j++)
        {
            for (int i = 1; i <= n; i++)
            {
                Span<byte> ri = r.Slice((i - 1) * 8, 8);
                BinaryPrimitives.WriteUInt64BigEndian(block[..8], a);
                ri.CopyTo(block[8..]);

                aes.EncryptEcb(block, block, PaddingMode.None);

                a = BinaryPrimitives.ReadUInt64BigEndian(block[..8]) ^ (ulong)(n * j + i);
                block[8..].CopyTo(ri);
            }
        }

        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(0, 8), a);
        return output;
    }

    public static byte[] Unwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length < 24 || wrapped.Length % 8 != 0)
            throw new ArgumentException("Wrapped key must be a multiple of 8 bytes and at least 24.", nameof(wrapped));

        int n = wrapped.Length / 8 - 1;
        var output = new byte[n * 8];
        Span<byte> r = output;
        wrapped[8..].CopyTo(r);

        ulong a = BinaryPrimitives.ReadUInt64BigEndian(wrapped[..8]);
        using var aes = Aes.Create();
        aes.Key = kek.ToArray();

        Span<byte> block = stackalloc byte[16];
        for (int j = 5; j >= 0; j--)
        {
            for (int i = n; i >= 1; i--)
            {
                Span<byte> ri = r.Slice((i - 1) * 8, 8);
                BinaryPrimitives.WriteUInt64BigEndian(block[..8], a ^ (ulong)(n * j + i));
                ri.CopyTo(block[8..]);

                aes.DecryptEcb(block, block, PaddingMode.None);

                a = BinaryPrimitives.ReadUInt64BigEndian(block[..8]);
                block[8..].CopyTo(ri);
            }
        }

        if (a != DefaultIv)
        {
            CryptographicOperations.ZeroMemory(output);
            throw new CryptographicException("AES-KW integrity check failed — wrong KEK or corrupted wrapped key.");
        }
        return output;
    }
}

/// <summary>Minimal forward-only writer over a span; keeps blob assembly readable.</summary>
file ref struct SpanWriter(Span<byte> buffer)
{
    private readonly Span<byte> _buffer = buffer;
    private int _pos;

    public void Byte(byte value) => _buffer[_pos++] = value;

    public void Int32(int value)
    {
        BinaryPrimitives.WriteInt32BigEndian(_buffer.Slice(_pos, 4), value);
        _pos += 4;
    }

    // 'scoped' promises the span is only read here (it is — we copy out of it),
    // so passing a stackalloc'd argument doesn't violate ref-safety.
    public void Write(scoped ReadOnlySpan<byte> data)
    {
        data.CopyTo(_buffer[_pos..]);
        _pos += data.Length;
    }
}

/// <summary>Minimal forward-only reader over a span.</summary>
file ref struct SpanReader(ReadOnlySpan<byte> buffer)
{
    private readonly ReadOnlySpan<byte> _buffer = buffer;
    private int _pos;

    public ReadOnlySpan<byte> Take(int count)
    {
        var slice = _buffer.Slice(_pos, count);
        _pos += count;
        return slice;
    }

    public readonly ReadOnlySpan<byte> Rest => _buffer[_pos..];
}
