using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Crypto;

/// <summary>
/// Two-tier crypto. A random per-message DEK encrypts the payload; a password-derived
/// KEK wraps the DEK with AES-KWP (RFC 5649) via <see cref="Aes.EncryptKeyWrapPadded(ReadOnlySpan{byte})"/>.
/// v1: PBKDF2-SHA1 / AES-128-CBC / HMAC-SHA1 (encrypt-then-MAC) — legacy compat.
/// v2: PBKDF2-SHA256 / AES-128-GCM (header is GCM AAD).
/// v3: PBKDF2-SHA384 / AES-256-GCM (header is GCM AAD); key sizes doubled for post-Grover margin.
///
/// Wire: [magic:4][ver:1][iter:4][salt:16][iv|nonce][wrappedDek][ciphertext][auth].
/// iv=16B (v1, CBC) / nonce=12B (v2/v3, GCM); wrappedDek=24B (v1/v2) or 40B (v3);
/// auth=20B HMAC-SHA1 (v1) or 16B GCM tag (v2/v3).
/// </summary>
public enum CryptoVersion : byte { V1 = 1, V2 = 2, V3 = 3, Latest = V3 }

public sealed record CryptoBlobHeader(
    CryptoVersion Version, int Iterations, byte[] Salt, byte[] IvOrNonce,
    int HeaderLength, int WrappedDekOffset, int WrappedDekLength,
    int CiphertextLength, int AuthDataLength)
{
    public string Magic { get; } = "CA42";
    public string PasswordKdf => $"PBKDF2-{HashName}";
    public string IvOrNonceName => Version == CryptoVersion.V1 ? "IV" : "Nonce";
    public string KeyWrap => $"AES-{KeyBits}-KWP (RFC 5649)";
    public string ContentEncryption => Version == CryptoVersion.V1
        ? "AES-128-CBC with PKCS#7 padding" : $"AES-{KeyBits}-GCM";
    public string Authentication => Version == CryptoVersion.V1
        ? "HMAC-SHA1, encrypt-then-MAC" : "AES-GCM tag";
    public string AuthDataName => Version == CryptoVersion.V1 ? "HMAC-SHA1" : "GCM tag";

    private string HashName => Version switch
    {
        CryptoVersion.V1 => "SHA1",
        CryptoVersion.V2 => "SHA256",
        _ => "SHA384",
    };
    private int KeyBits => Version == CryptoVersion.V3 ? 256 : 128;
}

public static class CryptoBlob
{
    private const int MagicLen = 4, IterLen = 4, SaltLen = 16,
                      IvLen = 16, NonceLen = 12, TagLen = 16, MacLen = 20,
                      MinIter = 1_000, MaxIter = 1_000_000;
    private const int Prefix = MagicLen + 1 + IterLen + SaltLen; // magic|ver|iter|salt

    private static ReadOnlySpan<byte> Magic => "CA42"u8;

    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> password,
                                 CryptoVersion version = CryptoVersion.Latest) => version switch
    {
        CryptoVersion.V1 => EncryptV1(plaintext, password),
        CryptoVersion.V2 or CryptoVersion.V3 => EncryptGcm(plaintext, password, version),
        _ => throw new ArgumentOutOfRangeException(nameof(version), version, "Unknown crypto version."),
    };

    public static byte[] Decrypt(ReadOnlySpan<byte> blob, ReadOnlySpan<char> password)
    {
        var h = ParseHeader(blob);
        return h.Version == CryptoVersion.V1
            ? DecryptV1(blob, password, h)
            : DecryptGcm(blob, password, h);
    }

    public static CryptoBlobHeader Inspect(ReadOnlySpan<byte> blob) => ParseHeader(blob);

    // ── v1: AES-128-CBC + HMAC-SHA1 (encrypt-then-MAC) ─────────────────────────
    private static byte[] EncryptV1(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> password)
    {
        var (iter, hash, keyLen) = Params(CryptoVersion.V1);

        Span<byte> salt = stackalloc byte[SaltLen];
        Span<byte> iv = stackalloc byte[IvLen];
        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(iv);

        // PBKDF2 output is split into KEK ‖ MAC key (key separation).
        Span<byte> km = stackalloc byte[keyLen * 2];
        Rfc2898DeriveBytes.Pbkdf2(password, salt, km, iter, hash);

        Span<byte> dek = stackalloc byte[16];
        RandomNumberGenerator.Fill(dek);
        byte[] wrapped = WrapDek(km[..keyLen], dek);

        using var aes = Aes.Create();
        aes.Key = dek.ToArray();
        byte[] ct = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

        int headerLen = Prefix + IvLen + wrapped.Length;
        int bodyLen = headerLen + ct.Length;
        var blob = new byte[bodyLen + MacLen];
        WriteHeader(blob, CryptoVersion.V1, iter, salt, iv, wrapped);
        ct.CopyTo(blob.AsSpan(headerLen));

#pragma warning disable CA5350 // HMAC-SHA1 intentional in legacy v1 tier
        HMACSHA1.HashData(km[keyLen..], blob.AsSpan(0, bodyLen), blob.AsSpan(bodyLen, MacLen));
#pragma warning restore CA5350

        CryptographicOperations.ZeroMemory(dek);
        CryptographicOperations.ZeroMemory(km);
        return blob;
    }

    private static byte[] DecryptV1(ReadOnlySpan<byte> blob, ReadOnlySpan<char> password, CryptoBlobHeader h)
    {
        var (_, hash, keyLen) = Params(CryptoVersion.V1);
        var wrapped = blob.Slice(h.WrappedDekOffset, h.WrappedDekLength);
        var ct = blob.Slice(h.HeaderLength, h.CiphertextLength);
        var storedMac = blob.Slice(h.HeaderLength + h.CiphertextLength, h.AuthDataLength);

        Span<byte> km = stackalloc byte[keyLen * 2];
        Rfc2898DeriveBytes.Pbkdf2(password, h.Salt, km, h.Iterations, hash);

        // Verify MAC over header+ciphertext before touching keys.
        Span<byte> mac = stackalloc byte[MacLen];
#pragma warning disable CA5350
        HMACSHA1.HashData(km[keyLen..], blob[..(h.HeaderLength + h.CiphertextLength)], mac);
#pragma warning restore CA5350
        if (!CryptographicOperations.FixedTimeEquals(mac, storedMac))
        {
            CryptographicOperations.ZeroMemory(km);
            throw new CryptographicException("v1 HMAC verification failed — blob corrupt, tampered, or wrong password.");
        }

        byte[] dek = UnwrapDek(km[..keyLen], wrapped);
        try
        {
            using var aes = Aes.Create();
            aes.Key = dek;
            return aes.DecryptCbc(ct, h.IvOrNonce, PaddingMode.PKCS7);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(km);
        }
    }

    // ── v2/v3: AES-GCM (header is GCM AAD) ─────────────────────────────────────
    private static byte[] EncryptGcm(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> password, CryptoVersion version)
    {
        var (iter, hash, keyLen) = Params(version);

        Span<byte> salt = stackalloc byte[SaltLen];
        Span<byte> nonce = stackalloc byte[NonceLen];
        RandomNumberGenerator.Fill(salt);
        RandomNumberGenerator.Fill(nonce);

        Span<byte> kek = stackalloc byte[32]; // sized for the largest version
        Rfc2898DeriveBytes.Pbkdf2(password, salt, kek[..keyLen], iter, hash);

        Span<byte> dek = stackalloc byte[32];
        RandomNumberGenerator.Fill(dek[..keyLen]);
        byte[] wrapped = WrapDek(kek[..keyLen], dek[..keyLen]);

        int headerLen = Prefix + NonceLen + wrapped.Length;
        var blob = new byte[headerLen + plaintext.Length + TagLen];
        WriteHeader(blob, version, iter, salt, nonce, wrapped);

        using var gcm = new AesGcm(dek[..keyLen], TagLen);
        gcm.Encrypt(nonce, plaintext,
            blob.AsSpan(headerLen, plaintext.Length),
            blob.AsSpan(headerLen + plaintext.Length, TagLen),
            blob.AsSpan(0, headerLen));

        CryptographicOperations.ZeroMemory(dek);
        CryptographicOperations.ZeroMemory(kek);
        return blob;
    }

    private static byte[] DecryptGcm(ReadOnlySpan<byte> blob, ReadOnlySpan<char> password, CryptoBlobHeader h)
    {
        var (_, hash, keyLen) = Params(h.Version);
        var wrapped = blob.Slice(h.WrappedDekOffset, h.WrappedDekLength);
        var ct = blob.Slice(h.HeaderLength, h.CiphertextLength);
        var tag = blob.Slice(h.HeaderLength + h.CiphertextLength, h.AuthDataLength);

        Span<byte> kek = stackalloc byte[32];
        Rfc2898DeriveBytes.Pbkdf2(password, h.Salt, kek[..keyLen], h.Iterations, hash);

        byte[] dek = UnwrapDek(kek[..keyLen], wrapped);
        try
        {
            var pt = new byte[ct.Length];
            using var gcm = new AesGcm(dek, TagLen);
            gcm.Decrypt(h.IvOrNonce, ct, tag, pt, blob[..h.HeaderLength]); // throws on auth failure
            return pt;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    private static CryptoBlobHeader ParseHeader(ReadOnlySpan<byte> blob)
    {
        if (blob.Length < MagicLen + 1 || !blob[..MagicLen].SequenceEqual(Magic))
            throw new CryptographicException("Unsupported blob format.");

        var version = (CryptoVersion)blob[MagicLen];
        if (version is not (CryptoVersion.V1 or CryptoVersion.V2 or CryptoVersion.V3))
            throw new CryptographicException($"Unsupported blob version {(byte)version}.");

        var (_, _, keyLen) = Params(version);
        int ivLen = version == CryptoVersion.V1 ? IvLen : NonceLen;
        int authLen = version == CryptoVersion.V1 ? MacLen : TagLen;
        int wrappedLen = keyLen + 8; // RFC 5649 AIV / integrity block
        int headerLen = Prefix + ivLen + wrappedLen;

        if (blob.Length < headerLen + authLen)
            throw new CryptographicException($"{version} blob is truncated.");

        int iter = BinaryPrimitives.ReadInt32BigEndian(blob.Slice(MagicLen + 1, IterLen));
        if (iter is < MinIter or > MaxIter)
            throw new CryptographicException($"{version} PBKDF2 iteration count is outside the supported range.");

        return new CryptoBlobHeader(
            Version: version,
            Iterations: iter,
            Salt: blob.Slice(MagicLen + 1 + IterLen, SaltLen).ToArray(),
            IvOrNonce: blob.Slice(Prefix, ivLen).ToArray(),
            HeaderLength: headerLen,
            WrappedDekOffset: Prefix + ivLen,
            WrappedDekLength: wrappedLen,
            CiphertextLength: blob.Length - headerLen - authLen,
            AuthDataLength: authLen);
    }

    private static (int Iter, HashAlgorithmName Hash, int KeyLen) Params(CryptoVersion v) => v switch
    {
        CryptoVersion.V1 => (10_000, HashAlgorithmName.SHA1, 16),
        CryptoVersion.V2 => (100_000, HashAlgorithmName.SHA256, 16),
        CryptoVersion.V3 => (300_000, HashAlgorithmName.SHA384, 32),
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    private static void WriteHeader(Span<byte> dst, CryptoVersion version, int iter,
        ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ivOrNonce, ReadOnlySpan<byte> wrapped)
    {
        Magic.CopyTo(dst);
        dst[MagicLen] = (byte)version;
        BinaryPrimitives.WriteInt32BigEndian(dst.Slice(MagicLen + 1, IterLen), iter);
        salt.CopyTo(dst[(MagicLen + 1 + IterLen)..]);
        ivOrNonce.CopyTo(dst[Prefix..]);
        wrapped.CopyTo(dst[(Prefix + ivOrNonce.Length)..]);
    }

    private static byte[] WrapDek(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> dek)
    {
        using var aes = Aes.Create();
        aes.Key = kek.ToArray();
        return aes.EncryptKeyWrapPadded(dek);
    }

    private static byte[] UnwrapDek(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        using var aes = Aes.Create();
        aes.Key = kek.ToArray();
        return aes.DecryptKeyWrapPadded(wrapped);
    }
}
