using System.Security.Cryptography;
using Crypto;

return Run(args);

static int Run(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        PrintUsage();
        return args.Length == 0 ? 1 : 0;
    }

    string command = args[0].ToLowerInvariant();

    try
    {
        return command switch
        {
            "encrypt" => EncryptFile(args),
            "decrypt" => DecryptFile(args),
            "inspect" => InspectFile(args),
            _ => UsageError($"Unknown command '{args[0]}'."),
        };
    }
    catch (CryptographicException ex) when (command == "inspect")
    {
        Console.Error.WriteLine($"Inspect failed: {ex.Message}");
        return 2;
    }
    catch (CryptographicException)
    {
        Console.Error.WriteLine("Decryption failed: wrong password, unsupported format, or corrupted file.");
        return 2;
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static int EncryptFile(string[] args)
{
    if (args.Length != 4)
        return UsageError("encrypt requires: <v1|v2|v3> <password> <filename>");

    CryptoVersion version = ParseVersion(args[1]);
    string password = args[2];
    string inputPath = args[3];
    string outputPath = inputPath + ".enc";

    if (!File.Exists(inputPath))
        throw new FileNotFoundException($"Input file not found: {inputPath}", inputPath);
    if (File.Exists(outputPath))
        throw new IOException($"Output file already exists: {outputPath}");

    byte[] plaintext = File.ReadAllBytes(inputPath);
    byte[] encrypted = CryptoBlob.Encrypt(plaintext, password, version);
    WriteNewFile(outputPath, encrypted);

    Console.WriteLine($"Encrypted {inputPath} to {outputPath} using {version}.");
    return 0;
}

static int DecryptFile(string[] args)
{
    if (args.Length != 3)
        return UsageError("decrypt requires: <password> <filename.enc>");

    string password = args[1];
    string inputPath = args[2];
    string outputPath = GetDecryptedPath(inputPath);

    if (!File.Exists(inputPath))
        throw new FileNotFoundException($"Input file not found: {inputPath}", inputPath);
    if (File.Exists(outputPath))
        throw new IOException($"Output file already exists: {outputPath}. Delete or rename it before decrypting.");

    byte[] encrypted = File.ReadAllBytes(inputPath);
    byte[] plaintext = CryptoBlob.Decrypt(encrypted, password);
    WriteNewFile(outputPath, plaintext);

    Console.WriteLine($"Decrypted {inputPath} to {outputPath}.");
    return 0;
}

static int InspectFile(string[] args)
{
    if (args.Length != 2)
        return UsageError("inspect requires: <filename.enc>");

    string inputPath = args[1];
    if (!File.Exists(inputPath))
        throw new FileNotFoundException($"Input file not found: {inputPath}", inputPath);

    byte[] encrypted = File.ReadAllBytes(inputPath);
    CryptoBlobHeader header = CryptoBlob.Inspect(encrypted);
    PrintHeader(inputPath, header);
    return 0;
}

static CryptoVersion ParseVersion(string value) => value.ToLowerInvariant() switch
{
    "1" or "v1" => CryptoVersion.V1,
    "2" or "v2" => CryptoVersion.V2,
    "3" or "v3" => CryptoVersion.V3,
    _ => throw new ArgumentException($"Unsupported version '{value}'. Use v1, v2, or v3."),
};

static string GetDecryptedPath(string inputPath) =>
    inputPath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase)
        ? inputPath[..^4]
        : inputPath + ".dec";

static void WriteNewFile(string outputPath, byte[] contents)
{
    string tempPath = outputPath + ".tmp";
    try
    {
        File.WriteAllBytes(tempPath, contents);
        File.Move(tempPath, outputPath);
    }
    catch
    {
        if (File.Exists(tempPath))
            File.Delete(tempPath);
        throw;
    }
}

static int UsageError(string message)
{
    Console.Error.WriteLine(message);
    PrintUsage();
    return 1;
}

static void PrintHeader(string inputPath, CryptoBlobHeader header)
{
    Console.WriteLine($"File: {inputPath}");
    Console.WriteLine($"Magic: {header.Magic}");
    Console.WriteLine($"Version: v{(byte)header.Version}");
    Console.WriteLine($"Password KDF: {header.PasswordKdf}");
    Console.WriteLine($"Iterations: {header.Iterations}");
    Console.WriteLine($"Salt: {Convert.ToHexString(header.Salt)}");
    Console.WriteLine($"{header.IvOrNonceName}: {Convert.ToHexString(header.IvOrNonce)}");
    Console.WriteLine($"Key wrap: {header.KeyWrap}");
    Console.WriteLine($"Content encryption: {header.ContentEncryption}");
    Console.WriteLine($"Authentication: {header.Authentication}");
    Console.WriteLine($"Header length: {header.HeaderLength} bytes");
    Console.WriteLine($"Wrapped DEK length: {header.WrappedDekLength} bytes");
    Console.WriteLine($"Ciphertext length: {header.CiphertextLength} bytes");
    Console.WriteLine($"{header.AuthDataName} length: {header.AuthDataLength} bytes");
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        Usage:
          Crypto encrypt <v1|v2|v3> <password> <filename>
          Crypto decrypt <password> <filename.enc>
          Crypto inspect <filename.enc>

        encrypt writes <filename>.enc and stores the format magic, version, PBKDF2
        iteration count, salt, IV or nonce, wrapped DEK, ciphertext, and auth tag.
        decrypt writes the original filename by removing
        the .enc suffix, or appends .dec when the input name does not end in .enc.
        inspect prints the public crypto header metadata without decrypting.
        Existing output files are not overwritten.
        """);
}
