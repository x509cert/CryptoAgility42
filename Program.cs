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

    try
    {
        return args[0].ToLowerInvariant() switch
        {
            "encrypt" => EncryptFile(args),
            "decrypt" => DecryptFile(args),
            _ => UsageError($"Unknown command '{args[0]}'."),
        };
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
    if (args.Length != 2)
        return UsageError("decrypt requires: <filename.enc>");

    string inputPath = args[1];
    string outputPath = GetDecryptedPath(inputPath);

    if (!File.Exists(inputPath))
        throw new FileNotFoundException($"Input file not found: {inputPath}", inputPath);
    if (File.Exists(outputPath))
        throw new IOException($"Output file already exists: {outputPath}");

    string password = ReadPassword("Password: ");
    byte[] encrypted = File.ReadAllBytes(inputPath);
    byte[] plaintext = CryptoBlob.Decrypt(encrypted, password);
    WriteNewFile(outputPath, plaintext);

    Console.WriteLine($"Decrypted {inputPath} to {outputPath}.");
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

static string ReadPassword(string prompt)
{
    Console.Error.Write(prompt);
    if (Console.IsInputRedirected)
        return Console.ReadLine() ?? string.Empty;

    var password = new List<char>();
    while (true)
    {
        ConsoleKeyInfo key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter)
        {
            Console.Error.WriteLine();
            return new string(password.ToArray());
        }

        if (key.Key == ConsoleKey.Backspace)
        {
            if (password.Count > 0)
                password.RemoveAt(password.Count - 1);
            continue;
        }

        if (!char.IsControl(key.KeyChar))
            password.Add(key.KeyChar);
    }
}

static int UsageError(string message)
{
    Console.Error.WriteLine(message);
    PrintUsage();
    return 1;
}

static void PrintUsage()
{
    Console.Error.WriteLine("""
        Usage:
          Crypto encrypt <v1|v2|v3> <password> <filename>
          Crypto decrypt <filename.enc>

        encrypt writes <filename>.enc and stores the format magic, version, PBKDF2
        iteration count, salt, IV or nonce, wrapped DEK, ciphertext, and auth tag.
        decrypt prompts for the password and writes the original filename by removing
        the .enc suffix, or appends .dec when the input name does not end in .enc.
        Existing output files are not overwritten.
        """);
}
