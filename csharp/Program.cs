using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int IterCount = 4096;

    static void Main(string[] args)
    {
        string passphrase = "passphrase";
        string plaintext = "plaintext";
        Console.WriteLine($"passphrase: {passphrase}");
        Console.WriteLine($"plaintext: {plaintext}");

        try
        {
            string encrypted = Encrypt(passphrase, plaintext);
            Console.WriteLine($"encrypted: {encrypted}");

            string decrypted = Decrypt(passphrase, encrypted);
            Console.WriteLine($"decrypted: {decrypted}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
        }
    }

    static string Encrypt(string passphrase, string plaintext)
    {
        byte[] salt = new byte[SaltSize];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        byte[] key = DeriveKey(passphrase, salt);

        byte[] nonce = new byte[NonceSize];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(nonce);
        }

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] ciphertext = new byte[plaintextBytes.Length];
        byte[] tag = new byte[TagSize];

        using (var aesGcm = new AesGcm(key, TagSize))
        {
            aesGcm.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }

        byte[] result = new byte[SaltSize + NonceSize + ciphertext.Length + TagSize];
        Buffer.BlockCopy(salt, 0, result, 0, SaltSize);
        Buffer.BlockCopy(nonce, 0, result, SaltSize, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, result, SaltSize + NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, SaltSize + NonceSize + ciphertext.Length, TagSize);

        return Convert.ToHexString(result).ToLower();
    }

    static string Decrypt(string passphrase, string encodedText)
    {
        byte[] result = Convert.FromHexString(encodedText);

        byte[] salt = new byte[SaltSize];
        Buffer.BlockCopy(result, 0, salt, 0, SaltSize);

        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(result, SaltSize, nonce, 0, NonceSize);

        int ciphertextLength = result.Length - SaltSize - NonceSize - TagSize;
        byte[] ciphertext = new byte[ciphertextLength];
        Buffer.BlockCopy(result, SaltSize + NonceSize, ciphertext, 0, ciphertextLength);

        byte[] tag = new byte[TagSize];
        Buffer.BlockCopy(result, result.Length - TagSize, tag, 0, TagSize);

        byte[] key = DeriveKey(passphrase, salt);

        byte[] plaintextBytes = new byte[ciphertextLength];

        using (var aesGcm = new AesGcm(key, TagSize))
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintextBytes);
        }

        return Encoding.UTF8.GetString(plaintextBytes);
    }

    static byte[] DeriveKey(string passphrase, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(passphrase),
            salt,
            IterCount,
            HashAlgorithmName.SHA256,
            KeySize);
    }
}
