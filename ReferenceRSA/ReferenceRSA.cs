using System.Security.Cryptography;
using RSA.commons;

namespace ReferenceRSA;

public class ReferenceRSA : ICommonRSA
{
    private readonly System.Security.Cryptography.RSA _refRSA = System.Security.Cryptography.RSA.Create();

    public string EncryptString(string pubKey, string plainText)
    {
        if (!pubKey.Contains("-----BEGIN PUBLIC KEY-----"))
        {
            pubKey = pubKey.Replace("\n", "").Replace("\r", "");
            string formattedKey = "-----BEGIN PUBLIC KEY-----\n";
            for (int i = 0; i < pubKey.Length; i += 64)
            {
                formattedKey += pubKey.Substring(i, Math.Min(64, pubKey.Length - i)) + "\n";
            }
            formattedKey += "-----END PUBLIC KEY-----";
            pubKey = formattedKey;
        }
        _refRSA.ImportFromPem(pubKey);
        byte [] plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
        byte [] encryptedTextBytes = _refRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);
        return Convert.ToBase64String(encryptedTextBytes);
    }

    public string DecryptString(string privKey, string cipherText)
    {
        if (!privKey.Contains("-----BEGIN PRIVATE KEY-----"))
        {
            // Clean the input (remove any existing newlines)
            privKey = privKey.Replace("\n", "").Replace("\r", "");
        
            // Format the key with proper PEM line breaks (64 chars per line)
            string formattedKey = "-----BEGIN PRIVATE KEY-----\n";
            for (int i = 0; i < privKey.Length; i += 64)
            {
                formattedKey += privKey.Substring(i, Math.Min(64, privKey.Length - i)) + "\n";
            }
            formattedKey += "-----END PRIVATE KEY-----";
            privKey = formattedKey;
        }
        _refRSA.ImportFromPem(privKey);
        byte [] encryptedTextBytes = Convert.FromBase64String(cipherText);
        byte [] plainTextBytes = _refRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.Pkcs1);
        return System.Text.Encoding.UTF8.GetString(plainTextBytes);
    }
}