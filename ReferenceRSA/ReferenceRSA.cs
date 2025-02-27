using System.Security.Cryptography;
using RSA.commons; // Use our own RSA.commons namespace for the RSAUtils class and the ICommonRSA interface

namespace ReferenceRSA;

// Class that handles RSA encryption and decryption using the reference methods from the .NET library and implements the same ICommonRSA interface used by the self-written RSA class
public class ReferenceRSA : ICommonRSA
{
    // Get a reference to the RSA class from the .NET library
    private readonly System.Security.Cryptography.RSA _refRSA = System.Security.Cryptography.RSA.Create();

    // Method that takes a public key (filepath, PEM or shortened PEM) and a plaintext string and returns the encrypted string
    public string EncryptString(string pubKey, string plainText)
    {
        pubKey = RSAUtils.sanitizePublicKeyInput(pubKey);
        _refRSA.ImportFromPem(pubKey);
        byte [] plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
        byte [] encryptedTextBytes = _refRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);
        return Convert.ToBase64String(encryptedTextBytes);
    }

    // Method that takes a private key (filepath, PEM or shortened PEM) and a ciphertext string and returns the decrypted string
    public string DecryptString(string privKey, string cipherText)
    {
        privKey = RSAUtils.sanitizePrivateKeyInput(privKey);
        _refRSA.ImportFromPem(privKey);
        byte [] encryptedTextBytes = Convert.FromBase64String(cipherText);
        byte [] plainTextBytes = _refRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.Pkcs1);
        return System.Text.Encoding.UTF8.GetString(plainTextBytes);
    }
}