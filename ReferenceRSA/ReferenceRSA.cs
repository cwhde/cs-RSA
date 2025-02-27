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
        pubKey = RSAUtils.sanitizeKeyInput(pubKey, true); // Sanitize input and set it as public key
        _refRSA.ImportFromPem(pubKey); // Import the pem key
        byte [] plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText); // Convert the string to a byte-array
        byte [] encryptedTextBytes = _refRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1); // Encrypt the bytes
        return Convert.ToBase64String(encryptedTextBytes); // Convert the bytes to a base64 string and return it
    }

    // Method that takes a private key (filepath, PEM or shortened PEM) and a ciphertext string and returns the decrypted string
    public string DecryptString(string privKey, string cipherText)
    {
        privKey = RSAUtils.sanitizeKeyInput(privKey,false); // Sanitize input and set it as private (not public) key
        _refRSA.ImportFromPem(privKey); // Import the pem key
        byte [] encryptedTextBytes = Convert.FromBase64String(cipherText); // Convert the base64 string to a byte-array
        byte [] plainTextBytes = _refRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.Pkcs1); // Decrypt the bytes
        return System.Text.Encoding.UTF8.GetString(plainTextBytes); // Parse the bytes as UTF-8 and return the string
    }
}