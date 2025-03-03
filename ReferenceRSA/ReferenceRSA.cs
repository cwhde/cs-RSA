using System.Security.Cryptography;
using RSA.commons; // Use our own RSA.commons namespace for the RSAUtils class and the ICommonRSA interface

namespace ReferenceRSA;

// Class that handles RSA encryption and decryption using the reference methods from the .NET library and implements the same ICommonRSA interface used by the self-written RSA class
public class ReferenceRSA : ICommonRSA
{
    // Get a reference to the RSA class from the .NET library
    private readonly System.Security.Cryptography.RSA _refRSA = System.Security.Cryptography.RSA.Create();

    // Method that takes a public key (filepath, PEM or shortened PEM) and a plaintext string and returns the encrypted string
    public string EncryptString(string pubKey, string padding, string plainText)
    {
        string[] allowedPaddings = RSAUtils.AllowedPaddings(); // Get the allowed paddings
        if (!allowedPaddings.Contains(padding.ToLower())) // Check if the set padding is part of the allowed paddings
        {
            throw new ArgumentException("Padding mode not allowed", nameof(padding)); // Throw an exception if the padding is not allowed
        }
        pubKey = RSAUtils.SanitizeKeyInput(pubKey, true); // Sanitize input and set it as public key
        _refRSA.ImportFromPem(pubKey); // Import the pem key
        byte [] plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText); // Convert the string to a byte-array
        switch (padding.ToLower())
        {
            case "pkcs1":
                plainTextBytes = _refRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1); // Decrypt the bytes using PKCS1 padding
                break;
            case "oaepsha1":
                plainTextBytes = _refRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.OaepSHA1); // Decrypt the bytes using OAEP with SHA1 padding
                break;
            case "oaepsha256":
                plainTextBytes = _refRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.OaepSHA256); // Decrypt the bytes using OAEP with SHA256 padding
                break;
        }
        return Convert.ToBase64String(plainTextBytes); // Convert the bytes to a base64 string and return it
    }

    // Method that takes a private key (filepath, PEM or shortened PEM) and a ciphertext string and returns the decrypted string
    public string DecryptString(string privKey, string padding, string cipherText)
    {
        string[] allowedPaddings = RSAUtils.AllowedPaddings(); // Get the allowed paddings
        if (!allowedPaddings.Contains(padding.ToLower()))      // Check if the set padding is part of the allowed paddings
        {
            throw new ArgumentException("Padding mode not allowed", nameof(padding)); // Throw an exception if the padding is not allowed
        }
        privKey = RSAUtils.SanitizeKeyInput(privKey,false); // Sanitize input and set it as private (not public) key
        _refRSA.ImportFromPem(privKey); // Import the pem key
        byte [] encryptedTextBytes = Convert.FromBase64String(cipherText); // Convert the base64 string to a byte-array
        byte [] plainTextBytes = [0]; // Initialize the byte-array for the decrypted bytes, assign a value to prevent IDE warnings
        switch (padding.ToLower())
        {
            case "pkcs1":
                plainTextBytes = _refRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.Pkcs1); // Decrypt the bytes using PKCS1 padding
                break;
            case "oaepsha1":
                plainTextBytes = _refRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.OaepSHA1); // Decrypt the bytes using OAEP with SHA1 padding
                break;
            case "oaepsha256":
                plainTextBytes = _refRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.OaepSHA256); // Decrypt the bytes using OAEP with SHA256 padding
                break;
        }
        return System.Text.Encoding.UTF8.GetString(plainTextBytes); // Parse the bytes as UTF-8 and return the string
    }
}