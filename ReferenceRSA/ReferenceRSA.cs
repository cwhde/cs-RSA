using System.Security.Cryptography;
using RSA.commons; // Own common RSA resources, Interface and Utils

namespace ReferenceRSA;

// Reference RSA Implementation using .NET Libraries
public class ReferenceRSA : ICommonRSA
{
    private readonly System.Security.Cryptography.RSA _referenceRSA = System.Security.Cryptography.RSA.Create();

    // Method that takes a public key (filepath, PEM or shortened PEM) and a plaintext string and returns the encrypted string
    public string EncryptString(string publicKey, string paddingMode, string plainText)
    {
        // Check if padding is valid
        string[] validPaddings = RSAUtils.GetValidPaddings();
        if (!validPaddings.Contains(paddingMode.ToLower()))
        {
            throw new ArgumentException("Padding mode invalid", nameof(paddingMode)); // Throw an exception if the padding is not allowed
        }
        
        publicKey = RSAUtils.SanitizeKeyInput(inputKey: publicKey, isPublic: true);
        _referenceRSA.ImportFromPem(publicKey);
            
        byte [] plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
        byte [] cypherTextBytes = [0];
        switch (paddingMode.ToLower())
        {
            case "pkcs1":
                cypherTextBytes = _referenceRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.Pkcs1);
                break;
            case "oaepsha1":
                cypherTextBytes = _referenceRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.OaepSHA1);
                break;
            case "oaepsha256":
                cypherTextBytes = _referenceRSA.Encrypt(plainTextBytes, RSAEncryptionPadding.OaepSHA256);
                break;
        }
        
        return Convert.ToBase64String(cypherTextBytes);
    }

    // Method that takes a private key (filepath, PEM or shortened PEM) and a ciphertext string and returns the decrypted string
    public string DecryptString(string privateKey, string paddingMode, string cipherText)
    {
        // Check if padding is valid
        string[] validPaddings = RSAUtils.GetValidPaddings();
        if (!validPaddings.Contains(paddingMode.ToLower()))
        {
            throw new ArgumentException("Padding mode not allowed", nameof(paddingMode));
        }
        
        privateKey = RSAUtils.SanitizeKeyInput(inputKey: privateKey,isPublic: false);
        _referenceRSA.ImportFromPem(privateKey);
        
        byte [] encryptedTextBytes = Convert.FromBase64String(cipherText);
        byte [] plainTextBytes = [0];
        switch (paddingMode.ToLower())
        {
            case "pkcs1":
                plainTextBytes = _referenceRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.Pkcs1);
                break;
            case "oaepsha1":
                plainTextBytes = _referenceRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.OaepSHA1);
                break;
            case "oaepsha256":
                plainTextBytes = _referenceRSA.Decrypt(encryptedTextBytes, RSAEncryptionPadding.OaepSHA256);
                break;
        }
        
        return System.Text.Encoding.UTF8.GetString(plainTextBytes);
    }
    
    // Method that generates a key pair of the specified size and returns the public and private pem keys as strings
    public (string publicKey, string privateKey) GenerateKeys(int keySize)
    {
        _referenceRSA.KeySize = keySize;
        System.Security.Cryptography.RSA RSAKeyInstance = System.Security.Cryptography.RSA.Create(keySizeInBits: keySize);
        string publicKey = RSAKeyInstance.ExportRSAPublicKeyPem();
        string privateKey = RSAKeyInstance.ExportRSAPrivateKeyPem();
        return (publicKey, privateKey);
    }
}