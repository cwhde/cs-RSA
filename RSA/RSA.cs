using System.Formats.Asn1;
using System.Numerics;
using System.Text;
using RSA.commons; // Use our own RSA.commons namespace for the RSAUtils class and the ICommonRSA interface

namespace RSA;

public class RSA : ICommonRSA
{
    // Random object for paddings
    private readonly Random _random = new();
    
    // Method that takes a public key (filepath, PEM or shortened PEM) and a plaintext string and returns the encrypted string
    public string EncryptString(string pubKey, string padding, string plainText)
    {
        string[] allowedPaddings = RSAUtils.AllowedPaddings(); // Get the allowed paddings
        if (!allowedPaddings.Contains(padding.ToLower())) // Check if the set padding is part of the allowed paddings
        {
            throw new ArgumentException("Padding mode not allowed", nameof(padding)); // Throw an exception if the padding is not allowed
        }
        pubKey = RSAUtils.SanitizeKeyInput(pubKey, true); // Sanitize input and set it as public key
        // Get key components
        (BigInteger n, BigInteger e, int keySize) = ParsePublicKey(pubKey);
        // Convert the plaintext to a byte array
        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        // Apply padding
        switch (padding.ToLower())
        {
            case "pkcs1":
                plainTextBytes = ApplyPadding(plainTextBytes, keySize, "pkcs1");
                break;
            case "oaepsha1":
                plainTextBytes = ApplyPadding(plainTextBytes, keySize, "oaepsha1");
                break;
            case "oaepsha256":
                plainTextBytes = ApplyPadding(plainTextBytes, keySize, "oaepsha256");
                break;
        }
        // Encrypt the padded data
        byte[] encryptedBytes = EncryptBytes(plainTextBytes, n, e, keySize);
        // Convert the encrypted bytes to a base64 string and return it
        return Convert.ToBase64String(encryptedBytes);
    }
    
    // Method that takes a private key (filepath, PEM or shortened PEM) and a ciphertext string and returns the decrypted string
    public string DecryptString(string privKey, string padding, string cipherText)
    {
        string[] allowedPaddings = RSAUtils.AllowedPaddings(); // Get the allowed paddings
        if (!allowedPaddings.Contains(padding.ToLower()))      // Check if the set padding is part of the allowed paddings
        {
            throw new ArgumentException("Padding mode not allowed", nameof(padding)); // Throw an exception if the padding is not allowed
        }
        // Get cleaned private key
        privKey = RSAUtils.SanitizeKeyInput(privKey, false);
        // Get key components
        (BigInteger n, BigInteger d, int keySize) = ParsePrivateKey(privKey);
        // Convert the base64 string to a byte array
        byte[] encryptedTextBytes = Convert.FromBase64String(cipherText);
        // Decrypt the data
        byte[] decryptedBytes = DecryptBytes(encryptedTextBytes, n, d, keySize);
        // Remove padding
        switch (padding.ToLower())
        {
            case "pkcs1":
                decryptedBytes = RemovePadding(decryptedBytes, keySize, "pkcs1");
                break;
            case "oaepsha1":
                decryptedBytes = RemovePadding(decryptedBytes, keySize, "oaepsha1");
                break;
            case "oaepsha256":
                decryptedBytes = RemovePadding(decryptedBytes, keySize, "oaepsha256");
                break;
        }
        // Convert the decrypted bytes to a string and return it
        return Encoding.UTF8.GetString(decryptedBytes);
    }
    
    // Method that takes a byte array (padding has to be applied already), a factor n and a factor e and returns the encrypted byte array
    private byte[] EncryptBytes(byte[] data, BigInteger n, BigInteger e, int keySize)
    {
        // Block size is key size in bytes
        int blockSize = keySize / 8; 
        List<byte[]> encryptedChunks = new();
        // Iterate through the data in chunks of blockSize
        for (int i = 0; i < data.Length; i += blockSize)
        {
            byte[] chunk = data.Skip(i).Take(blockSize).ToArray();
            // Create BigInteger with the big endian
            BigInteger bigEndianData = new(chunk, isUnsigned: true, isBigEndian: true);
            BigInteger encrypted = BigInteger.ModPow(bigEndianData, e, n);
            // Convert to byte array
            byte[] encryptedBytes = encrypted.ToByteArray(isUnsigned: true, isBigEndian: true);
            // Ensure fixed length output (pad with leading zeros if needed)
            if (encryptedBytes.Length < blockSize)
            {
                byte[] padded = new byte[blockSize];
                Array.Copy(encryptedBytes, 0, padded, blockSize - encryptedBytes.Length, encryptedBytes.Length);
                encryptedBytes = padded;
            }
            else if (encryptedBytes.Length > blockSize)
            {
                // Trim any excess bytes (should not happen with proper RSA)
                encryptedBytes = encryptedBytes.Skip(encryptedBytes.Length - blockSize).ToArray();
            }
            // Add to the rest of the data
            encryptedChunks.Add(encryptedBytes);
        }
        return encryptedChunks.SelectMany(x => x).ToArray();
    }
    
    // Method that takes a byte array, a factor n and a factor d and returns the decrypted byte array (padding has to be handled afterward)
    private byte[] DecryptBytes(byte[] data, BigInteger n, BigInteger d, int keySize)
    {
        // Figure out chunk size
        int blockSize = keySize/8;
        // Initialize the list for the decrypted chunks
        List<byte[]> decryptedChunks = new();
        // Loop through the data in chunks
        for (int i = 0; i < data.Length; i += blockSize)
        {
            // Get the chunk
            byte[] chunk = data.Skip(i).Take(blockSize).ToArray();
            // Decrypt the chunk
            BigInteger encrypted = new(chunk, isUnsigned: true, isBigEndian: true);
            BigInteger decrypted = BigInteger.ModPow(encrypted, d, n);            
            byte[] decryptedBytes = decrypted.ToByteArray(isUnsigned: true, isBigEndian: true);
            // Pad to block size if needed
            if (decryptedBytes.Length < blockSize)
            {
                byte[] padded = new byte[blockSize];
                Array.Copy(decryptedBytes, 0, padded, blockSize - decryptedBytes.Length, decryptedBytes.Length);
                decryptedBytes = padded;
            }
            decryptedChunks.Add(decryptedBytes);
        }
        // Concatenate the decrypted chunks and return
        return decryptedChunks.SelectMany(x => x).ToArray();
    }
    
    private byte[] ApplyPadding(byte[] data, int keySize, string padding)
    {
        return padding.ToLower() switch
        {
            "pkcs1" => ApplyPkcs1Padding(data, keySize),
            "oaepsha1" => ApplyOaepSha1Padding(data, keySize),
            "oaepsha256" => ApplyOaepSha256Padding(data, keySize),
            _ => throw new ArgumentException("Unsupported padding type")
        };
    }

    private byte[] ApplyPkcs1Padding(byte[] data, int keySize)
    {
        int blockSize = keySize / 8; // Block size is the key's size in bytesEncryptBytes
        int paddingOverhead = 11; // Pkcs1 padding is at least 11 bytes long
        int maxDataLength = blockSize - paddingOverhead; // In a normal block the actual data is the block's length minus the padding's length
        int numChunks = (int)Math.Ceiling((double)data.Length / maxDataLength); // Calculate the number of chunks needed
        byte[] paddedData = new byte[numChunks * blockSize];
        for (int i = 0; i < numChunks; i++)
        {
            int offset = i * blockSize; // Offset to navigate the padded data array for the current chunk
            int dataOffset = i * maxDataLength; // Offset  to navigate the data array for the current chunk (different because of missing padding)
            int currentDataLength = Math.Min(maxDataLength, data.Length - dataOffset); // If we're at the end of the data, the padding might be longer as we have less data
            paddedData[offset] = 0x00; // Standard padding starts with 0x00
            paddedData[offset + 1] = 0x02;
            int paddingLength = blockSize - currentDataLength - 3; // The actual random part of the padding is the block size minus the data length minus 0x00, 0x02 and 0x00
            for (int j = 0; j < paddingLength; j++)
            {
                paddedData[offset + 2 + j] = (byte)_random.Next(1, 256);  // Random bytes that make the padding unique, with calculated length of the padding
            }
            paddedData[offset + 2 + paddingLength] = 0x00; // Delimiter between padding and data
            Array.Copy(data, dataOffset, paddedData, offset + 3 + paddingLength, currentDataLength); // Insert the actual data of the chunk
        }
        return paddedData;
    }

    private byte[] ApplyOaepSha1Padding(byte[] data, int keySize)
    {
        // Implement OAEP SHA-1 padding logic here
        throw new NotImplementedException();
    }

    private byte[] ApplyOaepSha256Padding(byte[] data, int keySize)
    {
        // Implement OAEP SHA-256 padding logic here
        throw new NotImplementedException();
    }
    
    private byte[] RemovePadding(byte[] data, int keySize, string padding)
    {
        return padding.ToLower() switch
        {
            "pkcs1" => RemovePkcs1Padding(data, keySize),
            "oaepsha1" => RemoveOaepSha1Padding(data, keySize),
            "oaepsha256" => RemoveOaepSha256Padding(data, keySize),
            _ => throw new ArgumentException("Unsupported padding type")
        };
    }

    private byte[] RemovePkcs1Padding(byte[] data, int keySize)
    {
        int blockSize = keySize / 8; // Block size is the key's size in bytes
        int paddingOverhead = 11; // Pkcs1 padding is at least 11 bytes long
        int numChunks = data.Length / blockSize; // Calculate the number of chunks
        List<byte[]> unpaddedChunks = new();
        for (int i = 0; i < numChunks; i++)
        {
            int offset = i * blockSize; // Offset to navigate the padded data array for the current chunk
            int paddingStart = offset + 2; // The padding starts at the third byte
            // Find the 0x00 delimiter between padding and data
            int delimiterIndex = Array.IndexOf(data, (byte)0x00, paddingStart, (offset + blockSize) - paddingStart);
            // Find the actual data start
            int dataStart = delimiterIndex + 1;
            // Calculate data length correctly
            int dataLength = (offset + blockSize) - dataStart;
            // Copy the data to a new array
            byte[] unpaddedChunk = new byte[dataLength];
            Array.Copy(data, dataStart, unpaddedChunk, 0, dataLength);
            unpaddedChunks.Add(unpaddedChunk);
        }
        return unpaddedChunks.SelectMany(x => x).ToArray();
    }

    private byte[] RemoveOaepSha1Padding(byte[] data, int keySize)
    {
        throw new NotImplementedException();
    }

    private byte[] RemoveOaepSha256Padding(byte[] data, int keySize)
    {
        throw new NotImplementedException();
    }
    
    private (BigInteger n, BigInteger e, int keySize) ParsePublicKey(string pubKey)
    {
        // Remove the PEM header and footer and all line breaks and spaces
        string pem = pubKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "").Replace(" ", "");
        // Decode the base64 string into a dynamic list of bytes that represents the ASN.1 data
        byte[] asn1Data = Convert.FromBase64String(pem);
        // Create an AsnReader as an own implementation is too complex for now
        AsnReader reader = new(asn1Data, AsnEncodingRules.DER);
        // Read the outer SEQUENCE
        AsnReader sequence = reader.ReadSequence();
        // Skip the algorithm identifier SEQUENCE
        sequence.ReadSequence();
        // Get the BIT STRING containing the key data
        byte[] keyData = sequence.ReadBitString(out int unused);
        // Create a new reader for the key data SEQUENCE
        AsnReader keyReader = new(keyData, AsnEncodingRules.DER);
        AsnReader keySequence = keyReader.ReadSequence();
        // Get ByteArray and remove leading zero
        byte[] modulusBytes = keySequence.ReadIntegerBytes().ToArray();
        if (modulusBytes[0] == 0) modulusBytes = modulusBytes[1..];
        // Read modulus and exponent as unsigned integers in the right format
        BigInteger n = new(modulusBytes, isUnsigned: true, isBigEndian: true);
        // Read next integer as exponent
        byte[] exponentBytes = keySequence.ReadIntegerBytes().ToArray();
        BigInteger e = new(exponentBytes, isUnsigned: true, isBigEndian: true);
        // Calculate key size in bits
        int keySize = modulusBytes.Length * 8;
        return (n, e, keySize);
    }
    
    private (BigInteger n, BigInteger d, int keySize) ParsePrivateKey(string privKey)
    {
        // Remove the PEM header and footer and all line breaks and spaces
        string pem = privKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "").Replace("\n", "").Replace("\r", "").Replace(" ", "");
        // Decode the base64 string into a dynamic list of bytes that represents the ASN.1 data
        byte[] asn1Data = Convert.FromBase64String(pem);
        // Create an AsnReader for the entire structure
        AsnReader reader = new(asn1Data, AsnEncodingRules.DER);
        // Read the outer SEQUENCE
        AsnReader sequence = reader.ReadSequence();
        // Skip the version INTEGER
        sequence.ReadInteger();
        // Skip the algorithm identifier SEQUENCE
        sequence.ReadSequence();
        // Get the OCTET STRING containing the private key data
        byte[] privateKeyData = sequence.ReadOctetString();
        // Create a new reader for the private key data
        AsnReader privateKeyReader = new(privateKeyData, AsnEncodingRules.DER);
        // Read the RSAPrivateKey SEQUENCE
        AsnReader keySequence = privateKeyReader.ReadSequence();
        // Skip the version INTEGER
        keySequence.ReadInteger();
        // Read the modulus (n)
        byte[] modulusBytes = keySequence.ReadIntegerBytes().ToArray();
        if (modulusBytes[0] == 0) modulusBytes = modulusBytes[1..];
        BigInteger n = new(modulusBytes, isUnsigned: true, isBigEndian: true);
        // Skip public exponent (e)
        keySequence.ReadInteger();
        // Read the private exponent (d)
        byte[] privateExponentBytes = keySequence.ReadIntegerBytes().ToArray();
        if (privateExponentBytes[0] == 0) privateExponentBytes = privateExponentBytes[1..];
        BigInteger d = new(privateExponentBytes, isUnsigned: true, isBigEndian: true);
        // Calculate key size in bits
        int keySize = modulusBytes.Length * 8;
        return (n, d, keySize);
    }
}