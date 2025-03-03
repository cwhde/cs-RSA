using System.Formats.Asn1;
using System.Numerics;
using System.Text;
using RSA.commons; // Own common RSA resources, Interface and Utils

namespace RSA;

public class RSA : ICommonRSA
{
    private readonly Random _random = new Random();
    
    // Method that takes a public key (filepath, PEM or shortened PEM) and a plaintext string and returns the encrypted string
    public string EncryptString(string publicKey, string paddingMode, string plainText)
    {
        // Check if padding is valid
        string[] validPaddings = RSAUtils.ValidPaddings();
        if (!validPaddings.Contains(paddingMode.ToLower()))
        {
            throw new ArgumentException("Padding mode not allowed", nameof(paddingMode));
        }
        
        // Clean and parse the public key
        publicKey = RSAUtils.SanitizeKeyInput(inputKey: publicKey, isPublic: true);
        (BigInteger modulus, BigInteger publicExponent, int keySize) = ParsePublicKey(publicKey: publicKey);

        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        byte [] paddedTextBytes = ApplyPadding(bytes: plainTextBytes, keySize: keySize, padding: paddingMode.ToLower());
        
        byte[] cypherTextBytes = EncryptBytes(bytes: paddedTextBytes, modulus: modulus, publicExponent: publicExponent, keySize: keySize);

        return Convert.ToBase64String(cypherTextBytes);
    }
    
    // Method that takes a private key (filepath, PEM or shortened PEM) and a ciphertext string and returns the decrypted string
    public string DecryptString(string privateKey, string paddingMode, string cipherText)
    {
        // Check if padding is valid
        string[] validPaddings = RSAUtils.ValidPaddings();
        if (!validPaddings.Contains(paddingMode.ToLower()))
        {
            throw new ArgumentException("Padding mode not allowed", nameof(paddingMode)); // Throw an exception if the padding is not allowed
        }
        
        privateKey = RSAUtils.SanitizeKeyInput(inputKey: privateKey, isPublic: false);
        (BigInteger modulus, BigInteger privateExponent, int keySize) = ParsePrivateKey(privateKey: privateKey);
        
        byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
        byte[] paddedTextBytes = DecryptBytes(bytes: cipherTextBytes, modulus: modulus, privateExponent: privateExponent, keySize: keySize);

        byte[] plainTextBytes = RemovePadding(bytes: paddedTextBytes, keySize: keySize, padding: paddingMode.ToLower());
        
        return Encoding.UTF8.GetString(plainTextBytes);
    }
    
    // Method that takes a byte array (padding has to be applied already), a factor n and a factor e and returns the encrypted byte array
    private static byte[] EncryptBytes(byte[] bytes, BigInteger modulus, BigInteger publicExponent, int keySize)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        List<byte[]> encryptedChunks = new List<byte[]>();
        
        // Iterate through the data in chunks of blockSize
        for (int bytesProcessed = 0; bytesProcessed < bytes.Length; bytesProcessed += chunkSize)
        {
            byte[] currentChunk = bytes.Skip(bytesProcessed).Take(chunkSize).ToArray();

            BigInteger currentChunkEndian = new BigInteger(currentChunk, isUnsigned: true, isBigEndian: true); // Big Endian is the default for RSA
            BigInteger encryptedChunk = BigInteger.ModPow(currentChunkEndian, publicExponent, modulus); // Actual way RSA encrypts data (c = m^e mod n)
            byte[] encryptedBytes = encryptedChunk.ToByteArray(isUnsigned: true, isBigEndian: true);
            
            // Ensure fixed length output (pad with leading zeros if needed)
            if (encryptedBytes.Length < chunkSize)
            {
                byte[] paddedEncryptedBytes = new byte[chunkSize];
                Array.Copy(sourceArray: encryptedBytes, sourceIndex: 0, destinationArray: paddedEncryptedBytes, destinationIndex: (chunkSize - encryptedBytes.Length), length: encryptedBytes.Length);
                encryptedBytes = paddedEncryptedBytes;
            }
            else if (encryptedBytes.Length > chunkSize)
            {
                // Trim any excess bytes (should not happen with proper RSA)
                encryptedBytes = encryptedBytes.Skip(encryptedBytes.Length - chunkSize).ToArray();
            }
            
            encryptedChunks.Add(encryptedBytes);
        }
        
        return encryptedChunks.SelectMany(x => x).ToArray();
    }
    
    // Method that takes a byte array, a factor n and a factor d and returns the decrypted byte array (padding has to be handled afterward)
    private static byte[] DecryptBytes(byte[] bytes, BigInteger modulus, BigInteger privateExponent, int keySize)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        List<byte[]> decryptedChunks = new List<byte[]>();
        
        // Iterate through the data in chunks
        for (int bytesProcessed = 0; bytesProcessed < bytes.Length; bytesProcessed += chunkSize)
        {
            byte[] currentChunk = bytes.Skip(bytesProcessed).Take(chunkSize).ToArray();

            BigInteger currentChunkEndian = new BigInteger(currentChunk, isUnsigned: true, isBigEndian: true); // Big Endian is the default for RSA
            BigInteger decryptedChunk = BigInteger.ModPow(currentChunkEndian, privateExponent, modulus);            
            byte[] decryptedBytes = decryptedChunk.ToByteArray(isUnsigned: true, isBigEndian: true);
            
            // Pad to block size if needed
            if (decryptedBytes.Length < chunkSize)
            {
                byte[] paddedDecryptedBytes = new byte[chunkSize];
                Array.Copy(sourceArray: decryptedBytes, sourceIndex: 0, destinationArray: paddedDecryptedBytes, destinationIndex: (chunkSize - decryptedBytes.Length), length: decryptedBytes.Length);
                decryptedBytes = paddedDecryptedBytes;
            }
            
            decryptedChunks.Add(decryptedBytes);
        }

        return decryptedChunks.SelectMany(x => x).ToArray();
    }
    
    private byte[] ApplyPadding(byte[] bytes, int keySize, string padding)
    {
        return padding.ToLower() switch
        {
            "pkcs1" => ApplyPkcs1Padding(bytes: bytes, keySize: keySize),
            "oaepsha1" => ApplyOaepSha1Padding(bytes: bytes, keySize: keySize),
            "oaepsha256" => ApplyOaepSha256Padding(bytes: bytes, keySize: keySize),
            _ => throw new ArgumentException("Unsupported padding type")
        };
    }

    private byte[] ApplyPkcs1Padding(byte[] bytes, int keySize)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        int paddingOverhead = 11;    // Pkcs1 padding is at least 11 bytes long
        int maxDataLength = chunkSize - paddingOverhead;

        int totalChunks = (int)Math.Ceiling((double)bytes.Length / maxDataLength);
        byte[] paddedBytes = new byte[totalChunks * chunkSize];
        
        // Iterate through the data in chunks
        for (int processedChunks = 0; processedChunks < totalChunks; processedChunks++)
        {
            int destinationBytesIndex = processedChunks * chunkSize;
            int sourceBytesOffset = processedChunks * maxDataLength;
            
            int actualDataLength = Math.Min(maxDataLength, bytes.Length - sourceBytesOffset); // If we're at the end of the data, the padding might be longer as we have less actual data to fill the chunk
            
            // Add Pkcs1 padding (0x00, 0x02 , at least 8 random bytes, 0x00)
            paddedBytes[destinationBytesIndex] = 0x00;
            paddedBytes[destinationBytesIndex + 1] = 0x02;
            
            int paddingLength = chunkSize - actualDataLength - 3;
            for (int j = 0; j < paddingLength; j++)
            {
                paddedBytes[destinationBytesIndex + 2 + j] = (byte)_random.Next(1, 256); // Random padding bytes
            }
            
            paddedBytes[destinationBytesIndex + 2 + paddingLength] = 0x00;
            
            // Insert the actual data to the rest of the chunk
            Array.Copy(sourceArray: bytes, sourceIndex: sourceBytesOffset, destinationArray: paddedBytes, destinationIndex: (destinationBytesIndex + 3 + paddingLength), length: actualDataLength);
        }
        
        return paddedBytes;
    }

    private static byte[] ApplyOaepSha1Padding(byte[] bytes, int keySize)
    {
        // Implement OAEP SHA-1 padding logic here
        throw new NotImplementedException();
    }

    private static byte[] ApplyOaepSha256Padding(byte[] bytes, int keySize)
    {
        // Implement OAEP SHA-256 padding logic here
        throw new NotImplementedException();
    }
    
    private static byte[] RemovePadding(byte[] bytes, int keySize, string padding)
    {
        return padding.ToLower() switch
        {
            "pkcs1" => RemovePkcs1Padding(bytes, keySize),
            "oaepsha1" => RemoveOaepSha1Padding(bytes, keySize),
            "oaepsha256" => RemoveOaepSha256Padding(bytes, keySize),
            _ => throw new ArgumentException("Unsupported padding type")
        };
    }

    private static byte[] RemovePkcs1Padding(byte[] bytes, int keySize)
    {
        int chunkSize = keySize / 8;    // Chunk size is the key's size in bytes
        int totalChunks = bytes.Length / chunkSize;
        
        List<byte[]> unpaddedBytes = new List<byte[]>();
        
        // Iterate through the data in chunks
        for (int i = 0; i < totalChunks; i++)
        {
            int chunkStartIndex = i * chunkSize;
            int chunkPaddingStartIndex = chunkStartIndex + 2; // The padding starts at the third byte (0x00, 0x02, ...)
            
            // Find the 0x00 delimiter between padding and data
            int delimiterIndex = Array.IndexOf(array: bytes, value: (byte)0x00, startIndex: chunkPaddingStartIndex, count: ((chunkStartIndex + chunkSize) - chunkPaddingStartIndex));

            int dataStartIndex = delimiterIndex + 1; // (0x00, 0x02, ..., 0x00, {data})

            int numDataBytes = (chunkStartIndex + chunkSize) - dataStartIndex;

            byte[] unpaddedChunk = new byte[numDataBytes];
            Array.Copy(sourceArray: bytes, sourceIndex: dataStartIndex, destinationArray: unpaddedChunk, destinationIndex: 0, length: numDataBytes);
            
            unpaddedBytes.Add(unpaddedChunk);
        }
        
        return unpaddedBytes.SelectMany(x => x).ToArray();
    }

    private static byte[] RemoveOaepSha1Padding(byte[] data, int keySize)
    {
        throw new NotImplementedException();
    }

    private static byte[] RemoveOaepSha256Padding(byte[] data, int keySize)
    {
        throw new NotImplementedException();
    }
    
    private static (BigInteger modulus, BigInteger publicExponent, int keySize) ParsePublicKey(string publicKey)
    {
        // Clean the public key and remove the PEM header and footer
        string pem = publicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "").Replace(" ", "");

        byte[] asn1EncodedData = Convert.FromBase64String(pem);

        // Parse the ASN.1 DER-encoded public key structure
        AsnReader reader = new AsnReader(asn1EncodedData, AsnEncodingRules.DER);
        // PKCS#8 format: 
        // PublicKeyInfo ::= SEQUENCE {
        //     algorithm       AlgorithmIdentifier,
        //     publicKey       BIT STRING
        // }
        
        AsnReader pkiSequence = reader.ReadSequence();              // Read the PKI sequence
        pkiSequence.ReadSequence();                                 // Skip AlgorithmIdentifier in the PKI sequence
        byte[] keyData = pkiSequence.ReadBitString(out int unused); // Extract the key bits from the publicKey BIT STRING
        
        // Parse the RSA public key structure
        AsnReader keyReader = new AsnReader(keyData, AsnEncodingRules.DER);
        // RSA Public Key structure:
        // RSAPublicKey ::= SEQUENCE {
        //     modulus         INTEGER,
        //     publicExponent  INTEGER
        // }
        AsnReader rsaKeySequence = keyReader.ReadSequence();        // Read the actual RSA key sequence
        
        // Get the modulus as byte array without leading zero and then convert it to a BigInteger
        byte[] modulusBytes = rsaKeySequence.ReadIntegerBytes().ToArray();
        if (modulusBytes[0] == 0) modulusBytes = modulusBytes[1..];
        BigInteger modulus = new BigInteger(modulusBytes, isUnsigned: true, isBigEndian: true); // Big Endian is the default for RSA
        
        // Get the public exponent as byte array and then convert it to a BigInteger
        byte[] exponentBytes = rsaKeySequence.ReadIntegerBytes().ToArray();
        BigInteger publicExponent = new BigInteger(exponentBytes, isUnsigned: true, isBigEndian: true);
        
        int keySize = modulusBytes.Length * 8;
        
        return (modulus, publicExponent, keySize);
    }
    
    private static (BigInteger modulus, BigInteger privateExponent, int keySize) ParsePrivateKey(string privateKey)
    {
        // Clean the private key and remove the PEM header, footer and whitespace
        string pem = privateKey.Replace("-----BEGIN PRIVATE KEY-----", "")
                               .Replace("-----END PRIVATE KEY-----", "")
                               .Replace("\n", "")
                               .Replace("\r", "")
                               .Replace(" ", "");

        byte[] asn1EncodedData = Convert.FromBase64String(pem);

        // Parse the ASN.1 DER-encoded private key structure
        AsnReader reader = new AsnReader(asn1EncodedData, AsnEncodingRules.DER);
        // PKCS#8 format:
        // PrivateKeyInfo ::= SEQUENCE {
        //     version             INTEGER,
        //     algorithm           AlgorithmIdentifier,
        //     privateKey          OCTET STRING
        // }
        AsnReader pkiSequence = reader.ReadSequence();            // Read the PKI sequence
        pkiSequence.ReadInteger();                                // Skip version
        pkiSequence.ReadSequence();                               // Skip AlgorithmIdentifier
        byte[] keyData = pkiSequence.ReadOctetString();           // Extract the private key data

        // Parse the RSA private key structure
        AsnReader keyReader = new AsnReader(keyData, AsnEncodingRules.DER);
        // RSA Private Key structure:
        // RSAPrivateKey ::= SEQUENCE {
        //     version           INTEGER,
        //     modulus           INTEGER,
        //     publicExponent    INTEGER,
        //     privateExponent   INTEGER,
        //     ...other parameters...
        // }
        AsnReader rsaKeySequence = keyReader.ReadSequence();      // Read the RSA key sequence
        rsaKeySequence.ReadInteger();                             // Skip the version

        // Read and convert the modulus
        byte[] modulusBytes = rsaKeySequence.ReadIntegerBytes().ToArray();
        if (modulusBytes[0] == 0)
            modulusBytes = modulusBytes[1..];
        BigInteger modulus = new BigInteger(modulusBytes, isUnsigned: true, isBigEndian: true); // Big Endian is the default for RSA

        // Skip the public exponent
        rsaKeySequence.ReadInteger();

        // Read and convert the private exponent
        byte[] privateExponentBytes = rsaKeySequence.ReadIntegerBytes().ToArray();
        if (privateExponentBytes[0] == 0)
            privateExponentBytes = privateExponentBytes[1..];
        BigInteger privateExponent = new BigInteger(privateExponentBytes, isUnsigned: true, isBigEndian: true);

        int keySize = modulusBytes.Length * 8;

        return (modulus, privateExponent, keySize);
    }
}