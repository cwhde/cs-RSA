using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Security;
using RSA.commons; // Own common RSA resources, Interface and Utils

namespace RSA;

public class RSA : ICommonRSA
{
    private static readonly RandomNumberGenerator _random = RandomNumberGenerator.Create();
    
    // Method that takes a public key (filepath, PEM or shortened PEM) and a plaintext string and returns the encrypted string
    public string EncryptString(string publicKey, string paddingMode, string plainText)
    {
        // Check if padding is valid
        string[] validPaddings = RSAUtils.GetValidPaddings();
        if (!validPaddings.Contains(paddingMode.ToLower()))
        {
            throw new ArgumentException("Padding mode not allowed", nameof(paddingMode));
        }
        
        // Clean and parse the public key
        publicKey = RSAUtils.SanitizeKeyInput(inputKey: publicKey, isPublic: true);
        (BigInteger modulus, BigInteger publicExponent, int keySize) = ParsePublicKey(publicKey: publicKey);

        byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
        byte [] paddedTextBytes = ApplyPadding(dataBytes: plainTextBytes, keySize: keySize, padding: paddingMode.ToLower());
        
        byte[] cypherTextBytes = EncryptBytes(dataBytes: paddedTextBytes, modulus: modulus, publicExponent: publicExponent, keySize: keySize);

        return Convert.ToBase64String(cypherTextBytes);
    }
    
    // Method that takes a private key (filepath, PEM or shortened PEM) and a ciphertext string and returns the decrypted string
    public string DecryptString(string privateKey, string paddingMode, string cipherText)
    {
        // Check if padding is valid
        string[] validPaddings = RSAUtils.GetValidPaddings();
        if (!validPaddings.Contains(paddingMode.ToLower()))
        {
            throw new ArgumentException("Padding mode not allowed", nameof(paddingMode)); // Throw an exception if the padding is not allowed
        }
        
        privateKey = RSAUtils.SanitizeKeyInput(inputKey: privateKey, isPublic: false);
        (BigInteger modulus, BigInteger privateExponent, int keySize) = ParsePrivateKey(privateKey: privateKey);
        
        byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
        byte[] paddedTextBytes = DecryptBytes(dataBytes: cipherTextBytes, modulus: modulus, privateExponent: privateExponent, keySize: keySize);

        byte[] plainTextBytes = RemovePadding(dataBytes: paddedTextBytes, keySize: keySize, padding: paddingMode.ToLower());
        
        return Encoding.UTF8.GetString(plainTextBytes);
    }
    
    // Method that generates a pem key pair and returns the public (X.509) and private (PKCS8) key as strings
    public (string publicKey, string privateKey) GenerateKeys(int keySize)
    {
        // Get two random distinct prime numbers
        BigInteger randomPrime1 = GetRandomPrime(bitLength: keySize / 2);
        BigInteger randomPrime2 = GetRandomPrime(bitLength: keySize / 2);
        while (true)
        {
            if (randomPrime1 == randomPrime2) randomPrime1 = GetRandomPrime(bitLength: keySize / 2);
            else break;
        }
        
        BigInteger smallTotient = CarmichaelTotient(p: randomPrime1, q: randomPrime2);
        BigInteger modulus = BigInteger.Multiply(randomPrime1, randomPrime2);
        
        BigInteger publicExponent = new BigInteger(65537); // Is an efficient prime, so gcd(e, totient of modulus) is always 1
        BigInteger privateExponent = EuclideanInverseModulo(a: publicExponent, b: smallTotient);
        
        // Create the public key (ASN.1 DER-encoded to Base64 to PEM)
        
        // Write the public key octets
        AsnWriter publicKeyWriter = new AsnWriter(AsnEncodingRules.DER);
        // RSAPublicKey ::= SEQUENCE {
        //     modulus         INTEGER,
        //     publicExponent  INTEGER
        // }
        publicKeyWriter.PushSequence();
        publicKeyWriter.WriteInteger(modulus);
        publicKeyWriter.WriteInteger(publicExponent);
        publicKeyWriter.PopSequence();
        byte[] publicKeyBytes = publicKeyWriter.Encode();
        
        // Now wrap it in a PublicKeyInfo structure
        AsnWriter publicKeyInfoWriter = new AsnWriter(AsnEncodingRules.DER);
        // PublicKeyInfo ::= SEQUENCE {
        //     algorithm       AlgorithmIdentifier,
        //     publicKey       BIT STRING
        // }
        publicKeyInfoWriter.PushSequence();
        publicKeyInfoWriter.PushSequence();
        publicKeyInfoWriter.WriteObjectIdentifier("1.2.840.113549.1.1.1"); // Algorithm identifier for RSA Encryption is 1.2.840.113549.1.1.1
        publicKeyInfoWriter.WriteNull();
        publicKeyInfoWriter.PopSequence();
        publicKeyInfoWriter.WriteBitString(publicKeyBytes); // Public key as BIT STRING
        publicKeyInfoWriter.PopSequence();
        byte[] publicKeyInfoBytes = publicKeyInfoWriter.Encode();
        
        string publicKeyString = Convert.ToBase64String(publicKeyInfoBytes);
        string publicKey = $"-----BEGIN PUBLIC KEY-----\n{publicKeyString}\n-----END PUBLIC KEY-----";
        
        // Create the private key (ASN.1 DER-encoded to Base64 to PEM)
        BigInteger exponent1 = privateExponent % (randomPrime1 - 1);
        BigInteger exponent2 = privateExponent % (randomPrime2 - 1);
        BigInteger coefficient = EuclideanInverseModulo(a: randomPrime2, b: randomPrime1);
        
        // Write the private key octets
        AsnWriter privateKeyWriter = new AsnWriter(AsnEncodingRules.DER);
        // RSAPrivateKey ::= SEQUENCE {
        //     version           INTEGER,
        //     modulus           INTEGER,
        //     publicExponent    INTEGER,
        //     privateExponent   INTEGER,
        //     prime1            INTEGER,
        //     prime2            INTEGER,
        //     exponent1         INTEGER,
        //     exponent2         INTEGER,
        //     coefficient       INTEGER
        // }
        privateKeyWriter.PushSequence();
        privateKeyWriter.WriteInteger(0);
        privateKeyWriter.WriteInteger(modulus);
        privateKeyWriter.WriteInteger(publicExponent);
        privateKeyWriter.WriteInteger(privateExponent);
        privateKeyWriter.WriteInteger(randomPrime1);
        privateKeyWriter.WriteInteger(randomPrime2);
        privateKeyWriter.WriteInteger(exponent1);
        privateKeyWriter.WriteInteger(exponent2);
        privateKeyWriter.WriteInteger(coefficient);
        privateKeyWriter.PopSequence();
        byte[] privateKeyBytes = privateKeyWriter.Encode();
        
        // Now wrap it in a PrivateKeyInfo structure
        AsnWriter privateKeyInfoWriter = new AsnWriter(AsnEncodingRules.DER);
        // PrivateKeyInfo ::= SEQUENCE {
        //     version             INTEGER,
        //     algorithm           AlgorithmIdentifier,
        //     privateKey          OCTET STRING
        // }
        privateKeyInfoWriter.PushSequence();
        privateKeyInfoWriter.WriteInteger(0);                   
        privateKeyInfoWriter.PushSequence();
        privateKeyInfoWriter.WriteObjectIdentifier("1.2.840.113549.1.1.1"); // Algorithm identifier for RSA Encryption is 1.2.840.113549.1.1.1
        privateKeyInfoWriter.WriteNull();
        privateKeyInfoWriter.PopSequence();
        privateKeyInfoWriter.WriteOctetString(privateKeyBytes); // RSA private key as OCTET STRING
        privateKeyInfoWriter.PopSequence();
        byte[] privateKeyInfoBytes = privateKeyInfoWriter.Encode();
        
        string privateKeyString = Convert.ToBase64String(privateKeyInfoBytes);
        string privateKey = $"-----BEGIN PRIVATE KEY-----\n{privateKeyString}\n-----END PRIVATE KEY-----";
        
        return (publicKey, privateKey);
    }
    
    // Method that takes a byte array (padding has to be applied already), a factor n and a factor e and returns the encrypted byte array
    private static byte[] EncryptBytes(byte[] dataBytes, BigInteger modulus, BigInteger publicExponent, int keySize)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        List<byte[]> encryptedChunks = new List<byte[]>();
        
        // Iterate through the data in chunks of blockSize
        for (int bytesProcessed = 0; bytesProcessed < dataBytes.Length; bytesProcessed += chunkSize)
        {
            byte[] currentChunk = dataBytes.Skip(bytesProcessed).Take(chunkSize).ToArray();

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
            
            encryptedChunks.Add(encryptedBytes);
        }
        
        return encryptedChunks.SelectMany(x => x).ToArray();
    }
    
    // Method that takes a byte array, a factor n and a factor d and returns the decrypted byte array (padding has to be handled afterward)
    private static byte[] DecryptBytes(byte[] dataBytes, BigInteger modulus, BigInteger privateExponent, int keySize)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        List<byte[]> decryptedChunks = new List<byte[]>();
        
        // Iterate through the data in chunks
        for (int bytesProcessed = 0; bytesProcessed < dataBytes.Length; bytesProcessed += chunkSize)
        {
            byte[] currentChunk = dataBytes.Skip(bytesProcessed).Take(chunkSize).ToArray();

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
    
    private static byte[] ApplyPadding(byte[] dataBytes, int keySize, string padding)
    {
        return padding.ToLower() switch
        {
            "pkcs1" => ApplyPkcs1Padding(dataBytes: dataBytes, keySize: keySize),
            "oaepsha1" => ApplyOaepPadding(dataBytes: dataBytes, keySize: keySize, useSHA256: false),
            "oaepsha256" => ApplyOaepPadding(dataBytes: dataBytes, keySize: keySize, useSHA256: true),
            _ => throw new ArgumentException("Unsupported padding type")
        };
    }

    private static byte[] ApplyPkcs1Padding(byte[] dataBytes, int keySize)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        int paddingOverhead = 11;    // Pkcs1 padding is at least 11 bytes long
        int maxDataLength = chunkSize - paddingOverhead;

        int totalChunks = (int)Math.Ceiling((double)dataBytes.Length / maxDataLength);
        byte[] paddedBytes = new byte[totalChunks * chunkSize];
        
        // Iterate through the data in chunks
        for (int processedChunks = 0; processedChunks < totalChunks; processedChunks++)
        {
            int destinationBytesOffset = processedChunks * chunkSize;
            int sourceBytesOffset = processedChunks * maxDataLength;
            
            int actualDataLength = Math.Min(maxDataLength, dataBytes.Length - sourceBytesOffset); // If we're at the end of the data, the padding might be longer as we have less actual data to fill the chunk
            
            // Add Pkcs1 padding (0x00, 0x02 , at least 8 random bytes, 0x00)
            paddedBytes[destinationBytesOffset] = 0x00;
            paddedBytes[destinationBytesOffset + 1] = 0x02;
            
            int paddingLength = chunkSize - actualDataLength - 3;
            byte[] randomBytes = new byte[paddingLength];
            _random.GetNonZeroBytes(randomBytes);
            for (int j = 0; j < paddingLength; j++)
            {
                paddedBytes[destinationBytesOffset + 2 + j] = randomBytes[j]; // Random padding bytes
            }
            
            paddedBytes[destinationBytesOffset + 2 + paddingLength] = 0x00;
            
            // Insert the actual data to the rest of the chunk
            Array.Copy(sourceArray: dataBytes, sourceIndex: sourceBytesOffset, destinationArray: paddedBytes, destinationIndex: (destinationBytesOffset + 3 + paddingLength), length: actualDataLength);
        }
        
        return paddedBytes;
    }

    private static byte[] ApplyOaepPadding(byte[] dataBytes, int keySize, bool useSHA256)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        int hashLength = useSHA256 ? 32 : 20;
        int dbLength = chunkSize - hashLength - 1;
        int paddingOverhead = 2 * hashLength + 2;
        int maxDataLength = chunkSize - paddingOverhead;

        int totalChunks = (int)Math.Ceiling((double)dataBytes.Length / maxDataLength);
        byte[] paddedBytes = new byte[totalChunks * chunkSize];
        
        // Iterate through the data in chunks
        for (int processedChunks = 0; processedChunks < totalChunks; processedChunks++)
        {
            int destinationBytesOffset = processedChunks * chunkSize;
            int sourceBytesOffset = processedChunks * maxDataLength;
            
            int actualDataLength = Math.Min(maxDataLength, dataBytes.Length - sourceBytesOffset); // If we're at the end of the data, the padding might be longer as we have less actual data to fill the chunk
            int zeroPaddingLength = maxDataLength - actualDataLength; // If the data is shorter than the max length, we need to add zero padding

            // Create the data block (DB) as: Hash(label = 0) || Padding || 0x00 || Data
            byte[] DBBytes = new byte[dbLength];
            
            byte[] labelBytes = useSHA256 ?
                System.Security.Cryptography.SHA256.HashData(Array.Empty<byte>()) :
                System.Security.Cryptography.SHA1.HashData(Array.Empty<byte>());
            Array.Copy(sourceArray: labelBytes, sourceIndex: 0, destinationArray: DBBytes, destinationIndex: 0, length: labelBytes.Length);            
            
            byte[] zeroPaddingBytes = new byte[zeroPaddingLength];
            Array.Fill(zeroPaddingBytes, (byte)0);
            Array.Copy(sourceArray: zeroPaddingBytes, sourceIndex: 0, destinationArray: DBBytes, destinationIndex: labelBytes.Length, length: zeroPaddingBytes.Length);
            
            DBBytes[labelBytes.Length + zeroPaddingLength] = 0x01;

            Array.Copy(sourceArray: dataBytes, sourceIndex: sourceBytesOffset, destinationArray: DBBytes, destinationIndex: labelBytes.Length + zeroPaddingLength + 1, length: actualDataLength);
            
            // Get a seed and create a mask for the DB by applying MGF1 to the seed
            byte[] randomSeedBytes = new byte[hashLength];
            _random.GetBytes(randomSeedBytes);
            byte[] dbMaskBytes = ApplyMGF1(seed: randomSeedBytes, maskLength: dbLength, useSHA256: useSHA256);
            
            // Mask the DB by XORing it with the mask
            byte[] maskedDB = XORBytes(DBBytes, dbMaskBytes);
            
            // Create a mask for the seed by applying MGF1 to the masked DB and XORing it with the seed
            byte[] seedMask = ApplyMGF1(seed: maskedDB, maskLength: hashLength, useSHA256: useSHA256);
            byte[] maskedSeed = XORBytes(randomSeedBytes, seedMask);
            
            // Concatenate the masked seed and masked DB to get the final padded data (0x01, maskedSeed, maskedDB)
            byte[] paddedChunkBytes = new byte[chunkSize];
            paddedChunkBytes[0] = 0x00;
            Array.Copy(sourceArray: maskedSeed, sourceIndex: 0, destinationArray: paddedChunkBytes, destinationIndex: 1, length: hashLength);
            Array.Copy(sourceArray: maskedDB, sourceIndex: 0, destinationArray: paddedChunkBytes, destinationIndex: hashLength + 1, length: dbLength);
            
            // Add to the other chunks
            Array.Copy(sourceArray: paddedChunkBytes, sourceIndex: 0, destinationArray: paddedBytes, destinationIndex: destinationBytesOffset, length: chunkSize);
        }

        return paddedBytes;
    }
    
    private static byte[] RemovePadding(byte[] dataBytes, int keySize, string padding)
    {
        return padding.ToLower() switch
        {
            "pkcs1" => RemovePkcs1Padding(dataBytes: dataBytes, keySize: keySize),
            "oaepsha1" => RemoveOaepPadding(dataBytes: dataBytes, keySize: keySize, useSHA256: false),
            "oaepsha256" => RemoveOaepPadding(dataBytes: dataBytes, keySize: keySize, useSHA256: true),
            _ => throw new ArgumentException("Unsupported padding type")
        };
    }

    private static byte[] RemovePkcs1Padding(byte[] dataBytes, int keySize)
    {
        int chunkSize = keySize / 8;    // Chunk size is the key's size in bytes
        int totalChunks = dataBytes.Length / chunkSize;
        
        List<byte[]> unpaddedBytes = new List<byte[]>();
        
        // Iterate through the data in chunks
        for (int i = 0; i < totalChunks; i++)
        {
            int chunkStartIndex = i * chunkSize;
            int chunkPaddingStartIndex = chunkStartIndex + 2; // The padding starts at the third byte (0x00, 0x02, ...)
            
            // Find the 0x00 delimiter between padding and data
            int delimiterIndex = Array.IndexOf(array: dataBytes, value: (byte)0x00, startIndex: chunkPaddingStartIndex, count: ((chunkStartIndex + chunkSize) - chunkPaddingStartIndex));

            int dataStartIndex = delimiterIndex + 1; // (0x00, 0x02, ..., 0x00, {data})

            int numDataBytes = (chunkStartIndex + chunkSize) - dataStartIndex;

            byte[] unpaddedChunk = new byte[numDataBytes];
            Array.Copy(sourceArray: dataBytes, sourceIndex: dataStartIndex, destinationArray: unpaddedChunk, destinationIndex: 0, length: numDataBytes);
            
            unpaddedBytes.Add(unpaddedChunk);
        }
        
        return unpaddedBytes.SelectMany(x => x).ToArray();
    }

    private static byte[] RemoveOaepPadding(byte[] dataBytes, int keySize, bool useSHA256)
    {
        int chunkSize = keySize / 8; // Chunk size is the key's size in bytes
        int hashLength = useSHA256 ? 32 : 20;
        int dbLength = chunkSize - hashLength - 1;
        int totalChunks = dataBytes.Length / chunkSize;
        
        List<byte[]> unpaddedBytes = new List<byte[]>();
        
        // Iterate through the data in chunks
        for (int i = 0; i < totalChunks; i++)
        {
            int chunkStartIndex = i * chunkSize;
            
            // This is a necessary check part of OAEP specification
            if (dataBytes[chunkStartIndex] != 0x00)
            {
                throw new ArgumentException("Invalid OAEP padding");
            }
            
            // Read the chunks contents (maskedSeed, maskedDB)
            byte[] maskedSeed = dataBytes.Skip(chunkStartIndex + 1).Take(hashLength).ToArray();
            byte[] maskedDB = dataBytes.Skip(chunkStartIndex + 1 + hashLength).Take(dbLength).ToArray();
            
            // Extract the seed by applying MGF1 to the masked DB and XORing it with the masked seed
            byte[] seedMask = ApplyMGF1(seed: maskedDB, maskLength: hashLength, useSHA256: useSHA256);
            byte[] randomSeedBytes = XORBytes(maskedSeed, seedMask);
            
            // Extract the DB by applying MGF1 to the seed and XORing it with the masked DB
            byte[] dbMaskBytes = ApplyMGF1(seed: randomSeedBytes, maskLength: dbLength, useSHA256: useSHA256);
            byte[] DBBytes = XORBytes(maskedDB, dbMaskBytes);
            
            // Check if the label is correct
            byte[] expectedLabel = useSHA256 ?
                System.Security.Cryptography.SHA256.HashData(Array.Empty<byte>()) :
                System.Security.Cryptography.SHA1.HashData(Array.Empty<byte>());
            byte[] actualLabel = DBBytes.Take(hashLength).ToArray();
            
            bool hashesMatch = true;
            for (int j = 0; j < hashLength; j++)
            {
                if (expectedLabel[j] != actualLabel[j])
                {
                    hashesMatch = false;
                    break;
                }
            }
            
            if (!hashesMatch)
            {
                throw new CryptographicException("OAEP padding error: Label mismatch");
            }
            
            // Extract the actual data from DB
            int delimiterIndex = Array.IndexOf(array: DBBytes, value: (byte)0x01, startIndex: hashLength);
            byte[] unpaddedChunk = DBBytes.Skip(delimiterIndex + 1).ToArray();
            
            // Add to the other chunks
            unpaddedBytes.Add(unpaddedChunk);
        }
        
        return unpaddedBytes.SelectMany(x => x).ToArray();
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

    // Get a random prime number of the specified bit length using BouncyCastle as an own efficient implementation is not feasible
    private static BigInteger GetRandomPrime(int bitLength)
    {
        SecureRandom secureRandom = new SecureRandom();
        Org.BouncyCastle.Math.BigInteger bouncyPrime = Org.BouncyCastle.Math.BigInteger.ProbablePrime(bitLength, secureRandom);
        return new BigInteger(bouncyPrime.ToByteArrayUnsigned(), isUnsigned: true, isBigEndian: true);
    }

    // Calculate the Euler Totient function for two prime numbers
    private static BigInteger CarmichaelTotient(BigInteger p, BigInteger q)
    {
        p--;
        q--;
        return BigInteger.Multiply(p, q)/BigInteger.GreatestCommonDivisor(p, q);
    }
    
    // Calculate the multiplicative inverse using the Extended Euclidean Algorithm, a will usually be the public exponent (e) and b the Totient (phi(n))
    private static BigInteger EuclideanInverseModulo(BigInteger a, BigInteger b)
    {
        BigInteger oldR = a;
        BigInteger r = b;
        BigInteger oldS = 1;
        BigInteger s = 0;
        BigInteger oldT = 0;
        BigInteger t = 1;
        
        // Actual algorithm
        while (r > 0)
        {
            BigInteger quotient = oldR / r;
            
            (oldR, r) = (r, (oldR - quotient * r));
            (oldS, s) = (s, oldS - quotient * s);
            (oldT, t) = (t, oldT - quotient * t);
        }
        
        // OldS can be negative, in which case we add b (phi(n)) to it to get the positive multiplicative inverse
        while (oldS < 0)
        {
            oldS += b;
        }
        
        return oldS;
    }

    // Apply MGF1 on a byte array with either SHA1 or SHA256, used for OAEP
    private static byte[] ApplyMGF1(byte[] seed, int maskLength, bool useSHA256)
    {
        List<byte> maskBytes = new List<byte>(maskLength);
        int counter = 0;

        while (maskBytes.Count < maskLength)
        {
            // Ensure big endian byte array representation of the counter
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }
            
            // Concatenate the seed with the count (As 4 Byte representation) and hash it with either SHA1 or SHA256
            maskBytes.AddRange(useSHA256
                ? System.Security.Cryptography.SHA256.HashData(seed.Concat(counterBytes).ToArray())
                : System.Security.Cryptography.SHA1.HashData(seed.Concat(counterBytes).ToArray()));
            
            counter++;
        }
        
        // Return only asked for length
        return maskBytes.Take(maskLength).ToArray();
    }

    // XOR two byte arrays, used for OAEP
    private static byte[] XORBytes(byte[] array1, byte[] array2)
    {
        byte[] resultArray = new byte[array1.Length];

        for (int i = 0; i < array1.Length; i++)
        {
            resultArray[i] = (byte)(array1[i] ^ array2[i]);
        }

        return resultArray;
    }
}