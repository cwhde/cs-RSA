using System;
using System.IO;
using JetBrains.Annotations;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace csRSA.Tests;

[TestClass]
[TestSubject(typeof(ReferenceRSA.ReferenceRSA))]
public class ReferenceRSATest
{
    private readonly ReferenceRSA.ReferenceRSA _referenceRSA = new ReferenceRSA.ReferenceRSA();

    [TestMethod]
    // Pass if generating keys and then using them doesn't throw an error and the decrypted text is the same as the original text
    public void GenerateKeys_ShouldNotErrorAndReturnWorkingKeys()
    {
        int[] keySizes = [512, 1024, 2048, 4096];
        string text = "Less than 256 bits";
        
        foreach (int keySize in keySizes)
        {
            (string publicKey, string privateKey) = _referenceRSA.GenerateKeys(keySize);
            
            string encryptedText = _referenceRSA.EncryptString(publicKey, "pkcs1", text);
            string decryptedText = _referenceRSA.DecryptString(privateKey, "pkcs1", encryptedText);
            Assert.AreEqual(text, decryptedText);
        }
    }
    
    [TestMethod]
    // Pass if the EncryptString method runs without error and the output is the same length as the key size when given multiple formats of key input, with the key being known valid
    public void EncryptString_ShouldRunWithProvenKeysOfMultipleFormats()
    {
        string knownPublicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu5leeQUKqwYw3Ogit8gmmRFzPIPhdioK8838/bOqXYDGTMxk825GNUQ+pnd4BdPZ97PKDpfbgvEBCoNX7MtNdQu2zBE6Q6MalfpPrUdWQfgsUaHMP45B6pcFu88/fD9CK3DfXXAh1Pa09glV7nBlvoZNzkE2/ipPWSkMxqmJT53+eRtsBPyhvl6mMnxby9gHqAU74tDXotzUYBdwd0KFttzqncH6pJxw4aCO++6O/R0wyp7huL8eKRv5gMxiZl53sFlMBpFKF+Sidh85I1MsRTA5wso1GqaY3LMzYpOWj7XYm4vcD3KZ36KxK4/SptZahk3iigyBYW8LKYWKm/uxrwIDAQAB\n-----END PUBLIC KEY-----";
        string strippedPublicKey = knownPublicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "");
        string tempFilePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.pem");
        File.WriteAllText(tempFilePath, knownPublicKey);
                
        string plainText = "About 256 bytes or 2048 bits of text length should matter no problem, maybe leaving at least 11 bytes for pkcs1 padding leaving 245 bytes for the text. This text doesn't reach that, but surpasses 1024 bits.";
        
        foreach (string publicKey in new[] {knownPublicKey, strippedPublicKey, tempFilePath})        
        {
            string cipherText = _referenceRSA.EncryptString(publicKey, "pkcs1", plainText);
            byte[] encryptedBytes = Convert.FromBase64String(cipherText);
            Assert.AreEqual(256, encryptedBytes.Length);
        }
    }

    [TestMethod]
    // Pass if the DecryptString method runs without error and the output is the same as the known plaintext when given multiple formats of key input, with the key being known valid
    public void DecryptString_ShouldOutputCorrectTextWithProvenKeysOfMultipleFormats()
    {
        string knownPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFS7bmAaK2zcX4PRWt6R/XDXLTUPlRiSRahlkdNPtZoR5ALUYvyRXrjvaTSgU60B/6XYFTnmRlEE00CcCHuhAdXmerWALT2nIf7NBLZmuruhIO/w+1AkPuWKTF2bnlat0zaZF14EA/lBio6bTMst+f3GaMivbgMPVDEwMsVrzj8a0yCufg25Qf3lJ073jWRakNeoL0BohS3SPcOyKoocRC+J2SUUAYY2VKwhTZmXEx6weTcSOOlCuUaO0fDIbSs3Fx3XfS8P5kV0qKg789guxDOYb1hbN2COalEn83iIn8f0Z9mzQ5/CghiVU+JoT+pStSBIFDNmJkOXyreV29bmYxAgMBAAECggEAKnnWCyfP/bZIiFyyVapKihSho4Ab5SN2+axR9DlLYe0Po7Z7lV8gAoJZcLVvcc2MDO1jofqIV7/ON0VgN3hl7sS74gZFOZIenuPvpkQLK0IYkDT2jzxJHr/j3Zq17H/41pBEWlHo0ydRtc/29lkOTw723wwuAW9Y5lNqC/oymYo2M3AyqdK4vlJz1Z6E2jLDFJRsRKIFG21oDyxXyzQk1BX0NZg/mSSSYwV91c6ky/SxC65mG9IwjHn0hOHKOL3W7IIyCLw3EBbe4ZH9aLhQglj8wzYR3fwoU6L3ADRlRhrHVzHwkEnleb987DjtEq2dlrYUZR2SkN3bDEDmMyqehwKBgQDn+m6yt+Hsu1xetL4C8pCa2oUHvF7lKbX54qec6Ge8LdxzuAzv9JpU7YdUiAby3inKqF+PxTcjzjPcz2OdXuAY4L5yqMMEViuR1zt9LuXrYXaqc2JlToxuZSXMQ3CpPH3NP2OE7Qr/6XmqrOgj9Z42OF0o4uWdYw3WkOOTbh6x7wKBgQDZueAeOdU4TBwXCgXjgFczmvou7kasKTmuEcXV+Q3gx2B4NKtLNOan6uz9UAxtUMeK+/h6qZjl8S5Jfov/ddai1QymF61ufNlk/rVZGI1SssvG7DWqV4fSdJKYK4+OCp8GvOtwl2eol8U6bP6+TTVKtwMIcwEUI872eEfaupAJ3wKBgEnUgIrMz1DCyMEzkQ3rGW7PgWtW3nTc85fWNTZRGULg7bq+pw9vr/a7qkiTCnMdlftz3wYo5EW3CPaL4s5hNb11OefQIlEtA6zk7YAH/xEM8fGJy5UmjLdN5du+0wppwDgkpo3Vy5xrOFfDtBZNw87J3Yx3ulB/CBZ0ApoXgBltAoGAK0qZNIldSwdfInmcuCKhtCIhkslQBhVgYaspAiW2S7Z5CQ237YlEP6knnCqZffbs5ka5nnIwc7Aj+vsNjSr6FYB1NmVI18o9U6aNmnyWRRZGDHSVKxyiZgdFyroGnkCgZC+WRNnmA5DB558ae+5QJV4EXV64nS+NjFZYOzaTQ1MCgYEAjxLje+JwxdTW624fRMTJZ7cnVzKlDyy9BdclbmM/cZ38rgH2eg4zhYR6WNEtDglfsjTduznB9xTFMTNWxKKhN9yh4F/InXtRjt7xkeD/5TOaj5gR4rua0qR2JHhedhfqbSh+7J4aJ6CW2f1xDmZOwTIOiXy1PUo7Hs0QkBk8EJQ=\n-----END RSA PRIVATE KEY-----";
        string strippedPrivateKey = knownPrivateKey.Replace("-----BEGIN RSA PRIVATE KEY-----", "").Replace("-----END RSA PRIVATE KEY-----", "");
        string tempFilePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.pem");
        File.WriteAllText(tempFilePath, knownPrivateKey);
        
        string cipherText = "iMQvznNVwqiFnubGY3pDUgpw7GWZWkcCdEodcdITM/THgXeX5+bInEVoB1Zc8EJ8flnfCUvUih2bQ4IrJf/31ipfqBV+8wkegIQ9YPuVtWBJZoyeomZXjx79m55UiXFeVjd1g/sARz4Aggv0kwQLjty5Cy7yJTHoUicIR4NU1i/TEB5/E5/49j6mCTtX80y0JzSgT02M3pl2sMryJ/enWMWlAQYVpI1+XKYoj8/SZ0fnyD+rVzL4wVyh/lL7ymwsIi9JiR0UvL/sB/7zg0Kz0B9hCKNTTl0ZB3Cgr4/xIcQNs4eQXn5s3xvMgObSGE8ZWvk5gLUeOG+kE6uc1X7/Jg==";
        string expectedPlainText = "About 256 bytes or 2048 bits of text length should matter no problem, maybe leaving at least 11 bytes for pkcs1 padding leaving 245 bytes for the text. This text doesn't reach that, but surpasses 1024 bits.";
        
        foreach (string privateKey in new[] {knownPrivateKey, strippedPrivateKey, tempFilePath})
        {
            string decryptedText = _referenceRSA.DecryptString(privateKey, "pkcs1", cipherText);
            
            Assert.AreEqual(expectedPlainText, decryptedText);
        }
    }
    
    [TestMethod]
    // Pass if the complete flow of generating keys, encrypting and decrypting a string works without error and the decrypted text is the same as the original text
    public void TestCompleteFlow()
    {
        (string publicKey, string privateKey) = _referenceRSA.GenerateKeys(2048);
        string plainText = "About 256 bytes or 2048 bits of text length should matter no problem, maybe leaving at least 11 bytes for pkcs1 padding leaving 245 bytes for the text. This text doesn't reach that, but surpasses 1024 bits.";

        string encryptedText = _referenceRSA.EncryptString(publicKey, "pkcs1", plainText);
        string decryptedText = _referenceRSA.DecryptString(privateKey, "pkcs1", encryptedText);
        
        Assert.AreEqual(plainText, decryptedText);
    }
}