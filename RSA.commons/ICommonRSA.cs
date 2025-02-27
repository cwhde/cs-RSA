namespace RSA.commons;

// Interface to ensure uniformity and similar access between the reference and the self-written RSA classes
public interface ICommonRSA
{
    string EncryptString(string pubKey, string plainText);
    string DecryptString(string privKey, string cipherText);
}