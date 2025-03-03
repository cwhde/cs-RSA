namespace RSA.commons;

// Interface to ensure uniformity and similar access between the reference and the self-written RSA classes
public interface ICommonRSA
{
    string EncryptString(string publicKey, string paddingMode, string plainText);
    string DecryptString(string privateKey, string paddingMode, string cipherText);
}