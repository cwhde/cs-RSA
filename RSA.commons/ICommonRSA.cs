namespace RSA.commons;

public interface ICommonRSA
{
    string EncryptString(string pubKey, string plainText);
    string DecryptString(string privKey, string cipherText);
}