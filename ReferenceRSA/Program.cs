namespace ReferenceRSA;

internal static class CommandLine
{
    static void Main()
    { 
        // Check RSA implementation with user input
        // ReSharper disable once InconsistentNaming
        ReferenceRSA RSA = new ReferenceRSA();      // Reference Implementation
        Console.Write("Enter your public key: ");
        string publicKey = Console.ReadLine()!;     // Don't handle null input
        Console.WriteLine();
        
        Console.Write("Enter your private key: ");
        string privateKey = Console.ReadLine()!;
        Console.WriteLine();
        
        Console.Write("Enter your message content: ");
        string message = Console.ReadLine()!;
        Console.WriteLine();

        string encryptedMessage = RSA.EncryptString(publicKey: publicKey, paddingMode: "pkcs1", plainText: message);
        Console.WriteLine($"Encrypted message is:\n{encryptedMessage}\n");

        string decryptedMessage = RSA.DecryptString(privateKey: privateKey, paddingMode: "pkcs1", cipherText: encryptedMessage);
        Console.WriteLine($"Decrypted message is:\n{decryptedMessage}\n");
    }
}