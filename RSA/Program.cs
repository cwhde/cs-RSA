using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RSA;

public static class CommandLine
{
    static void Main()
    { 
        RSA rsa = new RSA();    // Using the ReferenceRSA class
        Console.Write("Enter your public key: "); // Get public key as input
        string publicRSAKey = Console.ReadLine()!;
        Console.WriteLine();
        Console.Write("Enter your private key: ");
        string privateRSAKey = Console.ReadLine()!;
        Console.WriteLine();
        Console.Write("Enter your message content: "); // Get message content as input
        string message = Console.ReadLine()!;
        Console.WriteLine();
        Console.WriteLine("Encrypted message is:");
        Console.WriteLine();
        Console.WriteLine(rsa.EncryptString(publicRSAKey, "pkcs1", message)); // Encrypt and output the message
        Console.WriteLine();
        Console.WriteLine("Decrypted message is:");
        Console.WriteLine();
        Console.WriteLine(rsa.DecryptString(privateRSAKey, "pkcs1", rsa.EncryptString(publicRSAKey, "pkcs1", message))); // Decrypt and output the message
    }
}