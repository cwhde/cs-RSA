namespace ReferenceRSA;

// Class that holds the command line interface
internal static class CommandLine
{
    static void Main()
    { 
        ReferenceRSA rsa = new ReferenceRSA(); // Using the ReferenceRSA class
        Console.Write("Enter your public key: "); // Get public key as input
        string publicRSAKey = Console.ReadLine();
        Console.WriteLine();
        Console.Write("Enter your message content: "); // Get message content as input
        string message = Console.ReadLine();
        Console.WriteLine();
        Console.WriteLine("Encrypted message is:");
        Console.WriteLine();
        Console.WriteLine(rsa.EncryptString(publicRSAKey, message)); // Encrypt and output the message
    }
}