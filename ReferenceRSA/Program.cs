namespace ReferenceRSA;

internal static class CommandLine
{
    static void Main()
    { 
        ReferenceRSA rsa = new ReferenceRSA();
        Console.Write("Enter your public key: ");
        string publicRSAKey = Console.ReadLine();
        Console.WriteLine();
        Console.Write("Enter your message content: ");
        string message = Console.ReadLine();
        Console.WriteLine();
        Console.WriteLine("Encrypted message is:");
        Console.WriteLine();
        Console.WriteLine(rsa.EncryptString(publicRSAKey, message));
    }
}