using RSA.commons;
#pragma warning disable CS8600 // Converting null literal or possible null value to non-nullable type.

namespace RSA.CLI;

static class CommandLine
{
    // Easy command line interface for testing the RSA implementations
    static void Main()
    {
        // Prepare the implementations
        ReferenceRSA.ReferenceRSA referenceImplementation = new ReferenceRSA.ReferenceRSA();
        RSA selfImplemented = new RSA();
        
        // Get padding mode
        string[] validPaddingModes = RSAUtils.GetValidPaddings();
        string paddingMode;
        while (true)
        {
            Console.Write($"Enter the desired padding mode ({string.Join(", ", validPaddingModes)}): ");
            try
            {
                paddingMode = Console.ReadLine();
                if (paddingMode == null || !validPaddingModes.Contains(paddingMode.ToLower())) throw new InvalidOperationException();
                break;
            }      
            catch
            {
                Console.WriteLine("Invalid input. Please try again...\n");
            }
        }
        
        // Get keys
        Console.WriteLine();
        string publicKey = GetValidString("Enter the X509 string of the public key: ");

        Console.WriteLine();
        string privateKey = GetValidString("Enter the X509 string of the private key: ");
        
        // Get, encrypt, double-check, print, decrypt, double-check, print
        string plainText = "";
        while (plainText != "!exit")
        {
            Console.WriteLine();
            plainText = GetValidString("Enter the message to encrypt (!exit to exit): ");
            Console.WriteLine();

            string referenceEncrypted = referenceImplementation.EncryptString(publicKey: publicKey, paddingMode: paddingMode, plainText: plainText);
            string selfEncrypted = selfImplemented.EncryptString(publicKey: publicKey, paddingMode: paddingMode, plainText: plainText);

            Console.WriteLine($"Self-Implementation encryption: \n{selfEncrypted}\n");

            string referenceDecrypted = referenceImplementation.DecryptString(privateKey: privateKey, paddingMode: paddingMode, cipherText: referenceEncrypted);
            string selfDecrypted = selfImplemented.DecryptString(privateKey: privateKey, paddingMode: paddingMode, cipherText: selfEncrypted);
            bool referenceDecryptionSuccess = (selfDecrypted == plainText) && (selfDecrypted == referenceDecrypted);
            string referenceDecryptionStatus = referenceDecryptionSuccess ? "Self-Implementation correct decryption" : "Self-Implementation incorrect decryption";

            Console.WriteLine($"{referenceDecryptionStatus}\n{referenceDecrypted}\n");
        }
    }
    
    private static string GetValidString(string question)
    {
        string input;
        while (true)
        {
            Console.Write(question);
            try
            {
                input = Console.ReadLine() ?? throw new InvalidOperationException();
                if (!string.IsNullOrWhiteSpace(input))
                    break;
                Console.WriteLine("Input cannot be empty. Please try again...\n");
            }
            catch
            {
                Console.WriteLine("Invalid input. Please try again...\n");
            }
            Console.WriteLine();
        }
        return input;
    }
}