using System.Text;

namespace RSA.commons;

public static class RSAUtils
{
    // Method that returns an array of valid padding modes
    public static string [] GetValidPaddings()
    {
        return ["pkcs1", "oaepsha1", "oaepsha256"];
    }
    
    // Method that takes a public key input of multiple kinds (filepath, PEM or shortened PEM) and returns a formatted PEM string with correct headers
    public static string SanitizeKeyInput(string inputKey, bool isPublic)
    {
        // Create header based on type
        string header = isPublic ? "PUBLIC" : "PRIVATE";
        string pemHeader = $"-----BEGIN {header} KEY-----";
        string pemFooter = $"-----END {header} KEY-----";
        
        // Check if it could be a filepath and return the file's contents if so
        if (File.Exists(inputKey)) return File.ReadAllText(inputKey);
        
        // Check if the input, which is not a file, mismatches RSA PEM format and format it accordingly
        else if (!inputKey.Contains(pemHeader))
        {
            inputKey = inputKey.Replace("\n", "").Replace("\r", "");

            StringBuilder formattedKey = new StringBuilder();
            formattedKey.AppendLine(pemHeader);
            
            // Restrict lines to 64 characters as per the PEM format
            for (int i = 0; i < inputKey.Length; i += 64)
            {
                formattedKey.AppendLine(inputKey.Substring(i, Math.Min(64, inputKey.Length - i)));
            }

            formattedKey.AppendLine(pemFooter);
            
            return formattedKey.ToString();
        }
        
        // If it's neither a file nor a misformatted key we can't do anything with it and assume it is a correct PEM key
        else return inputKey;
    }
}