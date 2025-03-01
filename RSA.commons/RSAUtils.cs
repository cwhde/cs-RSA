using System.Text;

namespace RSA.commons;

// Class that holds various utility methods aiding the RSA classes
public static class RSAUtils
{
    // Method that returns an array of allowed padding modes
    public static string [] AllowedPaddings()
    {
        return ["pkcs1", "oaepsha1", "oaepsha256"];
    }
    
    // Method that takes a public key input of multiple kinds (filepath, PEM or shortened PEM) and returns a formatted PEM string with correct headers
    public static string SanitizeKeyInput(string input, bool isPublic)
    {
        // Determine the header based on whether the key is public or private
        string header = isPublic ? "PUBLIC" : "PRIVATE";
        string pemHeader = $"-----BEGIN {header} KEY-----";
    
        // Check if it could be a filepath and return the file's contents if so
        if (File.Exists(input)) return File.ReadAllText(input);
        // Check if the input, which is not a file, mismatches RSA PEM format and format it accordingly
        else if (!input.Contains(pemHeader))
        {
            // Remove line breaks and carriage returns from the input
            input = input.Replace("\n", "").Replace("\r", "");
            // Start the formatted key with the PEM header
            string formattedKey = $"{pemHeader}\n";
            // Restrict lines to 64 characters as per the PEM format
            StringBuilder keyBuilder = new StringBuilder();
            for (int i = 0; i < input.Length; i += 64)
            {
                keyBuilder.Append(input.Substring(i, Math.Min(64, input.Length - i))).Append("\n");
            }
            formattedKey += keyBuilder.ToString();
            // End the formatted key with the PEM footer
            formattedKey += $"-----END {header} KEY-----";
            return formattedKey;
        }
        // If it's neither a file nor a misformatted key we can't do anything with it and assume it is a correct PEM key
        else return input;
    }
}