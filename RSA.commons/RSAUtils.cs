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
        string headerType = isPublic ? "PUBLIC KEY" : "PRIVATE KEY";
        string pemHeader = $"-----BEGIN {headerType}-----";
        string pemFooter = $"-----END {headerType}-----";

        // Check if it could be a filepath and read the file's contents as key if so
        if (File.Exists(inputKey)) inputKey = File.ReadAllText(inputKey);

        // Always normalize the key by removing existing headers and formatting
        string normalizedKey = inputKey
            .Replace("-----BEGIN PUBLIC KEY-----", "")
            .Replace("-----END PUBLIC KEY-----", "")
            .Replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .Replace("-----END RSA PRIVATE KEY-----", "")
            .Replace("-----BEGIN PRIVATE KEY-----", "")
            .Replace("-----END PRIVATE KEY-----", "")
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();

        // Format with correct headers
        StringBuilder formattedKey = new StringBuilder();
        formattedKey.AppendLine(pemHeader);

        // Restrict lines to 64 characters as per the PEM format
        for (int i = 0; i < normalizedKey.Length; i += 64)
        {
            formattedKey.AppendLine(normalizedKey.Substring(i, Math.Min(64, normalizedKey.Length - i)));
        }

        formattedKey.AppendLine(pemFooter);

        return formattedKey.ToString();
    }
}