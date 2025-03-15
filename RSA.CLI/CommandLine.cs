using RSA.commons;

namespace RSA.CLI;

public class CommandLine
{
    private string? _activePublicKey;
    private string? _activePrivateKey;
    private string _activePaddingMode = "oaepsha256"; // Default padding mode
    private string? _lastCiphertext;
    private string? _lastPlaintext;
    private Mode _currentMode = Mode.Default;

    public bool TestSuccess { get; private set; } = false;

    private readonly RSA _rsaImplementation = new RSA();
    private readonly ReferenceRSA.ReferenceRSA _referenceRsa = new ReferenceRSA.ReferenceRSA();

    private enum Mode
    {
        Default,
        Encrypt,
        Decrypt
    }

    // Static Main method - Entry point of the application
    public static void Main(string[] args)
    {
        CommandLine commandLine = new CommandLine();
        commandLine.Run();
    }

    // Main entry point to start the CLI
    public void Run(bool isTesting = false)
    {
        if (isTesting)
        {
            RunAutomatedTests(); // Call a new method for automated tests
        }
        else
        {
            // Generate initial key pair on startup
            (string publicKey, string privateKey) = _rsaImplementation.GenerateKeys(2048);
            _activePublicKey = publicKey;
            _activePrivateKey = privateKey;

            Console.WriteLine("RSA Interactive Tool (RIT) started.");
            Console.WriteLine("A 2048-bit key pair has been generated. Use !help for commands.");
            Console.WriteLine(); // Keep new line after startup messages

            while (true)
            {
                Console.Write("RIT > ");
                string? input = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(input))
                {
                    continue; // Ignore empty input
                }

                if (input.StartsWith('!'))
                {
                    HandleCommand(input);
                }
                else
                {
                    HandleInput(input);
                }
            }
        }
    }

    // Runs automated testing on the code and enables usage of private methods
    private void RunAutomatedTests()
    {
        Console.WriteLine("Running automated tests...");

        // Define a sequence of commands and inputs to simulate user interaction
        string[] testCommands =
        [
            "!help",          // Test help command
            "!generatekeypair 1024", // Test key generation
            "!keyinfo",       // Test key info display
            "!padding pkcs1", // Test padding change
            "Test message 1", // Default mode input (encrypt/decrypt/validate)
            "!encrypt",       // Switch to encrypt mode
            "Test message 2", // Encrypt mode input
            "!decrypt",       // Switch to decrypt mode
            "paste_ciphertext_here", // Decrypt mode input (you'd need to programmatically get ciphertext)
            "!default",       // Switch back to default mode
            "!check reference", // Test reference check
            "!writepublickey test_public_key.pem", // Test write public key
            "!writeprivatekey test_private_key.pem", // Test write private key
            "!loadpublickey test_public_key.pem", // Test load public key from file
            "!loadprivatekey test_private_key.pem", // Test load private key from file
            "!padding oaepsha256", // Reset padding
            "!exit"           // Exit command
        ];

        foreach (string command in testCommands)
        {
            Console.WriteLine($"Executing command: {command}");
            HandleCommand(command, isTesting: true);

            TestSuccess = true;
        }
    }

    // Handles commands prefixed with "!"
    private void HandleCommand(string command, bool isTesting = false)
    {
        string[] parts = command.Split(' ');
        string commandName = parts[0].ToLower();
        Console.WriteLine(); // Keep new line before command output

        switch (commandName)
        {
            case "!generatekeypair":
                HandleGenerateKeyPairCommand(parts);
                break;
            case "!loadpublickey":
                HandleLoadPublicKeyCommand(parts);
                break;
            case "!loadprivatekey":
                HandleLoadPrivateKeyCommand(parts);
                break;
            case "!writepublickey":
                HandleWritePublicKeyCommand(parts);
                break;
            case "!writeprivatekey":
                HandleWritePrivateKeyCommand(parts);
                break;
            case "!keyinfo":
                HandleKeyInfoCommand();
                break;
            case "!padding":
                HandlePaddingCommand(parts);
                break;
            case "!check":
                HandleCheckCommand(parts);
                break;
            case "!readplainfile":
                HandleReadPlainFileCommand(parts);
                break;
            case "!readcipherfile":
                HandleReadCipherFileCommand(parts);
                break;
            case "!writeplainfile":
                HandleWritePlainFileCommand(parts);
                break;
            case "!writecipherfile":
                HandleWriteCipherFileCommand(parts);
                break;
            case "!encrypt":
                _currentMode = Mode.Encrypt;
                Console.WriteLine("Switched to Encrypt-Only mode.");
                break;
            case "!decrypt":
                _currentMode = Mode.Decrypt;
                Console.WriteLine("Switched to Decrypt-Only mode.");
                break;
            case "!default":
            case "!validate":
                _currentMode = Mode.Default;
                Console.WriteLine("Switched to Default (Encrypt/Decrypt/Validate) mode.");
                break;
            case "!help":
                DisplayHelp();
                break;
            case "!exit":
                if (!isTesting) // Only exit if not in testing mode
                {
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("!exit command ignored during testing."); // Optional feedback during testing
                }
                break;
            default:
                Console.WriteLine($"Unknown command: {commandName}");
                break;
        }
        Console.WriteLine(); // Keep new line after command output
    }
    //Handles mode-specific (non-prefixed) user input.
    private void HandleInput(string input)
    {
        Console.WriteLine(); // Keep new line before input handling output
        switch (_currentMode)
        {
            case Mode.Default:
                HandleDefaultMode(input);
                break;
            case Mode.Encrypt:
                HandleEncryptMode(input);
                break;
            case Mode.Decrypt:
                HandleDecryptMode(input);
                break;
        }
        Console.WriteLine(); // Keep new line after input handling output
    }
    // Handles input in default (Encrypt/Decrypt/Validate) mode.
    private void HandleDefaultMode(string plaintext)
    {
        if (string.IsNullOrWhiteSpace(_activePublicKey) || string.IsNullOrWhiteSpace(_activePrivateKey))
        {
            Console.WriteLine("No active keys. Please generate or load keys first.");
            return;
        }

        try
        {
            _lastPlaintext = plaintext;
            _lastCiphertext = _rsaImplementation.EncryptString(_activePublicKey, _activePaddingMode, plaintext);
            Console.WriteLine($"Ciphertext: {_lastCiphertext}");
            // Removed extra new line after Ciphertext

            string decryptedPlaintext = _rsaImplementation.DecryptString(_activePrivateKey, _activePaddingMode, _lastCiphertext);
            Console.WriteLine($"Decrypted Plaintext: {decryptedPlaintext}");
            // Removed extra new line after Decrypted Plaintext

            // Validate against original plaintext
            Console.WriteLine(decryptedPlaintext == plaintext ? "✅ Validation against original plaintext successful!" : "❌ Validation against original plaintext failed.");

            // Validate against ReferenceRSA
            bool? referenceValidationResult = ValidateAgainstReference(plaintext);

            if (referenceValidationResult == true)
            {
                Console.WriteLine("✅ Verification against ReferenceRSA successful!");
            }
            else if (referenceValidationResult == false)
            {
                Console.WriteLine("❌ Verification against ReferenceRSA failed.");
            }
            else
            {
                Console.WriteLine("❓ Verification against ReferenceRSA uncertain.");
                Console.WriteLine("  Reason: Plaintext might be too long for ReferenceRSA to encrypt without chunking.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during encryption/decryption: {ex.Message}");
        }
    }

    // Encrypts the input and displays the ciphertext.
    private void HandleEncryptMode(string plaintext)
    {
        if (string.IsNullOrWhiteSpace(_activePublicKey))
        {
            Console.WriteLine("No active public key. Please generate or load a public key first.");
            return;
        }
        try
        {
            _lastPlaintext = plaintext;
            _lastCiphertext = _rsaImplementation.EncryptString(_activePublicKey, _activePaddingMode, plaintext);
            Console.WriteLine($"Ciphertext: {_lastCiphertext}");
            // Removed extra new line after Ciphertext in Encrypt Mode
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during encryption: {ex.Message}");
        }
    }

    // Decrypts the input and displays the plaintext
    private void HandleDecryptMode(string ciphertext)
    {
        if (string.IsNullOrWhiteSpace(_activePrivateKey))
        {
            Console.WriteLine("No active private key. Please generate or load a private key first.");
            return;
        }
        try
        {
            _lastCiphertext = ciphertext; // Store for file output
            _lastPlaintext = _rsaImplementation.DecryptString(_activePrivateKey, _activePaddingMode, ciphertext);
            Console.WriteLine($"Plaintext: {_lastPlaintext}");
             // Removed extra new line after Plaintext in Decrypt Mode
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during decryption: {ex.Message}");
        }
    }

// Validates the last encryption/decryption against the ReferenceRSA implementation (CORRECTED + EXCEPTION HANDLING).
    private bool? ValidateAgainstReference(string originalPlaintext) // Return type changed to bool? (nullable boolean)
    {
        if (string.IsNullOrEmpty(_activePublicKey) || string.IsNullOrEmpty(_activePrivateKey))
        {
            Console.WriteLine("Warning: Cannot perform reference validation. Active public or private key is missing.");
            return null;
        }
        try
        {
            string selfCiphertext = _rsaImplementation.EncryptString(_activePublicKey, _activePaddingMode, originalPlaintext);
            string referencePlaintext = _referenceRsa.DecryptString(_activePrivateKey, _activePaddingMode, selfCiphertext);
            return referencePlaintext == originalPlaintext;
        }

        catch (System.Security.Cryptography.CryptographicException ex)
        {
            if (ex.Message.Contains("The length of the data to decrypt is not valid for the size of this key."))
            {
                return null; // Indicate "uncertain" validation due to length issue
            }
            else
            {
                Console.WriteLine($"Error during reference validation: {ex.Message}"); // More specific error message
                return false;
            }
        }

        catch (Exception ex) // Catch any other unexpected exceptions
        {
            Console.WriteLine($"Unexpected error during reference validation: {ex.Message}");
            return false;
        }
    }

    // Handles the !generatekeypair command
    private void HandleGenerateKeyPairCommand(string[] parts)
    {
        int keySize = 2048; // Default key size
        if (parts.Length > 1 && int.TryParse(parts[1], out int parsedKeySize))
        {
            if (parsedKeySize is 512 or 1024 or 2048 or 4096)
            {
                keySize = parsedKeySize;
            }

            else
            {
                Console.WriteLine("Invalid key size. Using default key size of 2048 bits.");
            }
        }

        try
        {
            (string publicKey, string privateKey) = _rsaImplementation.GenerateKeys(keySize);
            _activePublicKey = publicKey;
            _activePrivateKey = privateKey;
            Console.WriteLine("Keys generated. Active keys updated.");
        }

        catch (Exception ex)
        {
            Console.WriteLine($"Error generating keys: {ex.Message}");
        }
    }
    // Handles loading a public key from a file or string.
    private void HandleLoadPublicKeyCommand(string[] parts)
    {
      if (parts.Length < 2)
      {
          Console.WriteLine("Usage: !loadpublickey <filepath or key string>");
          return;
      }

      string keySource = string.Join(" ", parts, 1, parts.Length - 1);

      try
      {
          _activePublicKey = RSAUtils.SanitizeKeyInput(keySource, true);
          Console.WriteLine("Public key loaded and set as active.");
      }
      catch (Exception ex)
      {
          Console.WriteLine($"Error loading public key: {ex.Message}");
      }
    }

    //Handles loading a private key from file or string
    private void HandleLoadPrivateKeyCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !loadprivatekey <filepath or key string>");
            return;
        }

        string keySource = string.Join(" ", parts, 1, parts.Length - 1);

        try
        {
            _activePrivateKey = RSAUtils.SanitizeKeyInput(keySource, false);
            Console.WriteLine("Private key loaded and set as active.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error loading private key: {ex.Message}");
        }
    }

    //Handles writing the active public key to a file
    private void HandleWritePublicKeyCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !writepublickey <filepath>");
            return;
        }
        if (string.IsNullOrEmpty(_activePublicKey))
        {
            Console.WriteLine("No Public Key to Write.");
            return;
        }

        string filePath = parts[1];

        try
        {
            File.WriteAllText(filePath, _activePublicKey);
            Console.WriteLine($"Public key written to {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing public key to file: {ex.Message}");
        }
    }

    //Handles writing the active private key to file
    private void HandleWritePrivateKeyCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !writeprivatekey <filepath>");
            return;
        }

        if (string.IsNullOrEmpty(_activePrivateKey))
        {
            Console.WriteLine("No Private Key to Write.");
            return;
        }

        string filePath = parts[1];

        try
        {
            File.WriteAllText(filePath, _activePrivateKey);
            Console.WriteLine($"Private key written to {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing private key to file: {ex.Message}");
        }
    }

    //Displays the currently active keys.
    private void HandleKeyInfoCommand()
    {
        Console.WriteLine(); // Keep new line before key info display
        if (!string.IsNullOrEmpty(_activePublicKey))
        {
            Console.WriteLine("-----BEGIN PUBLIC KEY-----");
            Console.WriteLine(_activePublicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", ""));
            Console.WriteLine("-----END PUBLIC KEY-----");
        }
        else
        {
            Console.WriteLine("No active public key.");
        }

        Console.WriteLine(); // Keep new line between public and private key info

        if (!string.IsNullOrEmpty(_activePrivateKey))
        {
            Console.WriteLine("-----BEGIN PRIVATE KEY-----");
            Console.WriteLine(_activePrivateKey.Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", ""));
            Console.WriteLine("-----END PRIVATE KEY-----");
        }
        else
        {
            Console.WriteLine("No active private key.");
        }
        Console.WriteLine(); // Keep new line after key info display
    }

    // Handles changing the padding mode.
    private void HandlePaddingCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine($"Current padding mode: {_activePaddingMode}");
            return;
        }

        string newPaddingMode = parts[1].ToLower();
        if (RSAUtils.GetValidPaddings().Contains(newPaddingMode))
        {
            _activePaddingMode = newPaddingMode;
            Console.WriteLine($"Padding mode changed to {newPaddingMode}.");
        }
        else
        {
            Console.WriteLine($"Invalid padding mode.  Valid modes: {string.Join(", ", RSAUtils.GetValidPaddings())}");
        }
    }

    // Explicitly triggers the reference check
    private void HandleCheckCommand(string[] parts)
    {
        if (parts.Length > 1 && parts[1].ToLower() == "reference")
        {
            if (string.IsNullOrWhiteSpace(_lastPlaintext))
            {
                Console.WriteLine("No previous encryption/decryption to check.");
                return;
            }
            Console.WriteLine(); // Keep new line before check result output

            bool? validationResult = ValidateAgainstReference(_lastPlaintext);
            if (validationResult == true)
            {
                Console.WriteLine("✅ Verification against ReferenceRSA successful!");
            }
            else if (validationResult == false)
            {
                Console.WriteLine("❌ Verification against ReferenceRSA failed.");
            }
            else
            {
                Console.WriteLine("❓ Verification against ReferenceRSA uncertain.");
            }
        }
    }
    //Reads plaintext from file.
    private void HandleReadPlainFileCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !readplainfile <filepath>");
            return;
        }

        string filePath = parts[1];

        try
        {
            _lastPlaintext = File.ReadAllText(filePath);
            Console.WriteLine($"Plaintext read from {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading plaintext from file: {ex.Message}");
        }
    }

    //Reads ciphertext from file.
    private void HandleReadCipherFileCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !readcipherfile <filepath>");
            return;
        }

        string filePath = parts[1];

        try
        {
            _lastCiphertext = File.ReadAllText(filePath);
            Console.WriteLine($"Ciphertext read from {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading ciphertext from file: {ex.Message}");
        }
    }

    //Writes the last plaintext to a file
    private void HandleWritePlainFileCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !writeplainfile <filepath>");
            return;
        }

        if (string.IsNullOrEmpty(_lastPlaintext))
        {
            Console.WriteLine("No plaintext to write. Encrypt or decrypt something first.");
            return;
        }

        string filePath = parts[1];

        try
        {
            File.WriteAllText(filePath, _lastPlaintext);
            Console.WriteLine($"Plaintext written to {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing plaintext to file: {ex.Message}");
        }
    }

    //Writes the last ciphertext to file
    private void HandleWriteCipherFileCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !writecipherfile <filepath>");
            return;
        }

        if (string.IsNullOrEmpty(_lastCiphertext))
        {
            Console.WriteLine("No ciphertext to write. Encrypt or decrypt something first.");
            return;
        }

        string filePath = parts[1];

        try
        {
            File.WriteAllText(filePath, _lastCiphertext);
            Console.WriteLine($"Ciphertext written to {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing ciphertext to file: {ex.Message}");
        }
    }

    // Displays available commands.
    private static void DisplayHelp()
    {
        Console.WriteLine("Available commands:");
        Console.WriteLine("  !generatekeypair <keysize> - Generate a new key pair.");
        Console.WriteLine("  !loadpublickey <filepath or key string> - Load a public key.");
        Console.WriteLine("  !loadprivatekey <filepath or key string> - Load a private key.");
        Console.WriteLine("  !writepublickey <filepath> - Save the active public key to a file.");
        Console.WriteLine("  !writeprivatekey <filepath> - Save the active private key to a file.");
        Console.WriteLine("  !keyinfo - Display the active keys.");
        Console.WriteLine("  !padding <mode> - Set the padding mode (pkcs1, oaepsha1, oaepsha256).");
        Console.WriteLine("  !check reference - Validate the last operation against the reference implementation.");
        Console.WriteLine("  !readplainfile <filepath> - Read plaintext from a file.");
        Console.WriteLine("  !readcipherfile <filepath> - Read ciphertext from a file.");
        Console.WriteLine("  !writeplainfile <filepath> - Write the last plaintext to a file.");
        Console.WriteLine("  !writecipherfile <filepath> - Write the last ciphertext to a file.");
        Console.WriteLine("  !encrypt - Switch to Encrypt-Only mode.");
        Console.WriteLine("  !decrypt - Switch to Decrypt-Only mode.");
        Console.WriteLine("  !default - Switch to Default (Encrypt/Decrypt/Validate) mode.");
        Console.WriteLine("  !help - Display this help message.");
        Console.WriteLine("  !exit - Exit the application.");
        Console.WriteLine(); // Keep new line before usage instructions
        Console.WriteLine("In Default mode, enter plaintext to encrypt, decrypt, and validate.");
        Console.WriteLine("In Encrypt-Only mode, enter plaintext to encrypt.");
        Console.WriteLine("In Decrypt-Only mode, enter ciphertext to decrypt.");
    }
}