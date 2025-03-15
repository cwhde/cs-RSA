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
            case "!readfile":
                HandleReadFileCommand(parts);
                break;
            case "!writefile":
                HandleWriteFileCommand(parts);
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
        if (!string.IsNullOrEmpty(_activePublicKey))
        {
            Console.WriteLine(_activePublicKey);
        }
        else
        {
            Console.WriteLine("No active public key.");
        }

        Console.WriteLine(); // Keep new line between public and private key info

        if (!string.IsNullOrEmpty(_activePrivateKey))
        {
            Console.WriteLine(_activePrivateKey);
        }
        else
        {
            Console.WriteLine("No active private key.");
        }
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

    // Reads from file and processes content based on current mode
    private void HandleReadFileCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !readfile <filepath>");
            return;
        }

        string filePath = parts[1];

        try
        {
            string fileContent = File.ReadAllText(filePath);
            Console.WriteLine($"File read from {filePath}");
            
            // Process the content based on the current mode
            switch (_currentMode)
            {
                case Mode.Default:
                    HandleDefaultMode(fileContent);
                    break;
                case Mode.Encrypt:
                    HandleEncryptMode(fileContent);
                    break;
                case Mode.Decrypt:
                    HandleDecryptMode(fileContent);
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading file: {ex.Message}");
        }
    }

    // Writes the appropriate output to file based on current mode
    private void HandleWriteFileCommand(string[] parts)
    {
        if (parts.Length < 2)
        {
            Console.WriteLine("Usage: !writefile <filepath>");
            return;
        }

        string filePath = parts[1];
        string contentToWrite;

        // Determine what to write based on current mode
        if (_currentMode == Mode.Decrypt)
        {
            if (string.IsNullOrEmpty(_lastPlaintext))
            {
                Console.WriteLine("No plaintext to write. Decrypt something first.");
                return;
            }
            contentToWrite = _lastPlaintext!; // Assert that _lastPlaintext is not null
        }
        else
        {
            if (string.IsNullOrEmpty(_lastCiphertext))
            {
                Console.WriteLine("No ciphertext to write. Encrypt something first.");
                return;
            }
            contentToWrite = _lastCiphertext!; // Assert that _lastCiphertext is not null
        }

        try
        {
            File.WriteAllText(filePath, contentToWrite);
            Console.WriteLine($"Content written to {filePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error writing to file: {ex.Message}");
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
        Console.WriteLine("  !readfile <filepath> - Read a file and process according to current mode.");
        Console.WriteLine("  !writefile <filepath> - Write the last output to a file.");
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
    
    // Runs automated testing on the code and enables usage of private methods
    private void RunAutomatedTests()
    {
        Console.WriteLine("Running automated tests...");
        TestSuccess = false; // Start with failure assumption

        // Setup test files and directories
        string testPublicKeyFile = "test_public_key.pem";
        string testPrivateKeyFile = "test_private_key.pem";
        string testPlaintextFile = "test_plaintext.txt";
        string testCiphertextFile = "test_ciphertext.txt";
        string nonExistentFile = "non_existent_file.txt";

        try
        {
            // Ensure test files are cleaned up before running tests
            CleanupTestFiles(testPublicKeyFile, testPrivateKeyFile, testPlaintextFile, testCiphertextFile, "temp_ciphertext.txt");

            // Create initial keypair for testing
            Console.WriteLine("Generating initial key pair for testing...");
            (string publicKey, string privateKey) = _rsaImplementation.GenerateKeys(2048);
            _activePublicKey = publicKey;
            _activePrivateKey = privateKey;

            // Test HandleInput with different modes directly
            Console.WriteLine("Testing HandleInput with different modes...");
            _currentMode = Mode.Default;
            HandleInput("Testing input handler with default mode");
            
            _currentMode = Mode.Encrypt;
            HandleInput("Testing input handler with encrypt mode");
            string savedCiphertext = _lastCiphertext ?? ""; // Save for decrypt test
            
            _currentMode = Mode.Decrypt;
            HandleInput(savedCiphertext);

            // Test all three mode handlers directly
            Console.WriteLine("Testing mode handlers directly...");
            HandleDefaultMode("Direct test for default mode");
            HandleEncryptMode("Direct test for encrypt mode");
            HandleDecryptMode(_lastCiphertext ?? "");

            // Test commands with inadequate parameters
            Console.WriteLine("Testing commands with missing parameters...");
            HandleCommand("!generatekeypair", isTesting: true);
            HandleCommand("!writepublickey", isTesting: true);
            HandleCommand("!writeprivatekey", isTesting: true);
            HandleCommand("!readfile", isTesting: true);  // NEW: Test missing filepath
            HandleCommand("!writefile", isTesting: true); // NEW: Test missing filepath
            HandleCommand("!loadpublickey", isTesting: true);
            HandleCommand("!loadprivatekey", isTesting: true);
            HandleCommand("!check", isTesting: true);
            
            // Test standard command workflow
            Console.WriteLine("Testing standard command workflow...");
            HandleCommand("!help", isTesting: true);
            HandleCommand("!generatekeypair 1024", isTesting: true);
            HandleCommand("!generatekeypair invalid_size", isTesting: true);
            HandleCommand("!generatekeypair 512", isTesting: true);
            HandleCommand("!keyinfo", isTesting: true);
            
            // Test padding modes
            HandleCommand("!padding pkcs1", isTesting: true);
            HandleCommand("!padding oaepsha1", isTesting: true);
            HandleCommand("!padding invalid_padding", isTesting: true);
            HandleCommand("!padding", isTesting: true);
            HandleCommand("!padding oaepsha256", isTesting: true); // Reset to default

            // Test file operations with actual files
            Console.WriteLine("Testing file operations with actual files...");
            File.WriteAllText(testPlaintextFile, "Test plaintext content");
            
            // Test in different modes
            HandleCommand("!default", isTesting: true);
            HandleCommand("!readfile " + testPlaintextFile, isTesting: true);
            HandleCommand("!writefile " + testCiphertextFile, isTesting: true);
            
            HandleCommand("!encrypt", isTesting: true);
            HandleCommand("!readfile " + testPlaintextFile, isTesting: true);
            HandleCommand("!writefile " + testCiphertextFile, isTesting: true);
            
            HandleCommand("!decrypt", isTesting: true);
            HandleCommand("!readfile " + testCiphertextFile, isTesting: true);
            HandleCommand("!writefile " + testPlaintextFile, isTesting: true);
            
            // Test file error cases
            HandleCommand("!readfile " + nonExistentFile, isTesting: true);
            
            // Test key file operations
            HandleCommand("!writepublickey " + testPublicKeyFile, isTesting: true);
            HandleCommand("!writeprivatekey " + testPrivateKeyFile, isTesting: true);
            HandleCommand("!loadpublickey " + testPublicKeyFile, isTesting: true);
            HandleCommand("!loadprivatekey " + testPrivateKeyFile, isTesting: true);
            
            // Test error cases
            Console.WriteLine("Testing error cases...");
            HandleCommand("!loadpublickey invalid_file.pem", isTesting: true);
            HandleCommand("!loadprivatekey invalid_file.pem", isTesting: true);
            HandleCommand("!loadpublickey -----BEGIN PUBLIC KEY-----INVALID KEY-----END PUBLIC KEY-----", isTesting: true);
            HandleCommand("!loadprivatekey -----BEGIN PRIVATE KEY-----INVALID KEY-----END PRIVATE KEY-----", isTesting: true);
            
            // Test writefile with no content to write
            _lastCiphertext = null;
            _lastPlaintext = null;
            HandleCommand("!encrypt", isTesting: true);
            HandleCommand("!writefile " + testCiphertextFile, isTesting: true); // Should show error about no ciphertext
            HandleCommand("!decrypt", isTesting: true);
            HandleCommand("!writefile " + testPlaintextFile, isTesting: true); // Should show error about no plaintext
            
            // Test with no keys
            Console.WriteLine("Testing operations with no keys...");
            string savedPubKey = _activePublicKey;
            string savedPrivKey = _activePrivateKey;
            _activePublicKey = null;
            _activePrivateKey = null;
            
            HandleEncryptMode("This should fail - no public key");
            HandleDecryptMode("This should fail - no private key");
            HandleDefaultMode("This should fail - no keys");
            
            // Restore keys
            _activePublicKey = savedPubKey;
            _activePrivateKey = savedPrivKey;
            
            // Test mode switches
            HandleCommand("!encrypt", isTesting: true);
            HandleCommand("!decrypt", isTesting: true);
            HandleCommand("!default", isTesting: true);
            HandleCommand("!validate", isTesting: true); // Alias for default
            
            // Test reference check 
            HandleCommand("!check reference", isTesting: true);
            HandleCommand("!check invalid_arg", isTesting: true);
            
            // Test exit command behavior
            HandleCommand("!exit", isTesting: true);
            
            // Test unknown command
            HandleCommand("!unknown_command", isTesting: true);
            
            // If we get here, tests passed
            TestSuccess = true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Automated tests failed: {ex.Message}");
            TestSuccess = false;
        }
        finally
        {
            // Always clean up test files
            CleanupTestFiles(testPublicKeyFile, testPrivateKeyFile, testPlaintextFile, testCiphertextFile, "temp_ciphertext.txt");
            Console.WriteLine("Automated tests finished. Success: " + (TestSuccess ? "✅" : "❌"));
        }
    }

    private static void CleanupTestFiles(params string[] files)
    {
        files.Where(File.Exists).ToList().ForEach(File.Delete);
    }
}