[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=alert_status&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Coverage](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=coverage&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=bugs&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=code_smells&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=duplicated_lines_density&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA)

# cs-RSA

## Overview

A custom implementation of RSA encryption in C\# created as part of my Matura-Project on Quantum-Computing's implications for modern cryptography. This project was built to understand RSA's inner workings through hands-on implementation.

## Disclaimer

**Educational Purpose Only:** This is a self-implemented RSA system created for learning and experimentation. While it follows RSA principles, it has not been security-tested and should not be used in production environments. For actual security needs, please use established cryptographic libraries. I am not liable for any security issues arising from its use in sensitive applications.

## Solution Structure

* **RSA:** Custom implementation of RSA encryption/decryption and key generation
* **ReferenceRSA:** Implementation using System.Security.Cryptography for comparison
* **RSA.commons:** Shared interfaces and utilities
* **RSA.CLI:** Command-line interface for demonstration
* **csRSA.Tests:** Comprehensive unit tests


## Current Features

* RSA implementation with PKCS1 Padding
* Key handling (generation, parsing) in X.509/PKCS\#8 format
* Support for various key formats (X509 String, PEM File contents, PEM File)
* CLI for encrypting and decrypting messages
* Comprehensive testing suite


## Planned Features

* OaepSHA1 and OaepSHA256 Padding support
* Enhanced CLI with better user experience
* Implementation unit test interfaces


## Technical Notes

* Uses Big Endian for compatibility with standard RSA implementations
* Relies on BigInteger and BouncyCastle for basic functions
* Only supports X.509/PKCS\#8 keys in the custom implementation


## Learning \& Validation Resources

* **Learning:**
    * [CrypTool](https://www.cryptool.org/en/cto/rsa-step-by-step/) - Step-by-step RSA explanation
    * [RSA Algorithm Demystified (arXiv)](https://arxiv.org/abs/2308.02785) - Detailed documentation
* **Validating Results:**
    * Use the included ReferenceRSA project
    * [AnyCrypt](https://anycript.com/crypto/rsa) - Online tool for RSA operations and validation
