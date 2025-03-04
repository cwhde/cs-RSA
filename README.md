[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=alert_status&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=bugs&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=code_smells&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=duplicated_lines_density&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA)
# cs-RSA
***
## What this project is for
Rewriting my own implementation of RSA in cs in order to learn how it works.
Part of my Matura-Project examining the implications of Quantum-Computing on modern-day cryptography.

## Features
* Self-implemented RSA with PKCS1 Padding for both encryption and decryption
* Parsing of keys of multiple formats (X509 String, PEM File contents, PEM File)
* Simple CLI for encrypting and decrypting messages and seeing whether it works

## Planned Features
* Support for OaepSHA1 and OaepSHA256 Padding
* Actually working self-implemented key generation (currently giving errors, no time to fix)
* Clean and feature-rich CLI
* Code coverage and testing

## More information on how it works
* [CrypTool](https://www.cryptool.org/en/cto/rsa-step-by-step/) explanation of what RSA does step-by-step (Key Generation + Encryption + Decryption)
* [Demystifying the RSA Algorithm: An Intuitive Introduction for Novices in Cybersecurity (arXiv)](https://arxiv.org/abs/2308.02785) detailed document that explains RSA and what makes it work including all concepts from the  basic math to the actual algorithm
* [Devglan.com](https://www.devglan.com/online-tools/rsa-encryption-decryption) for experimenting, checking and generating keys

## Double-Checking Config
You can use either the ReferenceRSA project to double-check results.
You can also use [devglan.com](https://www.devglan.com/online-tools/rsa-encryption-decryption) for double-checking as well as generating keys.