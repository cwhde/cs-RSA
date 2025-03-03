[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=alert_status&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Bugs](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=bugs&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=code_smells&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA) [![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=cwhde_cs-RSA&metric=duplicated_lines_density&token=ae26b67b1b638753901b092262914a82990865bc)](https://sonarcloud.io/summary/new_code?id=cwhde_cs-RSA)
# cs-RSA
***
## What this project is for
Rewriting my own implementation of RSA in cs in order to learn how it works.
Part of my Matura-Project examining the implications of Quantum-Computing on modern-day cryptography.

## Features
* Simple CLI for both the reference and self-implemented version
* Self-implemented RSA with PKCS1 Padding for both encryption and decryption
* Parsing of keys of multiple formats (X509 String, PEM File contents, PEM File)

## Planned Features
* Support for OaepSHA1 and OaepSHA256 Padding
* Reference and self-implemented version of key generation
* Cleaner and more feature-rich CLI
* Code coverage and testing
* Cleaned up code and comments

## Double-Checking Config
You can use either the ReferenceRSA project to double-check results.
You can also use [devglan.com](https://www.devglan.com/online-tools/rsa-encryption-decryption) for double-checking as well as generating keys.