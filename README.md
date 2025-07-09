# SecureChain - Cryptographic Transaction Management System

A C++ implementation using OpenSSL for secure transaction management between entities with ECC key pairs, ECDH key exchange, and custom AES-128-FancyOFB encryption.

## Features

- **ECC Key Generation**: 256-bit elliptic curve keys (secp256k1) with encrypted private key storage
- **RSA Key Generation**: 3072-bit RSA keys for transaction signing
- **Key Authentication**: GMAC validation using PBKDF2-SHA3-256
- **ECDH Key Exchange**: Secure symmetric key derivation through handshake protocol
- **Custom Encryption**: AES-128-FancyOFB mode with inverted IV XOR operation
- **Transaction Management**: DER-encoded transactions with RSA signatures
- **Binary Logging**: Action journaling in blob format

## Key Components

### ASN.1 Structures
- `PubKeyMAC`: Stores public key authentication data
- `SymElements`: Contains symmetric encryption elements (Base64 encoded)
- `Transaction`: Complete transaction structure with encrypted data and signature

### File Outputs
- **ECC Keys**: `{id}_priv.ecc`, `{id}_pub.ecc` (PEM format, PKCS8)
- **RSA Keys**: `{id}_priv.rsa`, `{id}_pub.rsa` (PEM format, PKCS1)
- **MAC Files**: `{id}_ecc.mac`, `{id}_rsa.mac` (DER encoded)
- **Symmetric Elements**: `{id}.sym` (Base64 encoded DER)
- **Transactions**: `{sender}_{receiver}_{id}.trx` (Raw DER)
- **Log File**: `info.log` (Binary blob format)

## Cryptographic Process

1. **Key Derivation**:
   - SymLeft = SHA-256(x) split and XORed
   - SymRight = PBKDF2-SHA384(y, no salt, 1000 iterations)
   - SymKey = SymLeft ⊕ First_16_bytes(SymRight)

2. **FancyOFB Encryption**:
   - Standard AES-128-OFB with additional XOR using inverted IV
   - inv_IV = reverse(IV)

3. **Transaction Flow**:
   - Generate and validate keys
   - Perform ECDH handshake
   - Encrypt message with derived symmetric key
   - Sign transaction with RSA private key
   - Verify signature and decrypt on receiver side

## Building & Running

```bash
# Requires OpenSSL library
# Visual Studio 2022 project included
# Run with input file:
SecureChain.exe input.txt
```

## Input Format
```
<number_of_entities>
<entity_id> <password>
...
<number_of_transactions>
<transaction_id>/<sender_id>/<receiver_id>/<subject>/<message>
...
```

## Dependencies
- OpenSSL 3.x
- C++20
- Windows (uses `_mkgmtime`)
