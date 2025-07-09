# SecureChain - Cryptographic Transaction Management System

A C++ implementation using OpenSSL for secure transaction management between entities, featuring ECC/RSA key pairs, ECDH handshake, and custom AES-128-FancyOFB encryption.

## Implementation Details

### 1. Key Generation (`creare_salvare_chei.cpp` & `generare_rsa.cpp`)

#### ECC Keys (secp256k1)
- **Private Key**: Encrypted with AES-256-CBC using entity password, saved in PKCS8 format
- **Public Key**: Saved in standard EC format
- **GMAC Generation**:
  ```cpp
  // Calculate time difference to 05/05/2005 05:05:05
  time_t timp_tinta = _mkgmtime(&data_tinta); // May 5, 2005, 05:05:05
  double diferenta_secunde = difftime(acum, timp_tinta);
  
  // Generate MAC key using PBKDF2-SHA3-256
  PKCS5_PBKDF2_HMAC(diferenta_timp, lungime_diferenta, 
                    NULL, 0, 10000, EVP_sha3_256(), 16, cheie_mac)
  
  // Generate GMAC with AES-128-GCM
  EVP_MAC_init(context_mac, cheie_mac, 16, parametri)
  ```

#### RSA Keys (3072-bit)
- Generated with same time-based GMAC approach
- Encrypted with hardcoded password: "parolamea2303"
- Saved in PKCS1 format

### 2. ECDH Handshake & Key Derivation (`handshake_ecdh.cpp`)

```cpp
// Extract x,y coordinates from shared ECDH point
EC_POINT_mul(grup, punct_comun, NULL, punct_public_peer, 
             EC_KEY_get0_private_key(cheie_privata), NULL)

// SymLeft: SHA-256(x) split and XORed
SHA256(x, 32, x_hash);
for (int i = 0; i < 16; i++) {
    elemente->sym_left[i] = x_hash[i] ^ x_hash[i + 16];
}

// SymRight: PBKDF2-SHA384(y)
PKCS5_PBKDF2_HMAC((const char*)y, 32, NULL, 0, 1000, 
                  EVP_sha384(), 48, elemente->sym_right)

// SymKey = SymLeft XOR first 16 bytes of SymRight
for (int i = 0; i < 16; i++) {
    elemente->sym_key[i] = elemente->sym_left[i] ^ elemente->sym_right[i];
}
```

### 3. FancyOFB Encryption (`criptare_fancyofb.cpp`)

```cpp
// Create inverted IV
for (int i = 0; i < 16; i++) {
    inv_iv[i] = iv[15 - i]; // Reverse byte order
}

// Standard AES-128-OFB encryption
EVP_EncryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, sym_key, iv)
EVP_EncryptUpdate(ctx, *date_criptate, &lungime_temp, date, lungime_date)

// Apply FancyOFB modification: XOR with inv_IV
for (int i = 0; i < *lungime_date_criptate; i++) {
    (*date_criptate)[i] ^= inv_iv[i % 16];
}
```

### 4. Transaction Creation & Signing (`tranzactii.cpp`)

```cpp
// Create ASN.1 Transaction structure
Transaction* tranzactie = Transaction_new();
ASN1_INTEGER_set(tranzactie->TransactionID, transaction_id);
ASN1_STRING_set(tranzactie->Subject, subiect.c_str(), subiect.length());
// ... set other fields

// Sign with RSA-SHA256
EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey)
EVP_DigestSignUpdate(md_ctx, date, lungime_date)
EVP_DigestSignFinal(md_ctx, *semnatura, &len)
```

### 5. Key Validation (`handshake_validare.cpp`)

Both ECC and RSA public keys are validated by:
1. Loading the stored MAC from `.mac` files
2. Recalculating GMAC over the public key DER encoding
3. Comparing stored vs calculated MAC values

### 6. Binary Logging (`jurnal.cpp`)

Singleton pattern implementation for thread-safe logging:
```cpp
// Format: <data><timp><entitate><actiune>
std::string data = "<" + data_timp.substr(0, 10) + ">";
std::string timp = "<" + data_timp.substr(10) + ">";
std::string id_entitate = "<" + entitate + ">";
std::string actiune_formatata = "<" + actiune + ">";
```

## File Structure

### Input Processing (`Source.cpp`)
1. Read entities and passwords
2. Generate ECC and RSA keys for each entity
3. Process transactions:
   - Verify key authenticity
   - Perform ECDH handshake
   - Save symmetric elements
   - Create and sign transaction
   - Decrypt and verify on receiver side

### ASN.1 Structures (`structuri_asn1.cpp`)
```cpp
ASN1_SEQUENCE(PubKeyMac) = {
    ASN1_SIMPLE(PubKeyMac, PubKeyName, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(PubKeyMac, MACKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PubKeyMac, MACValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(PubKeyMac)
```

## Output Files

- **Keys**: Stored in `output/` directory when using Visual Studio
- **Symmetric Elements**: Base64 encoded DER format
- **Transactions**: Raw DER format with signature
- **Log**: Binary blob format in `info.log`

## Security Notes

- IV for symmetric encryption: Extracted from bytes 16-31 of SymRight
- All private keys encrypted before storage
- GMAC provides key authenticity verification
- RSA signatures ensure transaction integrity
