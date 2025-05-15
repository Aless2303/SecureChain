#pragma warning(disable : 4996)
#include "creare_salvare_chei.h"
#include "structuri_asn1.h"
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/bio.h> 
#include <openssl/err.h> 
#include <openssl/applink.c>
#include <string>
#include <stdio.h>
#include <ctime>

//functia care va calcula diferenta de timp pana la 5 mai 2005, 05:05:05.
int calculeaza_diferenta_timp(unsigned char* diferenta, size_t* lungime_diferenta)
{
    time_t acum = time(nullptr);
    struct tm data_acum = *gmtime(&acum);

    //creez data tinta 5mai2005 05:05:05
    struct tm data_tinta = { 0 };
    data_tinta.tm_year = 2005 - 1900; //anul 2005 in formatul tm, anul incepe din 1900;
    data_tinta.tm_mon = 4; // am pus 4 nu 5 caci sunt de la 0 la 11.
    data_tinta.tm_mday = 5;
    data_tinta.tm_hour = 5;
    data_tinta.tm_sec = 5;

    //calculez diferenta in secunde.
    time_t timp_tinta = _mkgmtime(&data_tinta);
    if (timp_tinta == -1)
    {
        printf("eroare la convertirea timpului tinta din 2005 in secunde");
        return 1;
    }

    double diferenta_secunde = difftime(acum, timp_tinta);

    char diferenta_string[32];
    snprintf(diferenta_string, sizeof(diferenta_string), "%0.f", diferenta_secunde);
    *lungime_diferenta = strlen(diferenta_string);
    memcpy(diferenta, diferenta_string, *lungime_diferenta);
    return 0;
}

//functie de creare si salvare chei
int creeaza_salveaza_chei(const std::string& nume_entitate, const std::string& fisier_cheie_privata,
    const std::string& fisier_cheie_publica, const std::string& fisier_mac) {

    EC_KEY* cheie_ec = nullptr;
    EVP_PKEY* pkey = nullptr;
    BIO* bio = nullptr;

    // Extrage ID-ul entității din nume_entitate (presupunem că este un număr)
    int id_entitate = atoi(nume_entitate.c_str());

    // Formăm noile nume de fișiere conform convențiilor
    char nume_cheie_privata[256], nume_cheie_publica[256], nume_mac[256];
    sprintf(nume_cheie_privata, "%d_priv.ecc", id_entitate);
    sprintf(nume_cheie_publica, "%d_pub.ecc", id_entitate);
    sprintf(nume_mac, "%d_ecc.mac", id_entitate);

    //creez o pereche de chei pe curba secp256k1 cu ajutorul openssl.
    cheie_ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!cheie_ec || !EC_KEY_generate_key(cheie_ec)) {
        printf("eroare la generarea cheii EC\n");
        EC_KEY_free(cheie_ec);
        return 1;
    }

    pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey, cheie_ec)) {
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Salvez cheia privată în format PKCS8
    bio = BIO_new_file(nume_cheie_privata, "w");
    if (!bio) {
        printf("eroare la deschiderea fisierului %s: ", nume_cheie_privata);
        ERR_print_errors_fp(stderr);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (!PEM_write_bio_PKCS8PrivateKey(bio, pkey, EVP_aes_256_cbc(), (unsigned char*)"parolamea2303", strlen("parolamea2303"), nullptr, nullptr)) {
        printf("eroare la salvarea cheii private: ");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    BIO_free_all(bio);

    // Salvez cheia publică în format specific EC
    bio = BIO_new_file(nume_cheie_publica, "w");
    if (!bio) {
        printf("eroare la deschiderea fisierului %s: ", nume_cheie_publica);
        ERR_print_errors_fp(stderr);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (!PEM_write_bio_EC_PUBKEY(bio, cheie_ec))
    {
        printf("eroare la salvarea cheii publice: ");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    BIO_free_all(bio);

    //calculez diferenta de timp si generez cheia pentru GMAC.
    unsigned char diferenta_timp[32];
    size_t lungime_diferenta;
    if (calculeaza_diferenta_timp(diferenta_timp, &lungime_diferenta) != 0) {
        printf("eroare la calcularea diferentei de timp\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // Generez cheia pentru GMAC (16 bytes pentru AES-128) folosind PBKDF2 cu SHA3-256
    unsigned char cheie_mac[16]; // Redus de la 32 la 16 bytes pentru AES-128
    const EVP_MD* digest = EVP_sha3_256();
    if (!digest) {
        printf("eroare la obtinerea sha3-256\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (PKCS5_PBKDF2_HMAC((const char*)diferenta_timp, lungime_diferenta,
        NULL, 0, 10000, digest, sizeof(cheie_mac), cheie_mac) != 1) {
        printf("eroare la generarea cheii MAC cu pbkdf2\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    //transform cheia publica din format DER
    unsigned char* cheie_publica_der = nullptr;
    int lungime_cheie_publica = i2d_PUBKEY(pkey, &cheie_publica_der);
    if (lungime_cheie_publica <= 0)
    {
        printf("eroare la transformarea cheii publice in format DER\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    //generam GMAC
    unsigned char valoare_mac[16]; // 16 bytes pentru GMAC
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "GMAC", NULL);
    EVP_MAC_CTX* context_mac = EVP_MAC_CTX_new(mac);

    unsigned char iv[12] = { 0 };

    OSSL_PARAM parametri[3];
    parametri[0] = OSSL_PARAM_construct_utf8_string("cipher", (char*)"AES-128-GCM", 0);
    parametri[1] = OSSL_PARAM_construct_octet_string("iv", iv, sizeof(iv));
    parametri[2] = OSSL_PARAM_construct_end();
    size_t lungime_valoare_mac = sizeof(valoare_mac);

    if (!context_mac ||
        !EVP_MAC_init(context_mac, cheie_mac, sizeof(cheie_mac), parametri) ||
        !EVP_MAC_update(context_mac, cheie_publica_der, lungime_cheie_publica) ||
        !EVP_MAC_final(context_mac, valoare_mac, &lungime_valoare_mac, sizeof(valoare_mac))) {
        printf("Eroare la generarea GMAC\n");
        ERR_print_errors_fp(stderr);
        EVP_MAC_CTX_free(context_mac);
        EVP_MAC_free(mac);
        OPENSSL_free(cheie_publica_der);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    EVP_MAC_CTX_free(context_mac);
    EVP_MAC_free(mac);
    OPENSSL_free(cheie_publica_der);

    //acum avem gmac-ul si trebuie sa il salvam in format DER.
    PubKeyMac* mac_structura = PubKeyMac_new();
    if (!mac_structura) {
        printf("eroare la crearea structurii PubKeyMac\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    ASN1_STRING_set(mac_structura->PubKeyName, nume_entitate.c_str(), nume_entitate.length());
    ASN1_STRING_set(mac_structura->MACKey, cheie_mac, sizeof(cheie_mac));
    ASN1_STRING_set(mac_structura->MACValue, valoare_mac, lungime_valoare_mac);

    //transformam structura in formatul DER.
    unsigned char* date_der = nullptr;
    int lungime_der = i2d_PubKeyMac(mac_structura, &date_der);
    if (lungime_der <= 0) {
        printf("eroare la transformarea der\n");
        PubKeyMac_free(mac_structura);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    bio = BIO_new_file(nume_mac, "wb");
    if (!bio) {
        printf("eroare la deschiderea fisierului: %s: ", nume_mac);
        ERR_print_errors_fp(stderr);
        OPENSSL_free(date_der);
        PubKeyMac_free(mac_structura);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    BIO_write(bio, date_der, lungime_der);
    BIO_free_all(bio);

    OPENSSL_free(date_der);
    PubKeyMac_free(mac_structura);

    EC_KEY_free(cheie_ec);
    EVP_PKEY_free(pkey);

    return 0;
}