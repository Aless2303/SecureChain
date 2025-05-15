#pragma warning(disable : 4996)
#include "generare_rsa.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "structuri_asn1.h"
#include <stdio.h>
#include <ctime>


//calcularea diferentei de timp rsa
int calculeaza_diferenta_timp_rsa(unsigned char* diferenta, size_t* lungime_diferenta)
{
    time_t acum = time(nullptr);
    struct tm data_acum = *gmtime(&acum);

    struct tm data_tinta = { 0 };
    data_tinta.tm_year = 2005 - 1900;
    data_tinta.tm_mon = 4;
    data_tinta.tm_mday = 5;
    data_tinta.tm_hour = 5;
    data_tinta.tm_sec = 5;

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

int genereaza_salveaza_chei_rsa(const std::string& nume_entitate,
    const std::string& fisier_cheie_privata_rsa,
    const std::string& fisier_cheie_publica_rsa) {

    int id_entitate = atoi(nume_entitate.c_str());

    //formez numele de fisiere
    char nume_cheie_privata_rsa[256], nume_cheie_publica_rsa[256], nume_mac_rsa[256];
    sprintf(nume_cheie_privata_rsa, "%d_priv.rsa", id_entitate);
    sprintf(nume_cheie_publica_rsa, "%d_pub.rsa", id_entitate);
    sprintf(nume_mac_rsa, "%d_rsa.mac", id_entitate);

    //generez RSA cu 3072 de biti
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY* pkey = NULL;

    if (!ctx) {
        printf("Eroare la crearea contextului pentru RSA\n");
        return 1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Eroare la initializarea generatorului de chei RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    //setez lungimea de 3072 de biti
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) {
        printf("Eroare la setarea lungimii cheii RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    //generez key pair-ul
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("Eroare la generarea cheii RSA\n");
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }


    //obtin rsa din evp_pkey
    RSA* rsa_key = EVP_PKEY_get1_RSA(pkey);
    if (!rsa_key) {
        printf("Eroare la extragerea cheii RSA din EVP_PKEY\n");
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    //salvez cheia privata in fisier in format PKCS1
    BIO* bio_private = BIO_new_file(nume_cheie_privata_rsa, "w");
    if (!bio_private) {
        printf("Eroare la deschiderea fisierului pentru cheia privata RSA: %s\n",
            nume_cheie_privata_rsa);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    //salvez cheia privata in format PKCS1
    if (!PEM_write_bio_RSAPrivateKey(bio_private, rsa_key, EVP_aes_256_cbc(),
        (unsigned char*)"parolamea2303",
        strlen("parolamea2303"), NULL, NULL)) {
        printf("Eroare la salvarea cheii private RSA\n");
        BIO_free_all(bio_private);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    BIO_free_all(bio_private);

    //salvez cheia publica in fisier in format PKCS1
    BIO* bio_public = BIO_new_file(nume_cheie_publica_rsa, "w");
    if (!bio_public) {
        printf("Eroare la deschiderea fisierului pentru cheia publica RSA: %s\n",
            nume_cheie_publica_rsa);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    //salvez cheia publica in format PKCS1
    if (!PEM_write_bio_RSAPublicKey(bio_public, rsa_key)) {
        printf("Eroare la salvarea cheii publice RSA\n");
        BIO_free_all(bio_public);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    BIO_free_all(bio_public);



    //obtin forma der a cheii publice
    unsigned char* cheie_publica_der = nullptr;
    int lungime_cheie_publica = i2d_PUBKEY(pkey, &cheie_publica_der);
    if (lungime_cheie_publica <= 0) {
        printf("Eroare la convertirea cheii publice RSA in format DER\n");
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    unsigned char diferenta_timp[32];
    size_t lungime_diferenta;
    if (calculeaza_diferenta_timp_rsa(diferenta_timp, &lungime_diferenta) != 0) {
        printf("Eroare la calcularea diferentei de timp\n");
        OPENSSL_free(cheie_publica_der);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }


    //generez cheia gmac 16 bytes pentru aes-128
    unsigned char cheie_mac[16];
    const EVP_MD* digest = EVP_sha3_256();
    if (!digest) {
        printf("Eroare la obtinerea SHA3-256\n");
        OPENSSL_free(cheie_publica_der);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    if (PKCS5_PBKDF2_HMAC((const char*)diferenta_timp, lungime_diferenta,
        NULL, 0, 10000, digest, sizeof(cheie_mac), cheie_mac) != 1) {
        printf("Eroare la generarea cheii MAC cu PBKDF2\n");
        OPENSSL_free(cheie_publica_der);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    unsigned char valoare_mac[16];
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
        printf("Eroare la generarea GMAC pentru RSA\n");
        ERR_print_errors_fp(stderr);
        EVP_MAC_CTX_free(context_mac);
        EVP_MAC_free(mac);
        OPENSSL_free(cheie_publica_der);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    EVP_MAC_CTX_free(context_mac);
    EVP_MAC_free(mac);
    OPENSSL_free(cheie_publica_der);

    //salvez gmac in format der
    PubKeyMac* mac_structura = PubKeyMac_new();
    if (!mac_structura) {
        printf("Eroare la crearea structurii PubKeyMac pentru RSA\n");
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    ASN1_STRING_set(mac_structura->PubKeyName, nume_entitate.c_str(), nume_entitate.length());
    ASN1_STRING_set(mac_structura->MACKey, cheie_mac, sizeof(cheie_mac));
    ASN1_STRING_set(mac_structura->MACValue, valoare_mac, lungime_valoare_mac);

    unsigned char* date_der = nullptr;
    int lungime_der = i2d_PubKeyMac(mac_structura, &date_der);
    if (lungime_der <= 0) {
        printf("Eroare la transformarea MAC RSA in format DER\n");
        PubKeyMac_free(mac_structura);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }

    BIO* bio_mac = BIO_new_file(nume_mac_rsa, "wb");
    if (!bio_mac) {
        printf("Eroare la deschiderea fisierului pentru MAC RSA: %s\n", nume_mac_rsa);
        OPENSSL_free(date_der);
        PubKeyMac_free(mac_structura);
        RSA_free(rsa_key);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    BIO_write(bio_mac, date_der, lungime_der);
    BIO_free_all(bio_mac);

    OPENSSL_free(date_der);
    PubKeyMac_free(mac_structura);

    printf("Chei RSA generate cu succes pentru %s\n", nume_entitate.c_str());

    RSA_free(rsa_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}