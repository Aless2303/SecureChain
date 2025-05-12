#pragma warning(disable : 4996)
#include "generare_rsa.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

int genereaza_salveaza_chei_rsa(const std::string& nume_entitate,
    const std::string& fisier_cheie_privata_rsa,
    const std::string& fisier_cheie_publica_rsa) {


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


    //salvez cheia privata in fisier
    BIO* bio_private = BIO_new_file(fisier_cheie_privata_rsa.c_str(), "w");
    if (!bio_private) {
        printf("Eroare la deschiderea fisierului pentru cheia privata RSA: %s\n",
            fisier_cheie_privata_rsa.c_str());
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }


    //salvez cheia privata in format pem 
    if (!PEM_write_bio_PrivateKey(bio_private, pkey, EVP_aes_256_cbc(),
        (unsigned char*)"parolamea2303",
        strlen("parolamea2303"), NULL, NULL)) {
        printf("Eroare la salvarea cheii private RSA\n");
        BIO_free_all(bio_private);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    BIO_free_all(bio_private);


    //salvez cheia publica in fisier
    BIO* bio_public = BIO_new_file(fisier_cheie_publica_rsa.c_str(), "w");
    if (!bio_public) {
        printf("Eroare la deschiderea fisierului pentru cheia publica RSA: %s\n",
            fisier_cheie_publica_rsa.c_str());
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    //salvez cheia publica in format pem
    if (!PEM_write_bio_PUBKEY(bio_public, pkey)) {
        printf("Eroare la salvarea cheii publice RSA\n");
        BIO_free_all(bio_public);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    BIO_free_all(bio_public);

    printf("Chei RSA generate cu succes pentru %s\n", nume_entitate.c_str());

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}