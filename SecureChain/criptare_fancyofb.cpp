#include "criptare_fancyofb.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

int cripteaza_fancyofb(unsigned char* date, int lungime_date, unsigned char* sym_key, unsigned char* iv,
    unsigned char** date_criptate, int* lungime_date_criptate) {

    //initializez AES
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Eroare la crearea contextului AES\n");
        return 1;
    }

    //creez inv_IV conform cerintei.
    unsigned char inv_iv[16];
    for (int i = 0; i < 16; i++) {
        inv_iv[i] = iv[15 - i]; //inversez ordinea octetilor
    }

    //initializez criptarea cu AES-256-OFB
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, sym_key, iv)) {
        printf("Eroare la initializarea AES-256-OFB\n");
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    //aloc memorie ptr datele criptate
    *date_criptate = (unsigned char*)OPENSSL_malloc(lungime_date);
    if (!*date_criptate) {
        printf("Eroare la alocarea memoriei pentru date criptate\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int lungime_temp = 0;
    *lungime_date_criptate = 0;

    //criptez datele folosind ofb standard
    if (!EVP_EncryptUpdate(ctx, *date_criptate, &lungime_temp, date, lungime_date)) {
        printf("Eroare la criptarea datelor\n");
        ERR_print_errors_fp(stderr);
        OPENSSL_free(*date_criptate);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *lungime_date_criptate += lungime_temp;


    //finalizez criptarea
    if (!EVP_EncryptFinal_ex(ctx, *date_criptate + *lungime_date_criptate, &lungime_temp)) {
        printf("Eroare la finalizarea criptarii\n");
        ERR_print_errors_fp(stderr);
        OPENSSL_free(*date_criptate);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *lungime_date_criptate += lungime_temp;


    //aplic modificarea fancyofb
    //xor cu inv_IV pentru fiecare octet in parte
    for (int i = 0; i < *lungime_date_criptate; i++) {
        (*date_criptate)[i] ^= inv_iv[i % 16]; // repet inv_IV ciclic.
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}