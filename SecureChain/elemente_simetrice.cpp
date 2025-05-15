#pragma warning(disable : 4996)
#include "elemente_simetrice.h"
#include "structuri_asn1.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <stdio.h>
#include <string.h>

//fct pentru codificarea base64
int codifica_base64(unsigned char* input, int lungime, unsigned char** output, int* lungime_output) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem) {
        printf("Eroare la crearea BIO pentru Base64\n");
        BIO_free_all(b64);
        BIO_free_all(mem);
        return 1;
    }

    b64 = BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); //fara newline

    if (BIO_write(b64, input, lungime) <= 0 || BIO_flush(b64) <= 0) {
        printf("Eroare la codificarea Base64\n");
        BIO_free_all(b64);
        return 1;
    }

    char* buffer;
    *lungime_output = BIO_get_mem_data(mem, &buffer);
    *output = (unsigned char*)OPENSSL_malloc(*lungime_output + 1);
    if (!*output) {
        printf("Eroare la alocarea memoriei pentru Base64\n");
        BIO_free_all(b64);
        return 1;
    }

    memcpy(*output, buffer, *lungime_output);
    (*output)[*lungime_output] = '\0';
    BIO_free_all(b64);
    return 0;
}

int salveaza_elemente_simetrice(int sym_elements_id, ElementeHandshake* elemente, const std::string& fisier_output) {
    char nume_fisier[256];
    sprintf(nume_fisier, "%d.sym", sym_elements_id);

    //creez structura syselements
    SymElements* sym_elements = SymElements_new();
    if (!sym_elements) {
        printf("Eroare la crearea structurii SymElements\n");
        return 1;
    }

    //seteaza symelementsID
    if (!ASN1_INTEGER_set(sym_elements->SymElementsID, sym_elements_id)) {
        printf("Eroare la setarea SymElementsID\n");
        SymElements_free(sym_elements);
        return 1;
    }

    //setez symkey (16 octeti pentru AES-128)
    if (!ASN1_OCTET_STRING_set(sym_elements->SymKey, elemente->sym_key, 16)) {
        printf("Eroare la setarea SymKey\n");
        SymElements_free(sym_elements);
        return 1;
    }

    //extrag iv-ul (primii 16 octeti din symright din octetii neutilizati)
    unsigned char iv[16];
    memcpy(iv, elemente->sym_right + 16, 16); //incepe de la 16

    //setez iv
    if (!ASN1_OCTET_STRING_set(sym_elements->IV, iv, 16)) {
        printf("Eroare la setarea IV\n");
        SymElements_free(sym_elements);
        return 1;
    }

    //codific in der
    unsigned char* date_der = nullptr;
    int lungime_der = i2d_SymElements(sym_elements, &date_der);
    if (lungime_der <= 0) {
        printf("Eroare la codificarea DER\n");
        SymElements_free(sym_elements);
        return 1;
    }

    //codific in base64
    unsigned char* date_base64 = nullptr;
    int lungime_base64 = 0;
    if (codifica_base64(date_der, lungime_der, &date_base64, &lungime_base64) != 0) {
        printf("Eroare la codificarea Base64\n");
        OPENSSL_free(date_der);
        SymElements_free(sym_elements);
        return 1;
    }

    //salvez in fisier
    BIO* bio = BIO_new_file(nume_fisier, "w");
    if (!bio) {
        printf("Eroare la deschiderea fișierului %s\n", nume_fisier);
        ERR_print_errors_fp(stderr);
        OPENSSL_free(date_der);
        OPENSSL_free(date_base64);
        SymElements_free(sym_elements);
        return 1;
    }

    BIO_write(bio, date_base64, lungime_base64);
    BIO_free_all(bio);

    OPENSSL_free(date_der);
    OPENSSL_free(date_base64);
    SymElements_free(sym_elements);

    return 0;
}