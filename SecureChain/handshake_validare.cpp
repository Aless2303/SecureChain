#pragma warning(disable : 4996)
#include "handshake_validare.h"
#include "structuri_asn1.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <string.h>

//fct pentru incarcarea unei chei private din fisierul pem
EVP_PKEY* incarca_cheie_privata(const std::string& fisier_cheie_privata, const char* parola) {
    BIO* bio = BIO_new_file(fisier_cheie_privata.c_str(), "r");
    if (!bio) {
        printf("eroare la deschiderea fisier %s: ", fisier_cheie_privata.c_str());
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    EVP_PKEY* cheie_privata = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, (void*)parola);
    if (!cheie_privata) {
        printf("eroare la citirea cheii private: ");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        return nullptr;
    }

    BIO_free_all(bio);
    return cheie_privata;
}

//fct pentr incarcarea unei chei publice din fisierul pem
EVP_PKEY* incarca_cheie_publica(const std::string& fisier_cheie_publica) {
    BIO* bio = BIO_new_file(fisier_cheie_publica.c_str(), "r");
    if (!bio) {
        printf("eroare la deschiderea fisier %s: ", fisier_cheie_publica.c_str());
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    EVP_PKEY* cheie_publica = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!cheie_publica) {
        printf("eroare la citirea cheii publice: ");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        return nullptr;
    }

    BIO_free_all(bio);
    return cheie_publica;
}


//fct pentru extragerea mac-ului din fisierul der.
int extrage_mac_din_fisier(const std::string& fisier_mac, unsigned char** cheie_mac,
    unsigned char** valoare_mac, size_t* lungime_cheie, size_t* lungime_valoare) {
    FILE* f = fopen(fisier_mac.c_str(), "rb");
    if (!f) {
        printf("eroare la deschiderea fisierului MAC %s\n", fisier_mac.c_str());
        return 1;
    }

    // lungimea fisier
    fseek(f, 0, SEEK_END);
    long lungime_fisier = ftell(f);
    rewind(f);

    //citesc din fisierul der.
    unsigned char* date_der = (unsigned char*)OPENSSL_malloc(lungime_fisier);
    if (!date_der) {
        printf("eroare la alocarea memoriei pentru datele DER\n");
        fclose(f);
        return 1;
    }

    if (fread(date_der, 1, lungime_fisier, f) != lungime_fisier) {
        printf("eroare la citirea datelor DER din fisier\n");
        OPENSSL_free(date_der);
        fclose(f);
        return 1;
    }

    fclose(f);


    //parsez datele der pentru a obtine structura facuta cu Asn1. PubKeyMac
    const unsigned char* p = date_der;
    PubKeyMac* mac_structura = d2i_PubKeyMac(nullptr, &p, lungime_fisier);
    if (!mac_structura) {
        printf("eroare la parsarea structurii MAC\n");
        OPENSSL_free(date_der);
        return 1;
    }


    //extrag cheia mac si valoarea mac
    *lungime_cheie = ASN1_STRING_length(mac_structura->MACKey);
    *lungime_valoare = ASN1_STRING_length(mac_structura->MACValue);

    *cheie_mac = (unsigned char*)OPENSSL_malloc(*lungime_cheie);
    *valoare_mac = (unsigned char*)OPENSSL_malloc(*lungime_valoare);

    if (!(*cheie_mac) || !(*valoare_mac)) {
        printf("eroare la alocarea memoriei pentru cheia/valoarea MAC\n");
        if (*cheie_mac) OPENSSL_free(*cheie_mac);
        if (*valoare_mac) OPENSSL_free(*valoare_mac);
        PubKeyMac_free(mac_structura);
        OPENSSL_free(date_der);
        return 1;
    }

    memcpy(*cheie_mac, ASN1_STRING_get0_data(mac_structura->MACKey), *lungime_cheie);
    memcpy(*valoare_mac, ASN1_STRING_get0_data(mac_structura->MACValue), *lungime_valoare);

    PubKeyMac_free(mac_structura);
    OPENSSL_free(date_der);

    return 0;
}


//fct pentru obtinerea formatului der si al cheii publice
unsigned char* obtine_cheie_publica_der(EVP_PKEY* cheie_publica, int* lungime_der) {
    unsigned char* cheie_publica_der = nullptr;
    *lungime_der = i2d_PUBKEY(cheie_publica, &cheie_publica_der);

    if (*lungime_der <= 0) {
        printf("eroare la convertirea cheii publice in format DER\n");
        return nullptr;
    }

    return cheie_publica_der;
}


//fct pentru recalcularea gmac pentru verificarea autentificatii
int recalculeaza_gmac(unsigned char* cheie_mac, size_t lungime_cheie_mac,
    unsigned char* cheie_publica_der, int lungime_der,
    unsigned char* valoare_mac_calculata, size_t* lungime_valoare_mac_calculata) {

    printf("    in recalculeaza_gmac:   Recalculez GMAC cu o cheie de %zu bytes\n", lungime_cheie_mac);

    //afisez cativa bytes din cheie pentru debug
    printf("    in recalculeaza_gmac:   Cheie MAC (primii 8 bytes): ");
    for (int i = 0; i < 8 && i < lungime_cheie_mac; i++) {
        printf("%02x", cheie_mac[i]);
    }
    printf("\n");


    // Vector de inițializare pentru GMAC (12 zerouri)
    unsigned char iv[12] = { 0 };  // IV umplut cu zerouri

    // param pentru GMAC, cu IV adăugat explicit
    OSSL_PARAM parametri[3];
    parametri[0] = OSSL_PARAM_construct_utf8_string("cipher", (char*)"AES-256-GCM", 0);
    // Adăugăm parametrul IV folosind denumirea exactă din OpenSSL
    parametri[1] = OSSL_PARAM_construct_octet_string("iv", iv, sizeof(iv));
    parametri[2] = OSSL_PARAM_construct_end();

    // creez contextul MAC
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "GMAC", NULL);
    EVP_MAC_CTX* context_mac = EVP_MAC_CTX_new(mac);

    if (!context_mac) {
        printf("eroare la crearea contextului GMAC\n");
        EVP_MAC_free(mac);
        return 1;
    }

    // initializez MAC-ul
    if (!EVP_MAC_init(context_mac, cheie_mac, lungime_cheie_mac, parametri)) {
        printf("eroare la initializarea GMAC: ");
        ERR_print_errors_fp(stderr);  // Afișăm eroarea exactă
        EVP_MAC_CTX_free(context_mac);
        EVP_MAC_free(mac);
        return 1;
    }

    // actualizez MAC-ul cu datele cheii publice
    if (!EVP_MAC_update(context_mac, cheie_publica_der, lungime_der)) {
        printf("eroare la actualizarea GMAC\n");
        EVP_MAC_CTX_free(context_mac);
        EVP_MAC_free(mac);
        return 1;
    }

    //finalizez calculul MAC-ului
    if (!EVP_MAC_final(context_mac, valoare_mac_calculata, lungime_valoare_mac_calculata, 16)) {
        printf("eroare la finalizarea GMAC\n");
        EVP_MAC_CTX_free(context_mac);
        EVP_MAC_free(mac);
        return 1;
    }

    printf("    in recalculeaza_gmac:   GMAC calculat: ");
    for (size_t i = 0; i < *lungime_valoare_mac_calculata; i++) {
        printf("%02x", valoare_mac_calculata[i]);
    }
    printf("\n");

    EVP_MAC_CTX_free(context_mac);
    EVP_MAC_free(mac);

    return 0;
}



//fct pentru verificarea autenticitatii unei chei publice cu ajutorul  mac-ului
int verifica_autenticitate_cheie_publica(const std::string& nume_entitate,
    const std::string& fisier_cheie_publica,
    const std::string& fisier_mac) {
    // incarc cheia publica
    EVP_PKEY* cheie_publica = incarca_cheie_publica(fisier_cheie_publica);
    if (!cheie_publica) {
        return 0;
    }
    printf("am incarcat cheia publica\n");

    //convertesc cheia in format der
    int lungime_der;
    unsigned char* cheie_publica_der = obtine_cheie_publica_der(cheie_publica, &lungime_der);
    if (!cheie_publica_der) {
        EVP_PKEY_free(cheie_publica);
        return 0;
    }

    printf("am incarcat convertit cheia in format der\n");

    //extrafg mac-ul din fisire
    unsigned char* cheie_mac = nullptr;
    unsigned char* valoare_mac = nullptr;
    size_t lungime_cheie_mac, lungime_valoare_mac;

    if (extrage_mac_din_fisier(fisier_mac, &cheie_mac, &valoare_mac, &lungime_cheie_mac, &lungime_valoare_mac) != 0) {
        OPENSSL_free(cheie_publica_der);
        EVP_PKEY_free(cheie_publica);
        return 0;
    }
    printf("Valoare MAC din fisier: ");
    for (size_t i = 0; i < lungime_valoare_mac; i++) {
        printf("%02x", valoare_mac[i]);
    }
    printf("\n");

    //recalculez gmac pentru verificare
    unsigned char valoare_mac_calculata[16];
    size_t lungime_valoare_mac_calculata = sizeof(valoare_mac_calculata);

    if (recalculeaza_gmac(cheie_mac, lungime_cheie_mac, cheie_publica_der, lungime_der,
        valoare_mac_calculata, &lungime_valoare_mac_calculata) != 0) {
        OPENSSL_free(cheie_mac);
        OPENSSL_free(valoare_mac);
        OPENSSL_free(cheie_publica_der);
        EVP_PKEY_free(cheie_publica);
        return 0;
    }
    printf("am recalculat gmac pentru verificare\n");

    int rezultat = 0;
    if (lungime_valoare_mac_calculata == lungime_valoare_mac &&
        memcmp(valoare_mac_calculata, valoare_mac, lungime_valoare_mac_calculata) == 0) {
        rezultat = 1; // MAC-urile coincid, cheia este buna

        printf("mac-urile coincid\n");
    }
    else {
        printf("mac-urile nu coincid\n");
    }

    OPENSSL_free(cheie_mac);
    OPENSSL_free(valoare_mac);
    OPENSSL_free(cheie_publica_der);
    EVP_PKEY_free(cheie_publica);

    return rezultat;
}