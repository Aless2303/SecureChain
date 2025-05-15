#pragma warning(disable : 4996)
#include "decriptare_tranzactii.h"
#include "structuri_asn1.h"
#include "handshake_ecdh.h"
#include "tranzactii.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>



int decripteaza_fancyofb(unsigned char* date_criptate, int lungime_date_criptate,
    unsigned char* sym_key, unsigned char* iv,
    unsigned char** date_decriptate, int* lungime_date_decriptate) {


    //initializez aes context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Eroare la crearea contextului AES pentru decriptare\n");
        return 1;
    }

    //creare inv_IV
    unsigned char inv_iv[16];
    for (int i = 0; i < 16; i++) {
        inv_iv[i] = iv[15 - i]; // Reverse
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ofb(), NULL, sym_key, iv)) {
        printf("Eroare la initializarea AES-128-OFB pentru decriptare\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    *date_decriptate = (unsigned char*)OPENSSL_malloc(lungime_date_criptate);
    if (!*date_decriptate) {
        printf("Eroare la alocarea memoriei pentru date decriptate\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    unsigned char* date_intermediare = (unsigned char*)OPENSSL_malloc(lungime_date_criptate);
    if (!date_intermediare) {
        printf("Eroare la alocarea memoriei pentru date intermediare\n");
        OPENSSL_free(*date_decriptate);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    //XOR cu inv_iv pentru a reface modificarea FancyOFB
    for (int i = 0; i < lungime_date_criptate; i++) {
        date_intermediare[i] = date_criptate[i] ^ inv_iv[i % 16];
    }

    int lungime_temp = 0;
    *lungime_date_decriptate = 0;

    //decriptare cu OFB
    if (!EVP_DecryptUpdate(ctx, *date_decriptate, &lungime_temp, date_intermediare, lungime_date_criptate)) {
        printf("Eroare la decriptarea datelor\n");
        OPENSSL_free(date_intermediare);
        OPENSSL_free(*date_decriptate);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *lungime_date_decriptate += lungime_temp;

    //finalizez decriptarea
    if (!EVP_DecryptFinal_ex(ctx, *date_decriptate + *lungime_date_decriptate, &lungime_temp)) {
        printf("Eroare la finalizarea decriptarii\n");
        OPENSSL_free(date_intermediare);
        OPENSSL_free(*date_decriptate);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    *lungime_date_decriptate += lungime_temp;

    OPENSSL_free(date_intermediare);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int verifica_semnatura_rsa(const unsigned char* date, int lungime_date,
    const unsigned char* semnatura, int lungime_semnatura,
    const std::string& id_sender) {


    //obtin calea catre fisier cu cheia publica rsa
    char nume_fisier[256];
    sprintf(nume_fisier, "%s_pub.rsa", id_sender.c_str());

    BIO* bio = BIO_new_file(nume_fisier, "r");
    if (!bio) {
        printf("Eroare la deschiderea fisierului cu cheia publica RSA: %s\n",
            nume_fisier);
        return 0;
    }

    RSA* rsa_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    BIO_free_all(bio);

    if (!rsa_key) {
        printf("Eroare la incarcarea cheii publice RSA\n");
        return 0;
    }


    //convertesc rsa in evp_pkey
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_RSA(pkey, rsa_key)) {
        printf("Eroare la conversia RSA la EVP_PKEY\n");
        RSA_free(rsa_key);
        return 0;
    }


    //creez contextul pentru verificarea semnaturii
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("Eroare la crearea contextului pentru verificarea semnaturii\n");
        EVP_PKEY_free(pkey);
        RSA_free(rsa_key);
        return 0;
    }


    //initializez operatia de verificare
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        printf("Eroare la initializarea operatiei de verificare\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        RSA_free(rsa_key);
        return 0;
    }


    //verific datele
    if (EVP_DigestVerifyUpdate(md_ctx, date, lungime_date) != 1) {
        printf("Eroare la actualizarea operatiei de verificare\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        RSA_free(rsa_key);
        return 0;
    }


    //verific semnatura
    int rezultat = EVP_DigestVerifyFinal(md_ctx, semnatura, lungime_semnatura);

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    RSA_free(rsa_key);

    if (rezultat == 1) {
        printf("Semnatura RSA verificata cu succes\n");
        return 1;
    }
    else {
        printf("Verificarea semnaturii RSA a esuat\n");
        return 0;
    }
}

int decripteaza_tranzactie(const std::string& fisier_tranzactie,
    const std::string& id_sender,
    int sym_elements_id,
    unsigned char** date_decriptate, int* lungime_date_decriptate) {

    FILE* fp = fopen(fisier_tranzactie.c_str(), "rb");
    if (!fp) {
        fprintf(stderr, "Eroare la deschiderea fisierului %s pentru calcularea dimensiunii: %s\n",
            fisier_tranzactie.c_str(), strerror(errno));
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Eroare la mutarea cursorului la finalul fisierului: %s\n",
            strerror(errno));
        fclose(fp);
        return 1;
    }

    long lungime_fisier = ftell(fp);
    if (lungime_fisier < 0) {
        fprintf(stderr, "Eroare la obtinerea dimensiunii fisierului: %s\n",
            strerror(errno));
        fclose(fp);
        return 1;
    }
    if (lungime_fisier == 0) {
        fprintf(stderr, "Fisierul %s este gol\n", fisier_tranzactie.c_str());
        fclose(fp);
        return 1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Eroare la mutarea cursorului la inceputul fisierului: %s\n",
            strerror(errno));
        fclose(fp);
        return 1;
    }
    fclose(fp);

    printf("    incarca_elemente_simetrice: lungime fisier=%d\n", lungime_fisier);


    //citesc tranzactia
    BIO* bio = BIO_new_file(fisier_tranzactie.c_str(), "rb");
    if (!bio) {
        printf("Eroare la deschiderea fisierului de tranzactie: %s\n", fisier_tranzactie.c_str());
        return 1;
    }

    unsigned char* date_der = (unsigned char*)OPENSSL_malloc(lungime_fisier);
    if (!date_der) {
        printf("Eroare la alocarea memoriei pentru datele DER\n");
        BIO_free_all(bio);
        return 1;
    }

    int bytes_cititi = BIO_read(bio, date_der, lungime_fisier);
    if (bytes_cititi <= 0) {
        printf("Eroare la citirea fisierului de tranzactie\n");
        OPENSSL_free(date_der);
        BIO_free_all(bio);
        return 1;
    }
    BIO_free_all(bio);

    const unsigned char* p = date_der;
    Transaction* tranzactie = d2i_Transaction(NULL, &p, bytes_cititi);
    if (!tranzactie) {
        printf("Eroare la parsarea structurii de tranzactie\n");
        OPENSSL_free(date_der);
        return 1;
    }


    //extrag toate detaliile tranzactiei
    int transaction_id = ASN1_INTEGER_get(tranzactie->TransactionID);
    int sender_id = ASN1_INTEGER_get(tranzactie->SenderID);
    int receiver_id = ASN1_INTEGER_get(tranzactie->ReceiverID);
    int tranzactie_sym_id = ASN1_INTEGER_get(tranzactie->SymElementsID);

    printf("Decriptez tranzactia #%d de la %d la %d (SymElementsID: %d)\n",
        transaction_id, sender_id, receiver_id, tranzactie_sym_id);


    //verific daca corespund toate datele dins ymelements
    if (tranzactie_sym_id != sym_elements_id) {
        printf("ID-ul elementelor simetrice din tranzactie (%d) nu corespunde cu cel asteptat (%d)\n",
            tranzactie_sym_id, sym_elements_id);
        Transaction_free(tranzactie);
        OPENSSL_free(date_der);
        return 1;
    }

    Transaction* tranzactie_temp = Transaction_new();
    if (!tranzactie_temp) {
        printf("Eroare la crearea copiei temporare a tranzactiei\n");
        Transaction_free(tranzactie);
        OPENSSL_free(date_der);
        return 1;
    }


    //copiez tot integral fara semnatura
    ASN1_INTEGER_set(tranzactie_temp->TransactionID, transaction_id);
    ASN1_STRING_set(tranzactie_temp->Subject,
        ASN1_STRING_get0_data(tranzactie->Subject),
        ASN1_STRING_length(tranzactie->Subject));
    ASN1_INTEGER_set(tranzactie_temp->SenderID, sender_id);
    ASN1_INTEGER_set(tranzactie_temp->ReceiverID, receiver_id);
    ASN1_INTEGER_set(tranzactie_temp->SymElementsID, tranzactie_sym_id);
    ASN1_STRING_set(tranzactie_temp->EncryptedData,
        ASN1_STRING_get0_data(tranzactie->EncryptedData),
        ASN1_STRING_length(tranzactie->EncryptedData));
    //transactionsign las gol

    unsigned char* temp_der = NULL;
    int lungime_temp_der = i2d_Transaction(tranzactie_temp, &temp_der);
    if (lungime_temp_der <= 0) {
        printf("Eroare la encodarea temporara DER a tranzactiei\n");
        Transaction_free(tranzactie_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_der);
        return 1;
    }

    if (!verifica_semnatura_rsa(temp_der, lungime_temp_der,
        ASN1_STRING_get0_data(tranzactie->TransactionSign),
        ASN1_STRING_length(tranzactie->TransactionSign),
        id_sender)) {
        printf("Semnatura tranzactiei nu a putut fi verificata\n");
        OPENSSL_free(temp_der);
        Transaction_free(tranzactie_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_der);
        return 1;
    }


    //incarc toate el simetrice
    ElementeHandshake elemente;
    std::string sym_id_str = std::to_string(sym_elements_id);
    if (incarca_elemente_simetrice(sym_id_str, &elemente) != 0) {
        printf("Eroare la incarcarea elementelor simetrice\n");
        OPENSSL_free(temp_der);
        Transaction_free(tranzactie_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_der);
        return 1;
    }


    //decriptez cu fancyofb
    if (decripteaza_fancyofb((unsigned char*)ASN1_STRING_get0_data(tranzactie->EncryptedData),
        ASN1_STRING_length(tranzactie->EncryptedData),
        elemente.sym_key, elemente.sym_right + 16,
        date_decriptate, lungime_date_decriptate) != 0) {
        printf("Eroare la decriptarea datelor tranzactiei\n");
        OPENSSL_free(temp_der);
        Transaction_free(tranzactie_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_der);
        return 1;
    }

    OPENSSL_free(temp_der);
    Transaction_free(tranzactie_temp);
    Transaction_free(tranzactie);
    OPENSSL_free(date_der);

    return 0;
}