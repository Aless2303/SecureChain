#pragma warning(disable : 4996)
#include "tranzactii.h"
#include "structuri_asn1.h"
#include "criptare_fancyofb.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/asn1.h>
#include <openssl/decoder.h>
#include <stdio.h>
#include <string.h>

//decodificare base 64
int decodifica_base64(const unsigned char* input, int lungime_input,
    unsigned char** output, int* lungime_output) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(input, lungime_input);
    if (!b64 || !mem) {
        printf("Eroare la crearea BIO pentru decodificare Base64\n");
        if (b64) BIO_free(b64);
        if (mem) BIO_free(mem);
        return 1;
    }

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_push(b64, mem);

    //alocare memorie pentru datele decodificate
    *output = (unsigned char*)OPENSSL_malloc(lungime_input);
    if (!*output) {
        printf("Eroare la alocarea memoriei pentru decodificarea Base64\n");
        BIO_free_all(mem);
        return 1;
    }

    *lungime_output = BIO_read(mem, *output, lungime_input);
    if (*lungime_output <= 0) {
        printf("Eroare la decodificarea Base64\n");
        OPENSSL_free(*output);
        BIO_free_all(mem);
        return 1;
    }

    BIO_free_all(mem);
    return 0;
}

int incarca_elemente_simetrice(const std::string& sym_elements_id,
    ElementeHandshake* elemente) {

    // Noul format pentru numele fișierului
    char nume_fisier[256];
    sprintf(nume_fisier, "%s.sym", sym_elements_id.c_str());

    FILE* fp = fopen(nume_fisier, "rb");
    if (!fp) {
        fprintf(stderr, "Eroare la deschiderea fisierului %s pentru calcularea dimensiunii: %s\n",
            nume_fisier, strerror(errno));
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
        fprintf(stderr, "Fisierul %s este gol\n", nume_fisier);
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
    printf("    incarca_elemente_simetrice: fisier_elemente=%s\n", nume_fisier);

    //incarc base64 fisierul de el simetrice
    BIO* bio = BIO_new_file(nume_fisier, "rb");
    if (!bio) {
        printf("Eroare la deschiderea fisierului de elemente simetrice %s\n",
            nume_fisier);
        return 1;
    }

    unsigned char* date_base64 = (unsigned char*)OPENSSL_malloc(lungime_fisier + 1);
    if (!date_base64) {
        printf("Eroare la alocarea memoriei pentru citirea fisierului\n");
        BIO_free_all(bio);
        return 1;
    }

    printf("    incarca_elemente_simetrice: inainte de citirea din fisier_elemente=%s\n", nume_fisier);

    int bytes_cititi = BIO_read(bio, date_base64, lungime_fisier);
    if (bytes_cititi <= 0) {
        printf("Eroare la citirea fisierului de elemente simetrice\n");
        OPENSSL_free(date_base64);
        BIO_free_all(bio);
        return 1;
    }
    date_base64[bytes_cititi] = '\0';
    BIO_free_all(bio);
    printf("    incarca_elemente_simetrice: dupa citirea din fisier_elemente=%s\n", nume_fisier);

    //decodific base64
    unsigned char* date_der = NULL;
    int lungime_der = 0;

    if (decodifica_base64(date_base64, bytes_cititi, &date_der, &lungime_der) != 0) {
        printf("Eroare la decodificarea Base64\n");
        OPENSSL_free(date_base64);
        return 1;
    }
    OPENSSL_free(date_base64);

    //parsez datele DER
    const unsigned char* p = date_der;
    SymElements* sym_elements = d2i_SymElements(NULL, &p, lungime_der);
    if (!sym_elements) {
        printf("Eroare la parsarea structurii SymElements\n");
        OPENSSL_free(date_der);
        return 1;
    }

    //verific daca ID-ul este acelasi.
    long sym_id = ASN1_INTEGER_get(sym_elements->SymElementsID);
    if (sym_id != atoi(sym_elements_id.c_str())) {
        printf("ID-ul elementelor simetrice nu corespunde (asteptat: %d, gasit: %ld)\n",
            atoi(sym_elements_id.c_str()), sym_id);
        SymElements_free(sym_elements);
        OPENSSL_free(date_der);
        return 1;
    }

    //scot symkey-ul si iv-ul
    memcpy(elemente->sym_key, ASN1_STRING_get0_data(sym_elements->SymKey), 16);

    //----------------------------------------------------------------------------------------------------------------------------------------
    // We need to reconstruct SymRight and SymLeft based on available data
    // For simplicity, we'll just recover the IV which is stored in the SymElements
    // In a complete implementation, you'd recover all components as needed
    //----------------------------------------------------------------------------------------------------------------------------------------

    //copiez iv-ul (de lapozitia 16 incolo)
    memcpy(elemente->sym_right + 16, ASN1_STRING_get0_data(sym_elements->IV), 16);

    SymElements_free(sym_elements);
    OPENSSL_free(date_der);

    return 0;
}

//functie de semnare cu rsa
int semneaza_cu_rsa(const unsigned char* date, int lungime_date,
    const std::string& id_sursa,
    unsigned char** semnatura, int* lungime_semnatura) {

    //incarc cheia privata
    char nume_fisier[256];
    sprintf(nume_fisier, "%s_priv.rsa", id_sursa.c_str());

    BIO* bio = BIO_new_file(nume_fisier, "r");
    if (!bio) {
        printf("Eroare la deschiderea fisierului cu cheia privata RSA: %s\n",
            nume_fisier);
        return 1;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)"parolamea2303");
    BIO_free_all(bio);

    if (!pkey) {
        printf("Eroare la incarcarea cheii private RSA\n");
        return 1;
    }

    //creez contextul pentru semnatura
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("Eroare la crearea contextului pentru semnatura\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    //initializez operatia de semnare 
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        printf("Eroare la initializarea operatiei de semnare\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    //actualizez operatia de semnare
    if (EVP_DigestSignUpdate(md_ctx, date, lungime_date) != 1) {
        printf("Eroare la actualizarea operatia de semnare\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    size_t len = 0;
    if (EVP_DigestSignFinal(md_ctx, NULL, &len) != 1) {
        printf("Eroare la obtinerea lungimii semnaturii\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    *semnatura = (unsigned char*)OPENSSL_malloc(len);
    if (!*semnatura) {
        printf("Eroare la alocarea memoriei pentru semnaturii\n");
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    //finalizeze semnatura.
    if (EVP_DigestSignFinal(md_ctx, *semnatura, &len) != 1) {
        printf("Eroare la finalizarea semnaturii\n");
        OPENSSL_free(*semnatura);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    *lungime_semnatura = len;

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    return 0;
}

//creez tranzactia
int creeaza_tranzactie(int transaction_id, const std::string& subiect,
    int sender_id, int receiver_id, int sym_elements_id,
    const unsigned char* date, int lungime_date,
    const std::string& fisier_output) {

    printf("ma apuc sa incarc elmeentele simetrice, sym_elements_id = %d\n", sym_elements_id);

    //incarc elementele simetrice
    ElementeHandshake elemente;

    // Folosim noul format de denumire fișier
    std::string sym_id_str = std::to_string(sym_elements_id);
    if (incarca_elemente_simetrice(sym_id_str, &elemente) != 0) {
        printf("Eroare la incarcarea elementelor simetrice\n");
        return 1;
    }
    printf("am incarcat elementele simetrice.\n");

    //criptez datele cu fancyofb 
    unsigned char* date_criptate = NULL;
    int lungime_date_criptate = 0;
    if (cripteaza_fancyofb((unsigned char*)date, lungime_date, elemente.sym_key,
        elemente.sym_right + 16, &date_criptate, &lungime_date_criptate) != 0) {
        printf("Eroare la criptarea datelor\n");
        return 1;
    }

    //creez structura de tranzactie (asn1). 
    Transaction* tranzactie = Transaction_new();
    if (!tranzactie) {
        printf("Eroare la crearea structurii de tranzactie\n");
        OPENSSL_free(date_criptate);
        return 1;
    }

    //setez informatiile in sturctura de tranzactie.
    if (!ASN1_INTEGER_set(tranzactie->TransactionID, transaction_id) ||
        !ASN1_STRING_set(tranzactie->Subject, subiect.c_str(), subiect.length()) ||
        !ASN1_INTEGER_set(tranzactie->SenderID, sender_id) ||
        !ASN1_INTEGER_set(tranzactie->ReceiverID, receiver_id) ||
        !ASN1_INTEGER_set(tranzactie->SymElementsID, sym_elements_id) ||
        !ASN1_STRING_set(tranzactie->EncryptedData, date_criptate, lungime_date_criptate)) {

        printf("Eroare la setarea inf in structura de tranzactie\n");
        Transaction_free(tranzactie);
        OPENSSL_free(date_criptate);
        return 1;
    }

    //creez tranzactie DER codificata (fara semnatura)
    unsigned char* tranzactie_der_temp = NULL;
    int lungime_tranzactie_der_temp = i2d_Transaction(tranzactie, &tranzactie_der_temp);
    if (lungime_tranzactie_der_temp <= 0) {
        printf("Eroare la encodarea DER a tranzactia\n");
        Transaction_free(tranzactie);
        OPENSSL_free(date_criptate);
        return 1;
    }

    //semnez tranzactie
    unsigned char* semnatura = NULL;
    int lungime_semnatura = 0;

    // Folosim ID-ul expeditorului pentru a găsi cheia privată
    std::string id_sursa_str = std::to_string(sender_id);
    if (semneaza_cu_rsa(tranzactie_der_temp, lungime_tranzactie_der_temp,
        id_sursa_str, &semnatura, &lungime_semnatura) != 0) {
        printf("Eroare la semnarea tranzactiei\n");
        OPENSSL_free(tranzactie_der_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_criptate);
        return 1;
    }

    //adaug semnatura in tranzactie acum
    if (!ASN1_STRING_set(tranzactie->TransactionSign, semnatura, lungime_semnatura)) {
        printf("Eroare la adaugarea semnaturii in tranzactie\n");
        OPENSSL_free(semnatura);
        OPENSSL_free(tranzactie_der_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_criptate);
        return 1;
    }

    //creez codificarea der finala a tranzactiei
    unsigned char* tranzactie_der_final = NULL;
    int lungime_tranzactie_der_final = i2d_Transaction(tranzactie, &tranzactie_der_final);
    if (lungime_tranzactie_der_final <= 0) {
        printf("Eroare la encodarea DER finala a tranzactiei\n");
        OPENSSL_free(semnatura);
        OPENSSL_free(tranzactie_der_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_criptate);
        return 1;
    }

    // Noul format pentru numele fișierului: idSrc_idDest_idTranzactie.trx
    char nume_fisier[256];
    sprintf(nume_fisier, "%d_%d_%d.trx", sender_id, receiver_id, transaction_id);

    //salvez in fisier tranzactia creata
    BIO* bio = BIO_new_file(nume_fisier, "wb");
    if (!bio) {
        printf("Eroare la deschiderea fisierului pentru salvarea tranzactiei: %s\n",
            nume_fisier);
        OPENSSL_free(tranzactie_der_final);
        OPENSSL_free(semnatura);
        OPENSSL_free(tranzactie_der_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_criptate);
        return 1;
    }

    //salvez tranzactia in fisier
    if (BIO_write(bio, tranzactie_der_final, lungime_tranzactie_der_final) !=
        lungime_tranzactie_der_final) {
        printf("Eroare la scrierea tranzactiei in fisier\n");
        BIO_free_all(bio);
        OPENSSL_free(tranzactie_der_final);
        OPENSSL_free(semnatura);
        OPENSSL_free(tranzactie_der_temp);
        Transaction_free(tranzactie);
        OPENSSL_free(date_criptate);
        return 1;
    }

    BIO_free_all(bio);

    OPENSSL_free(tranzactie_der_final);
    OPENSSL_free(semnatura);
    OPENSSL_free(tranzactie_der_temp);
    Transaction_free(tranzactie);
    OPENSSL_free(date_criptate);

    printf("tranzactie creata si salvata cu succes in %s\n", nume_fisier);

    return 0;
}