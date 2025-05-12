#pragma warning(disable : 4996)
#include "creare_salvare_chei.h"
#include "structuri_asn1.h"
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include<openssl/hmac.h>
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
    BIO* bio = nullptr; // Schimbat de la FILE* la BIO*

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

    // Schimbat la utilizarea BIO pentru scrierea cheii private
    bio = BIO_new_file(fisier_cheie_privata.c_str(), "w");
    if (!bio) {
        printf("eroare la deschiderea fisierului %s: ", fisier_cheie_privata.c_str());
        ERR_print_errors_fp(stderr); // Afisează erorile OpenSSL
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (!PEM_write_bio_PrivateKey(bio, pkey, EVP_aes_256_cbc(), (unsigned char*)"parolamea2303", strlen("parolamea2303"), nullptr, nullptr)) {
        printf("eroare la salvarea cheii private: ");
        ERR_print_errors_fp(stderr); // Afisează erorile OpenSSL
        BIO_free_all(bio);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    BIO_free_all(bio); // Eliberează resursa BIO

    // Schimbat la utilizarea BIO pentru scrierea cheii publice
    bio = BIO_new_file(fisier_cheie_publica.c_str(), "w");
    if (!bio) {
        printf("eroare la deschiderea fisierului %s: ", fisier_cheie_publica.c_str());
        ERR_print_errors_fp(stderr); // Afisează erorile OpenSSL
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey))
    {
        printf("eroare la salvarea cheii publice: ");
        ERR_print_errors_fp(stderr); // Afisează erorile OpenSSL
        BIO_free_all(bio);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    BIO_free_all(bio); // Eliberează resursa BIO

    //calculez diferenta de timp si generez cheia pentru GMAC.
    //gmac -> varianta a algoritmului GCM folosit pentru autentificarea mesajelor. 
    //genereaza un cod de autentificare (mac) pentru a verifica autenticitatea si integritatea datelor.
    //necesita o cheie criptografica pentru a functiona. (o vom face cu ajutorul diferentei de timp)
    unsigned char diferenta_timp[32];
    size_t lungime_diferenta;
    if (calculeaza_diferenta_timp(diferenta_timp, &lungime_diferenta) != 0) {
        printf("eroare la calcularea diferentei de timp\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }


    //generez cheia pentru gmac cu pbkdf2 si sha256. 
    //PBKDF2 este un algoritm de derivare a cheilor ce transforma o parola sau un sir intr-o cheie cripgorafica
    //sha256 algoritm de hash din familia sha2 folosit in pbkdf2 pentru a crea has-uri iterative.
    //pbkdf2 combina:
        //un sir de intrare (diferenta de timp)
        //un salt (un random pentru a preveni atacurile)
        //un nr de iteratii
        //un algoritm de hash (sha256)
    unsigned char cheie_mac[32]; //cheia pentru gmac;
    const EVP_MD* digest = EVP_sha3_256(); //sha3-256 ca algorim de hash.
    if (!digest) {
        printf("eroare la obtinerea sha3-256\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }


    //folosesc PKCS5_PBKDF2_HMAC pentru a deriva cheia
    if (PKCS5_PBKDF2_HMAC((const char*)diferenta_timp, lungime_diferenta,
        NULL, 0, //fara salt
        10000, //cate iteratii sa aibe
        digest, //sha3-256
        sizeof(cheie_mac), //lungimea cheii adica 32 bytes
        cheie_mac) != 1) { //cheia derivata.
        printf("eroare la generarea cheii MAC cu pbkdf2\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }

    //generez GMAC pentru cheia publica 
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
    unsigned char valoare_mac[16]; //16 bytes pentru GMAC.
    EVP_MAC* mac = EVP_MAC_fetch(NULL, "GMAC", NULL); //am ales gmac.
    EVP_MAC_CTX* context_mac = EVP_MAC_CTX_new(mac); //am creat contextul pentru GMAC.


    unsigned char iv[12] = { 0 };   
    
    
    OSSL_PARAM parametri[3];
    parametri[0] = OSSL_PARAM_construct_utf8_string("cipher", (char*)"AES-256-GCM", 0);
    parametri[1] = OSSL_PARAM_construct_octet_string("iv", iv, sizeof(iv)); // adaug iv u
    parametri[2] = OSSL_PARAM_construct_end();
    size_t lungime_valoare_mac = sizeof(valoare_mac);


    if (!context_mac ||
        !EVP_MAC_init(context_mac, cheie_mac, sizeof(cheie_mac), parametri) || // initializez gmac
        !EVP_MAC_update(context_mac, cheie_publica_der, lungime_cheie_publica) || // adaug cheia publica
        !EVP_MAC_final(context_mac, valoare_mac, &lungime_valoare_mac, sizeof(valoare_mac))) { //generez gmac
        printf("Eroare la generarea GMAC\n");
        ERR_print_errors_fp(stderr); // adaug pentru afisarea erorilor la debug.
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
    //vom folosi structura creata PubKeyMac.
    PubKeyMac* mac_structura = PubKeyMac_new();
    if (!mac_structura) {
        printf("eroare la crearea structurii PubKeyMac\n");
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    //acum pun valorile anterioare in structura mac_structura.
    ASN1_STRING_set(mac_structura->PubKeyName, nume_entitate.c_str(), nume_entitate.length()); //setez numele entitatii
    ASN1_STRING_set(mac_structura->MACKey, cheie_mac, sizeof(cheie_mac)); // cheia mac
    ASN1_STRING_set(mac_structura->MACValue, valoare_mac, lungime_valoare_mac); // val gmac.

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

    // Schimbat la utilizarea BIO pentru scrierea GMAC
    bio = BIO_new_file(fisier_mac.c_str(), "wb"); // Deschid fisierul in mod binar
    if (!bio) {
        printf("eroare la deschiderea fisierului: %s: ", fisier_mac.c_str());
        ERR_print_errors_fp(stderr); // Afisează erorile OpenSSL
        OPENSSL_free(date_der);
        PubKeyMac_free(mac_structura);
        EC_KEY_free(cheie_ec);
        EVP_PKEY_free(pkey);
        return 1;
    }
    BIO_write(bio, date_der, lungime_der); // Scriere date DER
    BIO_free_all(bio); // Eliberează resursa BIO

    OPENSSL_free(date_der);
    PubKeyMac_free(mac_structura);

    EC_KEY_free(cheie_ec);
    EVP_PKEY_free(pkey);

    return 0;
}