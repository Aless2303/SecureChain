#pragma warning(disable : 4996)
#include "handshake_ecdh.h"
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <string.h>



//extrag coordonatele x,y din pct comun calculat cu ajutorul ECDH. 
int extrage_coordonate_punct(EC_KEY* cheie_privata, EC_KEY* cheie_publica_peer,
    unsigned char* x, unsigned char* y) {
    //obtin grupul si curba eliptica.
    const EC_GROUP* grup = EC_KEY_get0_group(cheie_privata);
    const EC_POINT* punct_public_peer = EC_KEY_get0_public_key(cheie_publica_peer);


    //aloc un nou pct pentru rezultatul operatiei ECDH
    EC_POINT* punct_comun = EC_POINT_new(grup);
    if (!punct_comun) {
        printf("eroare la crearea punctului comun\n");
        return 1;
    }

    //calculez un pct comun : cheie_privata * punct_public
    if (!EC_POINT_mul(grup, punct_comun, NULL, punct_public_peer,
        EC_KEY_get0_private_key(cheie_privata), NULL)) {
        printf("eroare la calcularea punctului comun\n");
        EC_POINT_free(punct_comun);
        return 1;
    }

    //extrag coord x si y
    BIGNUM* x_bn = BN_new();
    BIGNUM* y_bn = BN_new();
    if (!x_bn || !y_bn) {
        printf("eroare la alocarea BIGNUM\n");
        if (x_bn) BN_free(x_bn);
        if (y_bn) BN_free(y_bn);
        EC_POINT_free(punct_comun);
        return 1;
    }

    //obtinem coordonatele afine ale pct
    if (!EC_POINT_get_affine_coordinates(grup, punct_comun, x_bn, y_bn, NULL)) {
        printf("eroare la obtinerea coordonatelor punctului\n");
        BN_free(x_bn);
        BN_free(y_bn);
        EC_POINT_free(punct_comun);
        return 1;
    }

    //convertesc coord in format binar (32 octeti fiecare)
    memset(x, 0, 32);
    memset(y, 0, 32);


    BN_bn2bin(x_bn, x + (32 - BN_num_bytes(x_bn)));
    BN_bn2bin(y_bn, y + (32 - BN_num_bytes(y_bn)));


    BN_free(x_bn);
    BN_free(y_bn);
    EC_POINT_free(punct_comun);

    return 0;
}



//fct pentru realizarea handshake-ului ECDH si derivarea cheii simetrice
int handshake_ecdh_derivare_chei(EVP_PKEY* cheie_privata, EVP_PKEY* cheie_publica_peer,
    ElementeHandshake* elemente) {
    //extrag EC_KEY din EVP_PKEY
    EC_KEY* ec_cheie_privata = EVP_PKEY_get1_EC_KEY(cheie_privata);
    EC_KEY* ec_cheie_publica = EVP_PKEY_get1_EC_KEY(cheie_publica_peer);

    if (!ec_cheie_privata || !ec_cheie_publica) {
        printf("eroare la extragerea cheilor EC\n");
        if (ec_cheie_privata) EC_KEY_free(ec_cheie_privata);
        if (ec_cheie_publica) EC_KEY_free(ec_cheie_publica);
        return 1;
    }

    //extrag coord x si y din pct comun
    unsigned char x[32], y[32];
    if (extrage_coordonate_punct(ec_cheie_privata, ec_cheie_publica, x, y) != 0) {
        EC_KEY_free(ec_cheie_privata);
        EC_KEY_free(ec_cheie_publica);
        return 1;
    }


    EC_KEY_free(ec_cheie_privata);
    EC_KEY_free(ec_cheie_publica);


    //procesul de derivare a cheilor:
    unsigned char x_hash[32];
    SHA256(x, 32, x_hash);

    //impart rezultatul in 2 elemente de 16 octeti
    unsigned char prima_jumatate[16];
    unsigned char a_doua_jumatate[16];

    memcpy(prima_jumatate, x_hash, 16);
    memcpy(a_doua_jumatate, x_hash + 16, 16);

    //calculez sym_left facand xor.
    for (int i = 0; i < 16; i++) {
        elemente->sym_left[i] = prima_jumatate[i] ^ a_doua_jumatate[i];
    }


    //folosesc y ca input pentru PBKDF2 cu sha-384 fara salt.
    if (PKCS5_PBKDF2_HMAC((const char*)y, 32, NULL, 0, 1000, EVP_sha384(), 48, elemente->sym_right) != 1) {
        printf("eroare la calcularea SymRight folosind PBKDF2\n");
        return 1;
    }


    //symkey = symleft XOR primii octeti 16 din symright
    for (int i = 0; i < 16; i++) {
        elemente->sym_key[i] = elemente->sym_left[i] ^ elemente->sym_right[i];
    }

    return 0;
}