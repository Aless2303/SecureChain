#ifndef HANDSHAKE_ECDH_H
#define HANDSHAKE_ECDH_H

#include <openssl/evp.h>



//structura pentru stocarea elementelor derivate din handshake
typedef struct {
    unsigned char sym_left[16];    //SymLeft (16 octeti)
    unsigned char sym_right[48];   //SymRight (48 octeti)
    unsigned char sym_key[16];     //SymKey (16 octeti)
} ElementeHandshake;


int handshake_ecdh_derivare_chei(EVP_PKEY* cheie_privata, EVP_PKEY* cheie_publica_peer,
    ElementeHandshake* elemente);

#endif