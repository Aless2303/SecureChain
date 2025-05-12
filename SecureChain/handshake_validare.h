#ifndef HANDSHAKE_VALIDARE_H
#define HANDSHAKE_VALIDARE_H

#include <string>
#include <openssl/evp.h>

//incaracrea cheii private din fisier

EVP_PKEY* incarca_cheie_privata(const std::string& fisier_cheie_privata, const char* parola);

//incarcarea unei chei publice din fisire
EVP_PKEY* incarca_cheie_publica(const std::string& fisier_cheie_publica);


//verificarea autentificatii cheii publice cu ajutorul mac-ul.
int verifica_autenticitate_cheie_publica(const std::string& nume_entitate,
    const std::string& fisier_cheie_publica,
    const std::string& fisier_mac);

#endif