#ifndef HANDSHAKE_VALIDARE_H
#define HANDSHAKE_VALIDARE_H

#include <string>
#include <openssl/evp.h>
#include <openssl/rsa.h>

//ecc
EVP_PKEY* incarca_cheie_privata(const std::string& id_entitate, const char* parola);

EVP_PKEY* incarca_cheie_publica(const std::string& id_entitate);

//rsa:
RSA* incarca_cheie_privata_rsa(const std::string& id_entitate, const char* parola);

EVP_PKEY* incarca_cheie_publica_rsa(const std::string& id_entitate);

//verific ecc cu mac
int verifica_autenticitate_cheie_publica(const std::string& id_entitate);

//verific rsa cu mac
int verifica_autenticitate_cheie_publica_rsa(const std::string& id_entitate);

#endif