#ifndef HANDSHAKE_VALIDARE_H
#define HANDSHAKE_VALIDARE_H

#include <string>
#include <openssl/evp.h>
#include <openssl/rsa.h>

// Funcție pentru încărcarea cheii private ECC
EVP_PKEY* incarca_cheie_privata(const std::string& id_entitate, const char* parola);

// Funcție pentru încărcarea cheii publice ECC
EVP_PKEY* incarca_cheie_publica(const std::string& id_entitate);

// Funcție pentru încărcarea cheii private RSA
RSA* incarca_cheie_privata_rsa(const std::string& id_entitate, const char* parola);

// Funcție pentru încărcarea cheii publice RSA
EVP_PKEY* incarca_cheie_publica_rsa(const std::string& id_entitate);

// Verificarea autenticității cheii publice ECC cu ajutorul MAC-ului
int verifica_autenticitate_cheie_publica(const std::string& id_entitate);

// Verificarea autenticității cheii publice RSA cu ajutorul MAC-ului
int verifica_autenticitate_cheie_publica_rsa(const std::string& id_entitate);

#endif