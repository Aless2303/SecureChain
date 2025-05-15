#ifndef GENERARE_RSA_H
#define GENERARE_RSA_H

#include <string>

int genereaza_salveaza_chei_rsa(const std::string& nume_entitate,
    const std::string& fisier_cheie_privata_rsa,
    const std::string& fisier_cheie_publica_rsa);

#endif