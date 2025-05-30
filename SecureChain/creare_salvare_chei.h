﻿#ifndef CREARE_SALVARE_CHEI_H
#define CREARE_SALVARE_CHEI_H

#include <string>

int creeaza_salveaza_chei(const std::string& nume_entitate, const char* parola,
    const std::string& fisier_cheie_privata,
    const std::string& fisier_cheie_publica,
    const std::string& fisier_mac);

int calculeaza_diferenta_timp(unsigned char* diferenta, size_t* lungime_diferenta);

#endif