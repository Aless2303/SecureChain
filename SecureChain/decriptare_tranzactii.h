#ifndef DECRIPTARE_TRANZACTII_H
#define DECRIPTARE_TRANZACTII_H

#include <string>

// Funcție pentru decriptarea unei tranzacții
int decripteaza_tranzactie(const std::string& fisier_tranzactie,
    const std::string& id_sender,
    int sym_elements_id,
    unsigned char** date_decriptate, int* lungime_date_decriptate);

#endif