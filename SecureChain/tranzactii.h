#ifndef TRANZACTII_H
#define TRANZACTII_H

#include <string>
#include "structuri_asn1.h"
#include "handshake_ecdh.h"


//functie pentru incarcarea elementelor simetrice din base64
int incarca_elemente_simetrice(const std::string& fisier_elemente, int sym_elements_id_asteptat,
    ElementeHandshake* elemente);


//functie pentru a crea si salva o tranzactie
int creeaza_tranzactie(int transaction_id, const std::string& subiect,
    int sender_id, int receiver_id, int sym_elements_id,
    const unsigned char* date, int lungime_date,
    const std::string& fisier_cheie_privata_rsa,
    const std::string& fisier_output);

#endif