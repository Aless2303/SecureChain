﻿#ifndef TRANZACTII_H
#define TRANZACTII_H

#include <string>
#include "structuri_asn1.h"
#include "handshake_ecdh.h"


int incarca_elemente_simetrice(const std::string& sym_elements_id,
    ElementeHandshake* elemente);


int creeaza_tranzactie(int transaction_id, const std::string& subiect,
    int sender_id, int receiver_id, int sym_elements_id,
    const unsigned char* date, int lungime_date,
    const std::string& fisier_output);

#endif