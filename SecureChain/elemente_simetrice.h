#ifndef ELEMENTE_SIMETRICE_H
#define ELEMENTE_SIMETRICE_H

#include <string>
#include "handshake_ecdh.h"

int salveaza_elemente_simetrice(int sym_elements_id, ElementeHandshake* elemente, const std::string& fisier_output);

#endif