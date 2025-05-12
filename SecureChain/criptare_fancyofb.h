#ifndef CRIPTARE_FANCYOFB_H
#define CRIPTARE_FANCYOFB_H

#include <string>

int cripteaza_fancyofb(unsigned char* date, int lungime_date, unsigned char* sym_key, unsigned char* iv,
    unsigned char** date_criptate, int* lungime_date_criptate);

#endif