#pragma warning(disable : 4996)
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
#include <string>
#include "creare_salvare_chei.h"
#include "handshake_validare.h"
#include "handshake_ecdh.h"
#include "elemente_simetrice.h"
#include "generare_rsa.h"
#include "tranzactii.h"
#include "decriptare_tranzactii.h"
#include "jurnal.h"



//PubKeyMAC:
//	Toate informatiile generate vor fi salvate in fisiere specifice, astfel:
//		cheile asimetrice in fisiere PEM;
//		mac - urile cheilor publice, in fisier raw, continand codificarea DER a elementelor de forma :
//SymElements
//	elementele simetrice necesare criptării mesajelor, in fisiere codificate cu Base64, continand codificarea DER a elementelor de forma :
//Transaction
//	tranzactiile dintre entităti in fisiere raw, continand codificarea DER a elementelor de forma:
//voi folosi secp256k1 pentru chei si curba eliptica pe 256 biti.
//cheile private le voi salva in format PEM. 
//pem -> Privacy Enhanced Mail format de fisier utilizat pentru stocarea si transmiterea datelor criptografice.(certificate digitale, chei private
// cheile publice vor avea asignate un MAC (GMAC) iar cheia simetrica pentru GMAC o voi genera cu PBKDF2 prin SHA3-256. 
//mac-ul il stochez intr-un fisier DER cofnrm structurii PubKeyMac
// .der (Distinguished Encoding Rules) binar utilizat pentru stocarea datelor criptografice.  (Nu poate fi citit direct intr-un editor de text, spre deosebire de .pem.)
//cheile private si publice le salvez intr-un .pem




void afiseaza_bytes(const char* nume, unsigned char* date, int lungime) {
    printf("%s: ", nume);
    for (int i = 0; i < lungime; i++) {
        printf("%02x", date[i]);
    }
    printf("\n");
}


int proceseaza_fisier_intrare(const char* nume_fisier) {
    FILE* f = fopen(nume_fisier, "r");
    if (!f) {
        printf("Nu am putut deschide fisierul %s\n", nume_fisier);
        return 1;
    }


    Jurnal* jurnal = Jurnal::obtine_instanta();
    jurnal->seteaza_fisier("info.log");
    jurnal->adauga_actiune("System", "Pornire aplicatie");

    int numar_entitati;
    fscanf(f, "%d\n", &numar_entitati);


    //generez chei pentru toate entitatile
    int id_entitate;
    char parola[32];

    for (int i = 0; i < numar_entitati; i++) {
        fscanf(f, "%d %s\n", &id_entitate, parola);


        //convertesc id-ul in string pentru a l folosi in numele fisierelor 
        char id_str[16];
        sprintf(id_str, "%d", id_entitate);


        //generez cheile ecc
        char nume_cheie_privata_ecc[32], nume_cheie_publica_ecc[32], nume_mac_ecc[32];
        sprintf(nume_cheie_privata_ecc, "%d_priv.ecc", id_entitate);
        sprintf(nume_cheie_publica_ecc, "%d_pub.ecc", id_entitate);
        sprintf(nume_mac_ecc, "%d_ecc.mac", id_entitate);

        if (creeaza_salveaza_chei(id_str, parola,nume_cheie_privata_ecc, nume_cheie_publica_ecc, nume_mac_ecc) != 0) {
            printf("Eroare la generarea cheilor ECC pentru entitatea %d\n", id_entitate);
            fclose(f);
            return 1;
        }
        jurnal->adauga_actiune(id_str, "Generare chei EC reusita");


        //generez chei rsa
        char nume_cheie_privata_rsa[32], nume_cheie_publica_rsa[32];
        sprintf(nume_cheie_privata_rsa, "%d_priv.rsa", id_entitate);
        sprintf(nume_cheie_publica_rsa, "%d_pub.rsa", id_entitate);

        if (genereaza_salveaza_chei_rsa(id_str, nume_cheie_privata_rsa, nume_cheie_publica_rsa) != 0) {
            printf("Eroare la generarea cheilor RSA pentru entitatea %d\n", id_entitate);
            fclose(f);
            return 1;
        }
        jurnal->adauga_actiune(id_str, "Generare chei RSA reusita");
    }


    //citesc nr de tranzactii
    int numar_tranzactii;
    fscanf(f, "%d\n", &numar_tranzactii);


    //procesez tranzactiile rand pe rand
    int sym_counter = 1;  // elementele simetrice

    for (int i = 0; i < numar_tranzactii; i++) {
        char linie[2048];
        fgets(linie, sizeof(linie), f);


        //variabile pentru datele din tranzactie
        int id_tranzactie, id_sursa, id_dest;
        char subiect[512], mesaj[1024];

        //parsez linia in formatul urmator: 
        //id_tranzactie/id_entitate_sursa/
        //id_entitate_destinatie/subiect/mesaj
        sscanf(linie, "%d/%d/%d/%[^/]/%[^\n]",
            &id_tranzactie,
            &id_sursa,
            &id_dest,
            subiect,
            mesaj);


        //convertesc id-urile in string
        char id_sursa_str[16], id_dest_str[16];
        sprintf(id_sursa_str, "%d", id_sursa);
        sprintf(id_dest_str, "%d", id_dest);


        //verific autenticitatea cheilor
        printf("\nVerificam autenticitatea cheii publice a entitatii %s...\n", id_dest_str);
        jurnal->adauga_actiune("System", "Verificare autenticitate cheie publica Entitate " + std::string(id_dest_str));

        if (!verifica_autenticitate_cheie_publica(id_dest_str)) {
            printf("Verificarea autenticitatii cheii publice ECC a entitatii %s a esuat\n", id_dest_str);
            jurnal->adauga_actiune("System", "Eroare la verificarea autenticitatii cheii publice ECC Entitate " + std::string(id_dest_str));
            continue;
        }

        printf("Autenticitatea cheii ECC verificata cu succes\n");
        jurnal->adauga_actiune("System", "Autenticitate cheie publica ECC Entitate " + std::string(id_dest_str) + " verificata cu succes");


        if (!verifica_autenticitate_cheie_publica_rsa(id_dest_str)) {
            printf("Verificarea autenticitatii cheii publice RSA a entitatii %s a esuat\n", id_dest_str);
            jurnal->adauga_actiune("System", "Eroare la verificarea autenticitatii cheii publice RSA Entitate " + std::string(id_dest_str));
            continue;
        }

        printf("Autenticitatea cheii RSA verificata cu succes\n");
        jurnal->adauga_actiune("System", "Autenticitate cheie publica RSA Entitate " + std::string(id_dest_str) + " verificata cu succes");


        //citesc iar fisierul ca sa gasesc parola entitatii sursa
        FILE* f_parole = fopen(nume_fisier, "r");
        int nr_ent;
        fscanf(f_parole, "%d\n", &nr_ent);

        int id;
        char parola_sursa[32];
        bool parola_gasita = false;

        for (int j = 0; j < nr_ent; j++) {
            fscanf(f_parole, "%d %s\n", &id, parola_sursa);
            if (id == id_sursa) {
                parola_gasita = true;
                break;
            }
        }
        fclose(f_parole);

        if (!parola_gasita) {
            printf("Nu am gasit parola pentru entitatea %d\n", id_sursa);
            continue;
        }


        //fac handshake ecdh
        printf("\n=== Handshake ECDH si derivare chei simetrice ===\n");
        jurnal->adauga_actiune("System", "Incepere handshake ECDH intre Entitate " + std::string(id_sursa_str) + " si Entitate " + std::string(id_dest_str));


        //incarc cheile pentru handshake
        EVP_PKEY* cheie_privata_sursa = incarca_cheie_privata(id_sursa_str, parola_sursa);
        EVP_PKEY* cheie_publica_dest = incarca_cheie_publica(id_dest_str);

        if (!cheie_privata_sursa || !cheie_publica_dest) {
            printf("Eroare la incarcarea cheilor pentru handshake\n");
            jurnal->adauga_actiune("System", "Eroare la incarcarea cheilor pentru handshake");
            if (cheie_privata_sursa) EVP_PKEY_free(cheie_privata_sursa);
            if (cheie_publica_dest) EVP_PKEY_free(cheie_publica_dest);
            continue;
        }


        //efectuez handshake si derivarea cheii
        ElementeHandshake elemente;
        if (handshake_ecdh_derivare_chei(cheie_privata_sursa, cheie_publica_dest, &elemente) != 0) {
            printf("Eroare la handshake si derivarea cheilor\n");
            jurnal->adauga_actiune("System", "Eroare la handshake ECDH si derivarea cheilor");
            EVP_PKEY_free(cheie_privata_sursa);
            EVP_PKEY_free(cheie_publica_dest);
            continue;
        }
        jurnal->adauga_actiune(id_sursa_str, "Handshake ECDH cu Entitate " + std::string(id_dest_str) + " reusit");


        //afisez el simetrice
        afiseaza_bytes("SymLeft", elemente.sym_left, 16);
        afiseaza_bytes("SymRight (primii 16 octeti)", elemente.sym_right, 16);
        afiseaza_bytes("SymKey", elemente.sym_key, 16);


        //salvez el simetrice
        char nume_fisier_sym[32];
        sprintf(nume_fisier_sym, "%d.sym", sym_counter);

        jurnal->adauga_actiune("System", "Salvare elemente simetrice derivate din handshake");
        if (salveaza_elemente_simetrice(sym_counter, &elemente, nume_fisier_sym) != 0) {
            printf("Eroare la salvarea elementelor simetrice\n");
            jurnal->adauga_actiune("System", "Eroare la salvarea elementelor simetrice");
            EVP_PKEY_free(cheie_privata_sursa);
            EVP_PKEY_free(cheie_publica_dest);
            continue;
        }
        jurnal->adauga_actiune("System", "Elemente simetrice salvate cu succes");

        EVP_PKEY_free(cheie_privata_sursa);
        EVP_PKEY_free(cheie_publica_dest);


        //creez tranzactia
        printf("\n=== Creare tranzactie ===\n");
        jurnal->adauga_actiune(id_sursa_str, "Incepere creare tranzactie pentru Entitate " + std::string(id_dest_str));

        char nume_fisier_tranzactie[64];
        sprintf(nume_fisier_tranzactie, "%d_%d_%d.trx", id_sursa, id_dest, id_tranzactie);

        if (creeaza_tranzactie(id_tranzactie, subiect,
            id_sursa, id_dest,
            sym_counter,
            (const unsigned char*)mesaj,
            strlen(mesaj),
            nume_fisier_tranzactie) != 0) {
            printf("Eroare la crearea tranzactiei\n");
            jurnal->adauga_actiune(id_sursa_str, "Eroare la crearea tranzactiei pentru Entitate " + std::string(id_dest_str));
            continue;
        }
        jurnal->adauga_actiune(id_sursa_str, "Tranzactie #" + std::to_string(id_tranzactie) + " creata si semnata pentru Entitate " + std::string(id_dest_str));


        //decriptez tranzactia
        printf("\n=== Decriptare tranzactie ===\n");
        jurnal->adauga_actiune(id_dest_str, "Incepere decriptare tranzactie #" + std::to_string(id_tranzactie) + " de la Entitate " + std::string(id_sursa_str));

        unsigned char* date_decriptate = NULL;
        int lungime_date_decriptate = 0;

        if (decripteaza_tranzactie(nume_fisier_tranzactie, id_sursa_str, sym_counter,
            &date_decriptate, &lungime_date_decriptate) != 0) {
            printf("Eroare la decriptarea tranzactiei\n");
            jurnal->adauga_actiune(id_dest_str, "Eroare la decriptarea tranzactiei #" + std::to_string(id_tranzactie));
            continue;
        }
        jurnal->adauga_actiune(id_dest_str, "Tranzactie #" + std::to_string(id_tranzactie) + " decriptata si verificata cu succes");

        printf("Mesaj decriptat: %.*s\n", lungime_date_decriptate, date_decriptate);
        OPENSSL_free(date_decriptate);


        //incrementez pentru a continua cu urmatoarele el simetrice
        sym_counter++;
    }

    fclose(f);

    printf("\nToate operatiunile au fost finalizate cu succes!\n");
    jurnal->adauga_actiune("System", "Toate operatiunile au fost finalizate cu succes");
    Jurnal::elibereaza();

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Utilizare: %s <fisier_intrare> [<fisier_intrare2> ...]\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        printf("Procesare fisier: %s\n", argv[i]);
        if (proceseaza_fisier_intrare(argv[i]) != 0) {
            printf("Eroare la procesarea fisierului: %s\n", argv[i]);
            return 1;
        }
    }

    return 0;
}