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
//		mac - urile cheilor publice, in fisier raw, continând codificarea DER a elementelor de forma :
//SymElements
//	elementele simetrice necesare criptării mesajelor, in fisiere codificate cu Base64, continând codificarea DER a elementelor de forma :
//Transaction
//	tranzactiile dintre entităti in fisiere raw, continând codificarea DER a elementelor de forma:


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


int main() {
    Jurnal* jurnal = Jurnal::obtine_instanta();
    jurnal->seteaza_fisier("output/jurnal.bin");
    jurnal->adauga_actiune("System", "Pornire aplicatie");




    printf("Director de lucru: %s\n", _getcwd(NULL, 0));

    //test functionalitate 1 cu creare_salvare_chei
    if (creeaza_salveaza_chei("Entitate1", "output/entitate1_cheie_privata.pem",
        "output/entitate1_cheie_publica.pem",
        "output/entitate1_mac.der") != 0) {
        printf("Eroare la generarea cheilor pentru Entitate1\n");
        return 1;
    }
    jurnal->adauga_actiune("Entitate1", "Generare chei EC");

    if (creeaza_salveaza_chei("Entitate2", "output/entitate2_cheie_privata.pem",
        "output/entitate2_cheie_publica.pem",
        "output/entitate2_mac.der") != 0) {
        printf("Eroare la generarea cheilor pentru Entitate2\n");
        return 1;
    }
    jurnal->adauga_actiune("Entitate2", "Generare chei EC reusita");

    if (genereaza_salveaza_chei_rsa("Entitate1", "output/entitate1_cheie_privata_rsa.pem",
        "output/entitate1_cheie_publica_rsa.pem") != 0) {
        printf("Eroare la generarea cheilor RSA pentru Entitate1\n");
        return 1;
    }
    jurnal->adauga_actiune("Entitate1", "Generare chei RSA reusita");

    if (genereaza_salveaza_chei_rsa("Entitate2", "output/entitate2_cheie_privata_rsa.pem",
        "output/entitate2_cheie_publica_rsa.pem") != 0) {
        printf("Eroare la generarea cheilor RSA pentru Entitate2\n");
        return 1;
    }
    jurnal->adauga_actiune("Entitate2", "Generare chei RSA reusita");

    //test functionalitate handshake
    const char* entitate1 = "Entitate1";
    const char* entitate2 = "Entitate2";
    const char* parola = "parolamea2303";

    std::string fisier_cheie_privata1 = "output/entitate1_cheie_privata.pem";
    std::string fisier_cheie_publica1 = "output/entitate1_cheie_publica.pem";
    std::string fisier_mac1 = "output/entitate1_mac.der";

    std::string fisier_cheie_privata2 = "output/entitate2_cheie_privata.pem";
    std::string fisier_cheie_publica2 = "output/entitate2_cheie_publica.pem";
    std::string fisier_mac2 = "output/entitate2_mac.der";

    printf("Verificam autenticitatea cheii publice a Entitatii 1...\n");
    jurnal->adauga_actiune("System", "Verificare autenticitate cheie publica Entitate1");
    if (verifica_autenticitate_cheie_publica(entitate1, fisier_cheie_publica1, fisier_mac1)) {
        printf("OK\n");
        jurnal->adauga_actiune("System", "Autenticitate cheie publica Entitate1 verificata cu succes");
    }
    else {
        jurnal->adauga_actiune("System", "Eroare la verificarea autenticitatii cheii publice Entitate1");
        printf("Fail autenticitate cheie publica entitate 1\n");
        return 1;
    }

    printf("Verificam autenticitatea cheii publice a Entitatii 2...\n");
    jurnal->adauga_actiune("System", "Verificare autenticitate cheie publica Entitate2");
    if (verifica_autenticitate_cheie_publica(entitate2, fisier_cheie_publica2, fisier_mac2)) {
        printf("OK\n");
        jurnal->adauga_actiune("System", "Autenticitate cheie publica Entitate2 verificata cu succes");
    }
    else {
        printf("Fail autenticitate cheie publica entitate 2\n");
        jurnal->adauga_actiune("System", "Eroare la verificarea autenticitatii cheii publice Entitate2");
        return 1;
    }

    // ECDH handshake and key derivation
    printf("\n=== Handshake ECDH si derivare chei simetrice ===\n");
    jurnal->adauga_actiune("System", "Incepere handshake ECDH intre Entitate1 si Entitate2");

    EVP_PKEY* cheie_privata1 = incarca_cheie_privata(fisier_cheie_privata1, parola);
    EVP_PKEY* cheie_publica2 = incarca_cheie_publica(fisier_cheie_publica2);

    if (!cheie_privata1 || !cheie_publica2) {
        printf("Eroare la incarcarea cheilor\n");
        jurnal->adauga_actiune("System", "Eroare la incarcarea cheilor pentru handshake");
        if (cheie_privata1) EVP_PKEY_free(cheie_privata1);
        if (cheie_publica2) EVP_PKEY_free(cheie_publica2);
        return 1;
    }

    ElementeHandshake elemente;
    if (handshake_ecdh_derivare_chei(cheie_privata1, cheie_publica2, &elemente) != 0) {
        printf("Eroare la handshake si derivarea cheilor\n");
        jurnal->adauga_actiune("System", "Eroare la handshake ECDH si derivarea cheilor");
        EVP_PKEY_free(cheie_privata1);
        EVP_PKEY_free(cheie_publica2);
        return 1;
    }
    jurnal->adauga_actiune("Entitate1", "Handshake ECDH cu Entitate2 reusit");

    afiseaza_bytes("SymLeft", elemente.sym_left, 16);
    afiseaza_bytes("SymRight (primii 16 octeti)", elemente.sym_right, 16);
    afiseaza_bytes("SymKey", elemente.sym_key, 16);

    jurnal->adauga_actiune("System", "Salvare elemente simetrice derivate din handshake");
    if (salveaza_elemente_simetrice(1, &elemente, "output/sym_elements_1.base64") != 0) {
        printf("Eroare la salvarea elementelor simetrice\n");
        jurnal->adauga_actiune("System", "Eroare la salvarea elementelor simetrice");
        EVP_PKEY_free(cheie_privata1);
        EVP_PKEY_free(cheie_publica2);
        return 1;
    }
    jurnal->adauga_actiune("System", "Elemente simetrice salvate cu succes");

    EVP_PKEY_free(cheie_privata1);
    EVP_PKEY_free(cheie_publica2);

    printf("Handshake si derivare chei finalizate cu succes!\n");

    // Test transaction creation
    printf("\n=== Creare tranzactiei ===\n");
    jurnal->adauga_actiune("Entitate1", "Incepere creare tranzactie pentru Entitate2");

    const char* mesaj_text = "Aceasta este o tranzactie de test de la Entitate1 la Entitate2.";
    if (creeaza_tranzactie(1, "Tranzactie de test", 1, 2, 1,
        (const unsigned char*)mesaj_text, strlen(mesaj_text),
        "output/entitate1_cheie_privata_rsa.pem",
        "output/tranzactie_1.der") != 0) {
        printf("Eroare la crearea tranzactiei\n");
        jurnal->adauga_actiune("Entitate1", "Eroare la crearea tranzactiei pentru Entitate2");
        return 1;
    }
    jurnal->adauga_actiune("Entitate1", "Tranzactie #1 creata si semnata pentru Entitate2");

    // Test transaction decryption
    printf("\n=== Decriptare tranzactie ===\n");
    jurnal->adauga_actiune("Entitate2", "Incepere decriptare tranzactie #1 de la Entitate1");

    unsigned char* date_decriptate = NULL;
    int lungime_date_decriptate = 0;

    if (decripteaza_tranzactie("output/tranzactie_1.der",
        "output/entitate1_cheie_publica_rsa.pem",
        1, &date_decriptate, &lungime_date_decriptate) != 0) {
        printf("Eroare la decriptarea tranzactiei\n");
        jurnal->adauga_actiune("Entitate2", "Eroare la decriptarea tranzactiei #1");
        return 1;
    }
    jurnal->adauga_actiune("Entitate2", "Tranzactie #1 decriptata si verificata cu succes");

    printf("Mesaj decriptat: %.*s\n", lungime_date_decriptate, date_decriptate);
    OPENSSL_free(date_decriptate);

    printf("\nToate testele au fost finalizate cu succes!\n");
    jurnal->adauga_actiune("System", "Toate testele au fost finalizate cu succes");

    Jurnal::elibereaza();
    return 0;
}