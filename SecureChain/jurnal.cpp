#pragma warning(disable : 4996)
#include "jurnal.h"
#include <ctime>
#include <iomanip>
#include <iostream>



//instantiez membrii statici din clasa.
Jurnal* Jurnal::instanta = nullptr;
std::mutex Jurnal::mutex_jurnal;

Jurnal::Jurnal() : cale_fisier("output/jurnal.bin") {
    deschide_fisier();
}

Jurnal::~Jurnal() {
    if (fisier_jurnal.is_open()) {
        fisier_jurnal.close();
    }
}

Jurnal* Jurnal::obtine_instanta() {
    if (instanta == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_jurnal);
        if (instanta == nullptr) {
            instanta = new Jurnal();
        }
    }
    return instanta;
}

void Jurnal::elibereaza() {
    std::lock_guard<std::mutex> lock(mutex_jurnal);
    if (instanta != nullptr) {
        delete instanta;
        instanta = nullptr;
    }
}

void Jurnal::seteaza_fisier(const std::string& cale) {
    std::lock_guard<std::mutex> lock(mutex_jurnal);

    if (fisier_jurnal.is_open()) {
        fisier_jurnal.close();
    }

    cale_fisier = cale;
    deschide_fisier();
}

bool Jurnal::deschide_fisier() {
    fisier_jurnal.open(cale_fisier, std::ios::binary | std::ios::app);
    if (!fisier_jurnal.is_open()) {
        std::cerr << "Eroare la deschiderea fisierului jurnal: " << cale_fisier << std::endl;
        return false;
    }
    return true;
}

std::string Jurnal::obtine_timestamp() {
    auto acum = std::time(nullptr);
    auto tm_info = std::localtime(&acum);

    char data[11]; // YYYY-MM-DD + null terminator
    std::strftime(data, sizeof(data), "%Y-%m-%d", tm_info);

    char ora[9]; // HH:MM:SS + null terminator
    std::strftime(ora, sizeof(ora), "%H:%M:%S", tm_info);

    return std::string(data) + std::string(ora);
}

bool Jurnal::adauga_actiune(const std::string& entitate, const std::string& actiune) {
    std::lock_guard<std::mutex> lock(mutex_jurnal);

    if (!fisier_jurnal.is_open() && !deschide_fisier()) {
        return false;
    }

    std::string timestamp = obtine_timestamp();

    fisier_jurnal.write(timestamp.c_str(), timestamp.length());
    fisier_jurnal.write(entitate.c_str(), entitate.length());
    fisier_jurnal.write(actiune.c_str(), actiune.length());
    fisier_jurnal.flush();

    return !fisier_jurnal.fail();
}