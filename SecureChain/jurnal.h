#ifndef JURNAL_H
#define JURNAL_H

#include <string>
#include <fstream>
#include <mutex>

class Jurnal {
private:
    Jurnal();
    ~Jurnal();

    Jurnal(const Jurnal&) = delete;
    Jurnal& operator=(const Jurnal&) = delete;

    static Jurnal* instanta;
    static std::mutex mutex_jurnal;

    std::string cale_fisier;
    std::ofstream fisier_jurnal;

    std::string obtine_timestamp();

    bool deschide_fisier();

public:
    static Jurnal* obtine_instanta();

    void seteaza_fisier(const std::string& cale);

    bool adauga_actiune(const std::string& entitate, const std::string& actiune);

    static void elibereaza();
};

#endif