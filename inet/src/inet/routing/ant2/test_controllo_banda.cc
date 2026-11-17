//
// test_controllo_banda.cc
//
// Test automatici della regola 5 della metrica di trust (controllo sulla banda
// massima dichiarata). Verificano la logica pura di Ant2BandCheck.h, senza
// OMNeT++ e senza INET.
//
// Compilazione ed esecuzione, dalla cartella radice del progetto:
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I inet/src \
//       inet/src/inet/routing/ant2/test_controllo_banda.cc -o test_controllo_banda
//   ./test_controllo_banda
//
// Il corpo e' racchiuso in ANT2_TEST_STANDALONE perche' il makefile di INET
// compila tutti i .cc sotto src dentro libINET: senza questa protezione il main()
// di questo file finirebbe nella libreria e il collegamento fallirebbe.
#ifdef ANT2_TEST_STANDALONE

#include <cstdio>

#include "inet/routing/ant2/Ant2BandCheck.h"

using namespace ant2band;

static int eseguiti = 0, falliti = 0;

static void verifica(bool condizione, const char *descrizione)
{
    eseguiti++;
    if (condizione)
        std::printf("[ OK ] %s\n", descrizione);
    else {
        falliti++;
        std::printf("[FAIL] %s\n", descrizione);
    }
}

static void stampa(const std::vector<BandOutcome>& r)
{
    for (auto& o : r)
        std::printf("        %s  %s  %s\n", o.controllo.c_str(), esitoStr(o.esito), o.dettaglio.c_str());
}

static Esito esitoDi(const std::vector<BandOutcome>& r)
{
    return r.empty() ? Esito::NON_APPLICABILE : r[0].esito;
}

static bool vuoto(const std::vector<BandOutcome>& r) { return r.empty(); }

static BandSample S(double t, double maxBand, double throughput, double energia)
{
    BandSample s;
    s.t = t; s.maxBand = maxBand; s.throughput = throughput; s.energia = energia;
    return s;
}

int main()
{
    BandCheckParams p;
    const double BANDA = 0.40;      // Mbps, il valore dello scenario

    std::printf("Scenario: banda massima 0,40 Mbps, letta all'avvio e mai piu' modificata\n\n");

    std::printf("== La banda massima non cambia ==\n");
    {
        BandObservedState st;
        auto r = checkBand(st, S(5.0, BANDA, 0.10, 90.0), p); stampa(r);
        verifica(esitoDi(r) == Esito::SUPERATO, "prima dichiarazione: SUPERATO, diventa il riferimento");

        int esiti = 0;
        double t = 5.0;
        for (int i = 0; i < 20; i++) {
            t += 2.5;
            esiti += (int)checkBand(st, S(t, BANDA, 0.10 + 0.01 * i, 90.0 - 0.2 * i), p).size();
        }
        std::printf("        esiti prodotti in altre 20 dichiarazioni con la stessa banda: %d\n", esiti);
        verifica(esiti == 0, "banda invariata: nessun esito, i contatori non si gonfiano");

        r = checkBand(st, S(60.0, BANDA * 2, 0.10, 80.0), p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "banda dichiarata raddoppiata: VIOLATO certo");
    }
    {
        // Anche una diminuzione e' una violazione: la banda massima non cambia.
        BandObservedState st;
        checkBand(st, S(5.0, BANDA, 0.10, 90.0), p);
        auto r = checkBand(st, S(8.0, 0.20, 0.10, 90.0), p); stampa(r);
        verifica(esitoDi(r) == Esito::VIOLATO, "banda dichiarata dimezzata: VIOLATO certo");
    }
    {
        BandObservedState st;
        auto r = checkBand(st, S(-1.0, BANDA, 0.10, 90.0), p);
        verifica(vuoto(r), "misura mai eseguita (timbro negativo): nessun esito");
    }

    std::printf("\n== Drone onesto per 120 s (nessun falso positivo) ==\n");
    {
        BandObservedState st;
        int negativi = 0;
        double t = 0;
        for (int i = 0; i < 50; i++) {
            t += 2.4;
            // throughput e energia variano, la banda massima no
            double th = 0.05 + 0.004 * ((i * 7) % 60);
            for (auto& o : checkBand(st, S(t, BANDA, th, 95.0 - 0.07 * t), p))
                if (o.esito == Esito::VIOLATO)
                    negativi++;
        }
        verifica(negativi == 0, "50 misure con throughput ed energia variabili: nessuna violazione");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
