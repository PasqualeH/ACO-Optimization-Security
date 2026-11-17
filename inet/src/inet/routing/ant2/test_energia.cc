//
// test_energia.cc - test automatici delle correzioni sull'energia.
//
// Verifica la logica di Ant2Energy.h (la stessa usata da Ant2.cc):
//   1) calcolo della percentuale (modalita' legacy e corretta);
//   2) macchina a stati della ricarica;
//   3) una simulazione numerica semplificata della batteria, per ricavare i
//      tempi attesi nella configurazione di prova TestRicarica dell'.ini.
//
// Come per microbench.cc, tutto il file e' racchiuso in una #ifdef, cosi'
// la build di INET lo compila come file vuoto. Per eseguirlo:
//
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I<cartella src di INET>
//       test_energia.cc -o test_energia  (poi ./test_energia)
//

#ifdef ANT2_TEST_STANDALONE

#include <cstdio>
#include <cmath>
#include "inet/routing/ant2/Ant2Energy.h"

using namespace inet::ant2energy;

static int falliti = 0, eseguiti = 0;

static void verifica(bool condizione, const char *descrizione)
{
    eseguiti++;
    if (!condizione)
        falliti++;
    std::printf("[%s] %s\n", condizione ? " OK " : "FAIL", descrizione);
}

static bool circa(double a, double b, double tol = 1e-9) { return std::fabs(a - b) <= tol; }

static const char *nomeAzione(ChargingAction a)
{
    switch (a) {
        case ChargingAction::INIZIA_RICARICA: return "INIZIA_RICARICA";
        case ChargingAction::FINE_RICARICA: return "FINE_RICARICA";
        default: return "NESSUNA";
    }
}

int main()
{
    std::printf("== 1) Percentuale di carica ==\n");
    // Codice originale: nominalCapacity di Ant2 = 1 J, troncamento all'intero.
    verifica(circa(chargePercent(0.9, 1.0, true), 90.0), "legacy: adh[0] con 0,9 J dichiara 90% (invece del vero 30%)");
    verifica(circa(chargePercent(2.7, 1.0, true), 270.0), "legacy: adh[11] con 2,7 J dichiara 270%");
    verifica(circa(chargePercent(0.8997, 1.0, true), 89.0), "legacy: 0,8997 J viene troncato a 89%");
    // Correzione: capacita' reale della batteria (3 J) e decimali.
    verifica(circa(chargePercent(0.9, 3.0, false), 30.0), "corretta: adh[0] con 0,9 J dichiara 30%");
    verifica(circa(chargePercent(2.7, 3.0, false), 90.0), "corretta: adh[11] con 2,7 J dichiara 90%");
    verifica(circa(chargePercent(0.8997, 3.0, false), 29.99, 1e-9), "corretta: 0,8997 J vale 29,99% (decimali conservati)");
    verifica(circa(chargePercent(0.45, 3.0, false), 15.0), "corretta: la soglia del 15% corrisponde a 0,45 J");
    verifica(circa(chargePercent(0.15, 3.0, false), 5.0), "corretta: lo spegnimento (0,15 J) corrisponde al 5%");
    verifica(circa(chargePercent(1.0, 0.0, false), 0.0), "capacita' nulla: nessuna divisione per zero");

    std::printf("\n== 2) Macchina a stati della ricarica (soglie 15%% e 100%%) ==\n");
    {
        ChargingLogic l(15, 100);
        verifica(l.aggiorna(20.0) == ChargingAction::NESSUNA, "20%: nessuna azione");
        verifica(l.aggiorna(15.01) == ChargingAction::NESSUNA, "15,01%: ancora sopra la soglia");
        verifica(l.aggiorna(15.0) == ChargingAction::INIZIA_RICARICA, "15,00%: inizia la ricarica");
        verifica(l.inRicarica(), "stato: IN_RICARICA");
        verifica(l.aggiorna(14.9) == ChargingAction::NESSUNA, "14,9% durante la ricarica: nessun secondo avviso");
        verifica(l.aggiorna(60.0) == ChargingAction::NESSUNA, "60% durante la ricarica: si continua");
        verifica(l.aggiorna(99.99) == ChargingAction::NESSUNA, "99,99%: non ancora completata");
        verifica(l.aggiorna(100.0) == ChargingAction::FINE_RICARICA, "100%: ricarica completata");
        verifica(!l.inRicarica(), "stato: OPERATIVO");
        verifica(l.aggiorna(99.0) == ChargingAction::NESSUNA, "99% dopo il ritorno: nessuna azione");
        verifica(l.aggiorna(12.0) == ChargingAction::INIZIA_RICARICA, "12%: una nuova discesa avvia una nuova ricarica");
    }
    {
        ChargingLogic l(15, 100);
        verifica(l.aggiorna(100.0 - 1e-9) == ChargingAction::NESSUNA, "OPERATIVO al 100%: nessuna azione");
        l.aggiorna(10.0);
        verifica(l.aggiorna(100.0 - 1e-9) == ChargingAction::FINE_RICARICA, "99,999999999% (errore di arrotondamento) conta come carica");
    }
    {
        ChargingLogic l(15, 100);
        l.setSoglie(20, 90);
        verifica(l.aggiorna(19.0) == ChargingAction::INIZIA_RICARICA, "soglie modificabili: 20% avvia la ricarica");
        verifica(l.aggiorna(90.0) == ChargingAction::FINE_RICARICA, "soglie modificabili: 90% la completa");
    }

    std::printf("\n== 3) Simulazione semplificata della configurazione TestRicarica ==\n");
    // adh[9] parte con il 17% di 3 J, la radio consuma 2 mW (ascolto),
    // misure ogni 2 s, caricatore da 100 mW, soglie 15% e 100%.
    {
        const double capJ = 3.0, consumoW = 0.002, caricatoreW = 0.100, passo = 2.0;
        double energiaJ = 0.17 * capJ, t = 0;
        bool caricatoreAcceso = false;
        double tInizio = -1, tFine = -1;
        ChargingLogic l(15, 100);
        for (int i = 0; i < 200 && tFine < 0; i++) {
            t += passo;
            double netto = (caricatoreAcceso ? caricatoreW : 0.0) - consumoW;
            energiaJ = std::fmin(capJ, energiaJ + netto * passo);
            ChargingAction a = l.aggiorna(chargePercent(energiaJ, capJ, false));
            if (a == ChargingAction::INIZIA_RICARICA) { caricatoreAcceso = true; tInizio = t; }
            if (a == ChargingAction::FINE_RICARICA) { caricatoreAcceso = false; tFine = t; }
            if (a != ChargingAction::NESSUNA)
                std::printf("      t = %5.1f s  energia %6.2f%%  -> %s\n", t, chargePercent(energiaJ, capJ, false), nomeAzione(a));
        }
        verifica(tInizio > 0 && tInizio <= 32, "il drone avvisa e va alla stazione entro circa 30 s");
        verifica(tFine > tInizio, "la ricarica si completa");
        verifica(tFine - tInizio >= 24 && tFine - tInizio <= 30, "la ricarica dal 15% al 100% dura circa 26 s");
        std::printf("      (ricarica iniziata a %.0f s e completata a %.0f s: durata %.0f s)\n", tInizio, tFine, tFine - tInizio);
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
