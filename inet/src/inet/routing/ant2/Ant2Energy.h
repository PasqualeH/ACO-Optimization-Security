//
// Ant2Energy.h
//
// Logica "pura" della gestione dell'energia di Ant2: calcolo della
// percentuale di carica e macchina a stati della ricarica.
//
// Il file non dipende da OMNeT++ ne' da INET, cosi' la stessa logica usata
// dal protocollo puo' essere compilata ed eseguita da sola nei test
// automatici (tools/test_energia.cc).
//
// Introdotto con le correzioni sull'energia (parametro legacyEnergy):
//   - percentuale calcolata sulla capacita' reale della batteria e con i
//     decimali (con legacyEnergy = true: capacita' del parametro
//     nominalCapacity di Ant2 e troncamento all'intero, come nel codice
//     originale);
//   - ricarica: al raggiungimento della soglia bassa il drone avvisa, va alla
//     stazione e si ricarica; raggiunta la soglia di fine ricarica torna al
//     punto di partenza.
//

#ifndef __INET_ANT2ENERGY_H
#define __INET_ANT2ENERGY_H

#include <cmath>

namespace inet {
namespace ant2energy {

/**
 * Percentuale di carica a partire dall'energia residua (in joule).
 *
 * - modalita' corretta (legacy = false): residua / capacita' reale della
 *   batteria * 100, con tutti i decimali;
 * - modalita' legacy (legacy = true): stessa formula ma con la capacita'
 *   passata dal parametro nominalCapacity di Ant2 e troncata all'intero,
 *   esattamente come faceva il codice originale.
 */
inline double chargePercent(double residualJ, double capacityJ, bool legacy)
{
    if (capacityJ <= 0)
        return 0.0;
    double p = (residualJ / capacityJ) * 100.0;
    return legacy ? (double)(int)p : p;
}

/** Stato del drone rispetto alla ricarica. */
enum class ChargingState { OPERATIVO, IN_RICARICA };

/** Azione che il protocollo deve compiere dopo una nuova misura. */
enum class ChargingAction {
    NESSUNA,        // nessun cambiamento
    INIZIA_RICARICA,// avviso di batteria scarica + andata alla stazione + generatore acceso
    FINE_RICARICA   // generatore spento + ritorno alla posizione precedente
};

/**
 * Macchina a stati della ricarica.
 *
 * - OPERATIVO e percentuale <= sogliaBassa     -> INIZIA_RICARICA, stato IN_RICARICA
 * - IN_RICARICA e percentuale >= sogliaFine    -> FINE_RICARICA,   stato OPERATIVO
 * - in tutti gli altri casi                    -> NESSUNA
 *
 * La tolleranza su sogliaFine serve perche' la batteria di INET, quando e'
 * piena, si ferma esattamente alla capacita' nominale: con sogliaFine = 100
 * il confronto con i numeri in virgola mobile deve accettare 99,9999...
 */
class ChargingLogic
{
  public:
    ChargingLogic(double sogliaBassa, double sogliaFine)
        : sogliaBassa(sogliaBassa), sogliaFine(sogliaFine) {}

    ChargingAction aggiorna(double percentuale)
    {
        if (stato == ChargingState::OPERATIVO && percentuale <= sogliaBassa) {
            stato = ChargingState::IN_RICARICA;
            return ChargingAction::INIZIA_RICARICA;
        }
        if (stato == ChargingState::IN_RICARICA && percentuale >= sogliaFine - 1e-6) {
            stato = ChargingState::OPERATIVO;
            return ChargingAction::FINE_RICARICA;
        }
        return ChargingAction::NESSUNA;
    }

    ChargingState getStato() const { return stato; }
    bool inRicarica() const { return stato == ChargingState::IN_RICARICA; }
    void setSoglie(double bassa, double fine) { sogliaBassa = bassa; sogliaFine = fine; }

  private:
    double sogliaBassa;
    double sogliaFine;
    ChargingState stato = ChargingState::OPERATIVO;
};

} // namespace ant2energy
} // namespace inet

#endif
