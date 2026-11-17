//
// Ant2EnergyCheck.h
//
// Regola 1 della metrica di trust: controllo sull'andamento dell'energia
// dichiarata nei BANT. Logica "pura", senza dipendenze da OMNeT++/INET, cosi'
// la stessa funzione usata dal protocollo viene verificata dai test
// automatici (test_controllo_energia.cc).
//
// Per ogni drone osservato il nodo che controlla conserva l'ultima misura, una
// misura di riferimento e lo storico recente dei timbri. A ogni misura nuova,
// che arrivi da un BANT o da una voce di traccia:
//   0. coerenza del timbro: non nel futuro e non piu' vecchio dell'arrivo di
//      piu' di maxAgeS;
//   0b. coerenza della misura: se lo stesso timbro e' gia' stato dichiarato,
//      il valore deve essere lo stesso (un drone non puo' dichiarare due
//      energie diverse per la stessa lettura della batteria);
//   1. misura nuova? (prima misura: solo memorizzata; timbro uguale o piu'
//      vecchio dell'ultimo: non applicabile);
//   2. valore ammesso: tra 0% e 100%;
//   3. andamento rispetto all'ultima misura:
//        fuori dalla stazione: niente salita, calo <= calo massimo * dt;
//        alla stazione:        salita <= velocita' di ricarica * dt,
//                              calo <= calo massimo * dt;
//   4. calo minimo rispetto alla misura di riferimento, se sono passati
//      almeno W secondi e il drone non e' passato dalla stazione:
//        calo >= minDrop(dt);
//   5. (solo se e' nota l'energia iniziale) l'energia dichiarata non puo'
//      superare quella iniziale meno minDrop(t), finche' il drone non e' mai
//      stato alla stazione. Disattivato per impostazione predefinita: una GCS
//      non ha motivo di conoscere a priori i dati dei droni, e dopo lo
//      snapshot ottiene il primo campione con il primo giro di tracce.
//
// Il calo minimo (minDrop) non e' una costante: e' l'energia che il drone deve
// avere consumato nell'intervallo, ricavata dai consumi della radio e dal
// comportamento del protocollo, cioe'
//   - ascolto per tutta la durata dell'intervallo (pMinW);
//   - trasmissione (pMaxW) dei messaggi che il protocollo gli impone: due FANT
//     propri per generazione, piu' una ritrasmissione e un BANT per ogni
//     generazione altrui ricevuta;
//   - ricezione (pRxW) delle generazioni altrui.
// La durata in aria di un messaggio si ricava dalla sua dimensione reale, dalle
// intestazioni dei livelli sottostanti e dalla velocita' della radio. La parte
// di traffico e' moltiplicata per un coefficiente di prudenza trafficMargin
// (0 = solo ascolto, cioe' il comportamento precedente; 1 = traffico intero),
// perche' un nodo che perde un FANT per una collisione non lo ritrasmette e
// non risponde, e non deve essere accusato per questo.
//
// Ricarica non osservata: chi controlla puo' non ricevere i BANT inviati dal
// drone mentre era alla stazione (fuori portata). Una salita di energia fuori
// dalla stazione e' quindi "non applicabile" (e non violata) se nel tempo
// trascorso il drone avrebbe potuto scendere fino alla soglia di ricarica al
// calo massimo e poi ricaricarsi fino al valore dichiarato:
//   (E_prec - E_avvio) / calo massimo + (E_dich - E_avvio) / ricarica <= dt,
//   con E_avvio = min(E_prec, soglia di ricarica).
// In quel caso il riferimento del calo minimo riparte dalla nuova misura.
//
// Tutti i limiti sono in punti percentuali, con una tolleranza (0,01%)
// dovuta ai due decimali.
//

#ifndef __INET_ANT2ENERGYCHECK_H
#define __INET_ANT2ENERGYCHECK_H

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>

namespace inet {
namespace ant2energy {

/**
 * Costanti fisiche usate per la durata in aria di un messaggio. Non sono
 * parametri perche' non dipendono dallo scenario: la velocita' e' quella delle
 * interfacce dei droni nel file di configurazione, le intestazioni e il
 * preambolo vengono dai protocolli e dallo standard 802.11.
 */
constexpr double RADIO_BITRATE   = 54e6;    // bit/s: velocita' della radio dei droni
constexpr double FRAME_OVERHEAD_B = 56.0;   // byte: IP 20 + UDP 8 + MAC 24 + sequenza di controllo 4
constexpr double PHY_PREAMBLE_S  = 20e-6;   // s: preambolo e campo SIGNAL della modulazione OFDM

/** Parametri del controllo, relativi al drone osservato. */
struct EnergyCheckParams
{
    double capacityJ = 3.0;     // capacita' della batteria del drone osservato
    double pMinW = 0.002;       // potenza minima della radio (ascolto)
    double pMaxW = 0.100;       // potenza massima della radio (trasmissione)
    double pRxW = 0.010;        // potenza della radio in ricezione
    double chargeW = 0.0;       // potenza del caricatore (0 = nessuna ricarica)
    double tolPct = 0.01;       // tolleranza in punti percentuali
    double windowS = 30.0;      // finestra W per il calo minimo
    double maxAgeS = 4.0;       // eta' massima del timbro: intervallo di misura + ritardo di rete
    double initialPct = -1;     // energia iniziale nota, -1 = non nota (predefinito)
    double chargeThresholdPct = -1; // soglia sotto cui il drone va a ricaricarsi, -1 = non nota
    // --- dati del traffico di protocollo, per il calo minimo ---
    double helloIntervalS = 5.0;  // intervallo fra due generazioni di FANT
    int networkNodes = 1;         // nodi della rete noti a chi controlla (1 = nessun traffico dedotto)
    double fantBytes = 80.0;      // dimensione del messaggio FANT (byte, senza intestazioni)
    double bantBytes = 161.0;     // dimensione del messaggio BANT (byte, senza intestazioni)
    double trafficMargin = 0.0;   // coefficiente di prudenza k: 0 = solo ascolto, 1 = traffico intero

    double minRate() const { return pMinW / capacityJ * 100.0; }   // %/s (solo ascolto)
    double maxRate() const { return pMaxW / capacityJ * 100.0; }   // %/s
    double chargeRate() const                                      // %/s netti alla stazione
    {
        double netto = chargeW - pMinW;
        return netto > 0 ? netto / capacityJ * 100.0 : 0.0;
    }

    /** Durata in aria (s) di un messaggio con payload di payloadBytes byte. */
    double airtime(double payloadBytes) const
    {
        return (payloadBytes + FRAME_OVERHEAD_B) * 8.0 / RADIO_BITRATE + PHY_PREAMBLE_S;
    }

    /** Generazioni di FANT che ogni nodo crea in dt secondi. */
    double generazioni(double dt) const
    {
        return helloIntervalS > 0 ? dt / helloIntervalS : 0.0;
    }

    /** Generazioni di FANT altrui che il nodo osservato riceve in dt secondi. */
    double generazioniAltrui(double dt) const
    {
        return (networkNodes > 1 ? networkNodes - 1 : 0) * generazioni(dt);
    }

    /**
     * Tempo (s) che il nodo deve avere passato in trasmissione in dt secondi:
     * due FANT propri per generazione, piu' una ritrasmissione e un BANT di
     * risposta per ogni generazione altrui ricevuta.
     */
    double txTime(double dt) const
    {
        double g = generazioni(dt), f = generazioniAltrui(dt);
        return 2.0 * g * airtime(fantBytes) + f * airtime(fantBytes) + f * airtime(bantBytes);
    }

    /** Tempo (s) che il nodo deve avere passato in ricezione in dt secondi. */
    double rxTime(double dt) const
    {
        return generazioniAltrui(dt) * airtime(fantBytes);
    }

    /**
     * Calo minimo (punti percentuali) su un intervallo di dt secondi: ascolto
     * per il tempo restante, piu' la parte di traffico ridotta dal coefficiente
     * di prudenza. Con trafficMargin = 0 restituisce minRate() * dt, cioe' il
     * comportamento precedente.
     */
    double minDrop(double dt) const
    {
        if (dt <= 0 || capacityJ <= 0)
            return 0.0;
        double tTx = txTime(dt), tRx = rxTime(dt);
        double tIdle = dt - trafficMargin * (tTx + tRx);
        if (tIdle < 0)
            tIdle = 0;
        double joule = pMinW * tIdle + trafficMargin * (pMaxW * tTx + pRxW * tRx);
        return joule / capacityJ * 100.0;
    }
};

/**
 * Tempo minimo (s) perche' l'energia passi da fromPct a toPct > fromPct con
 * una ricarica: discesa fino alla soglia al calo massimo, poi ricarica.
 * Restituisce un valore infinito se la ricarica non e' possibile.
 */
inline double tempoMinimoRicarica(double fromPct, double toPct, const EnergyCheckParams& p)
{
    if (p.chargeThresholdPct < 0 || p.chargeRate() <= 0 || p.maxRate() <= 0)
        return INFINITY;
    double avvio = std::min(fromPct, p.chargeThresholdPct);
    double discesa = (fromPct - avvio) / p.maxRate();
    double ricarica = (toPct - avvio) / p.chargeRate();
    return discesa + (ricarica > 0 ? ricarica : 0);
}

/** Una misura dichiarata dal drone, in un BANT o in una voce di traccia. */
struct EnergySample
{
    double t = -1;          // timbro di misura (s)
    double arrival = 0;     // istante di arrivo presso chi controlla (s)
    double pct = 0;         // energia dichiarata (%)
    bool atStation = false; // posizione dichiarata = stazione di ricarica
    // true se il messaggio arriva DIRETTAMENTE dal nodo che lo ha creato, cioe'
    // se chi lo ha messo sul canale e' anche chi lo ha firmato. Su un messaggio
    // inoltrato da terzi l'istante di arrivo misura il ritardo di inoltro della
    // rete e non la vecchiaia della lettura, quindi il controllo sull'eta' del
    // timbro non e' applicabile: un BANT puo' restare in coda per secondi prima
    // di essere ritrasmesso, e punire il mittente per quel ritardo significa
    // punirlo per la congestione del canale. Nel dubbio vale false, per non
    // condannare mai su un'informazione che non abbiamo verificato.
    bool diretto = false;
    std::string fonte = "BANT";  // da dove arriva la misura: "BANT" o "traccia"
};

enum class Esito { SUPERATO, VIOLATO, NON_APPLICABILE };

inline const char *esitoStr(Esito e)
{
    return e == Esito::SUPERATO ? "SUPERATO" : e == Esito::VIOLATO ? "VIOLATO" : "NON_APPLICABILE";
}

/** Risultato di uno dei controlli eseguiti su una misura. */
struct EnergyOutcome
{
    std::string controllo;  // nome del controllo (es. "calo minimo")
    Esito esito;
    std::string dettaglio;  // numeri del confronto, in chiaro
};

/** Una misura gia' vista, conservata per riconoscere le contraddizioni. */
struct TimbroNoto
{
    double t = -1;        // timbro
    double pct = 0;       // energia dichiarata con quel timbro
    std::string fonte;    // messaggio in cui era stata dichiarata
};

/** Quante misure recenti si conservano per il confronto sullo stesso timbro. */
constexpr size_t STORICO_TIMBRI = 8;

/** Stato conservato per ogni drone osservato. */
struct EnergyObservedState
{
    bool has = false;            // almeno una misura gia' vista
    EnergySample last;           // ultima misura
    bool refValid = false;       // misura di riferimento disponibile
    EnergySample ref;            // misura di riferimento per il calo minimo
    bool everAtStation = false;  // il drone e' mai stato alla stazione
    std::vector<TimbroNoto> storico;  // ultime misure viste, per timbro
};

namespace detail {
inline std::string fmt(double v, int dec = 3)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(dec) << v;
    return o.str();
}

/** Aggiunge una misura allo storico dei timbri, tenendo le piu' recenti. */
inline void ricordaMisura(EnergyObservedState& st, const EnergySample& s)
{
    for (auto& v : st.storico)
        if (std::abs(v.t - s.t) <= 1e-9)
            return;   // timbro gia' presente: il valore e' gia' stato confrontato
    st.storico.push_back({s.t, s.pct, s.fonte});
    if (st.storico.size() > STORICO_TIMBRI)
        st.storico.erase(st.storico.begin());
}
}

/**
 * Esegue i controlli della regola 1 su una nuova misura e aggiorna lo stato.
 * Restituisce l'elenco degli esiti (vuoto se non c'e' nulla da registrare).
 */
inline std::vector<EnergyOutcome> checkEnergy(EnergyObservedState& st, const EnergySample& s, const EnergyCheckParams& p)
{
    using detail::fmt;
    std::vector<EnergyOutcome> out;
    const double eps = 1e-9;

    // Il drone non ha ancora fatto nessuna misura (timbro -1): nulla da controllare.
    if (s.t < 0) {
        out.push_back({"timbro", Esito::NON_APPLICABILE, "BANT senza timbro (nessuna misura ancora fatta)"});
        return out;
    }

    // --- Passo 0: coerenza del timbro ---
    if (s.t > s.arrival + eps) {
        out.push_back({"coerenza del timbro", Esito::VIOLATO,
                       "timbro " + fmt(s.t) + " s successivo all'arrivo " + fmt(s.arrival) + " s"});
        return out;
    }
    // L'eta' del timbro si controlla solo sui messaggi arrivati direttamente da
    // chi li ha creati. Su un messaggio inoltrato, fra la lettura e l'arrivo
    // c'e' il tempo che il messaggio ha passato nelle code degli altri nodi, che
    // non dipende da chi lo ha scritto: un BANT creato al secondo 26 e
    // ritrasmesso da un vicino al secondo 33 sembrerebbe portare una lettura
    // vecchia di sette secondi pur essendo stato scritto appena letto il dato.
    // Il timbro nel futuro, controllato sopra, resta invece impossibile in ogni
    // caso e si continua a condannare.
    if (s.diretto && s.arrival - s.t > p.maxAgeS + eps) {
        out.push_back({"coerenza del timbro", Esito::VIOLATO,
                       "timbro " + fmt(s.t) + " s piu' vecchio dell'arrivo " + fmt(s.arrival) + " s di "
                       + fmt(s.arrival - s.t) + " s (massimo " + fmt(p.maxAgeS) + " s)"});
        return out;
    }
    if (!s.diretto && s.arrival - s.t > p.maxAgeS + eps) {
        out.push_back({"coerenza del timbro", Esito::NON_APPLICABILE,
                       "timbro " + fmt(s.t) + " s vecchio di " + fmt(s.arrival - s.t)
                       + " s all'arrivo, ma il messaggio e' stato inoltrato da un terzo:"
                       " il ritardo e' della rete, non della lettura"});
    }

    // --- Passo 0b: coerenza della misura ---
    // Lo stesso timbro e' la stessa lettura della batteria: il valore
    // dichiarato deve essere lo stesso, anche se le due dichiarazioni arrivano
    // da messaggi diversi (un BANT e una voce di traccia, o due BANT).
    for (const auto& v : st.storico) {
        if (std::abs(v.t - s.t) <= eps && std::abs(v.pct - s.pct) > p.tolPct) {
            out.push_back({"coerenza della misura", Esito::VIOLATO,
                           "timbro " + fmt(s.t) + " s dichiarato " + fmt(v.pct, 2) + "% in " + v.fonte
                           + " e " + fmt(s.pct, 2) + "% in " + s.fonte});
            return out;
        }
    }

    // --- Passo 1: misura nuova? ---
    if (st.has && std::abs(s.t - st.last.t) <= eps) {
        out.push_back({"misura", Esito::NON_APPLICABILE, "stesso timbro dell'ultima misura (" + fmt(s.t)
                       + " s): misura ripetuta, da " + s.fonte});
        return out;
    }
    if (st.has && s.t < st.last.t) {
        out.push_back({"misura", Esito::NON_APPLICABILE, "timbro " + fmt(s.t) + " s piu' vecchio dell'ultima misura ("
                       + fmt(st.last.t) + " s): arrivata in disordine, da " + s.fonte});
        return out;
    }

    // --- Passo 2: valore ammesso ---
    if (s.pct < -p.tolPct || s.pct > 100.0 + p.tolPct)
        out.push_back({"valore ammesso", Esito::VIOLATO, "energia " + fmt(s.pct, 2) + "% fuori da 0-100%"});

    // Ricarica non osservata? Si valuta qui perche' serve sia al passo 5 sia
    // ai passi 3 e 4. Con una misura precedente si parte da quella; per la
    // prima misura della GCS si parte dall'energia iniziale all'istante 0.
    bool ricaricaIpotizzata = false;
    std::string motivoRicarica;
    if (!s.atStation) {
        if (st.has && !st.last.atStation && s.pct - st.last.pct > p.tolPct) {
            double dt0 = s.t - st.last.t;
            double tmin = tempoMinimoRicarica(st.last.pct, s.pct, p);
            if (tmin <= dt0 + eps) {
                ricaricaIpotizzata = true;
                motivoRicarica = "possibile ricarica non osservata: da " + fmt(st.last.pct, 2) + "% (" + fmt(st.last.t)
                                 + " s) a " + fmt(s.pct, 2) + "% (" + fmt(s.t) + " s) servono almeno " + fmt(tmin, 1)
                                 + " s, ne sono passati " + fmt(dt0, 1);
            }
        }
        else if (!st.has && p.initialPct >= 0) {
            double tmin = tempoMinimoRicarica(p.initialPct, s.pct, p);
            if (s.pct > p.initialPct - p.minDrop(s.t) + p.tolPct && tmin <= s.t + eps) {
                ricaricaIpotizzata = true;
                motivoRicarica = "possibile ricarica non osservata: dall'energia iniziale " + fmt(p.initialPct, 2) + "% a "
                                 + fmt(s.pct, 2) + "% (" + fmt(s.t) + " s) servono almeno " + fmt(tmin, 1) + " s";
            }
        }
    }

    // --- Passo 5 (GCS): confronto con l'energia iniziale ---
    if (p.initialPct >= 0 && !st.everAtStation && !s.atStation) {
        double massimo = p.initialPct - p.minDrop(s.t) + p.tolPct;
        if (ricaricaIpotizzata)
            out.push_back({"energia iniziale", Esito::NON_APPLICABILE, motivoRicarica});
        else {
            Esito e = s.pct <= massimo ? Esito::SUPERATO : Esito::VIOLATO;
            out.push_back({"energia iniziale", e,
                           "dichiara " + fmt(s.pct, 2) + "% a " + fmt(s.t) + " s; iniziale " + fmt(p.initialPct, 2)
                           + "%, massimo ammesso " + fmt(massimo, 2) + "%"});
        }
    }

    if (!st.has) {
        // Prima misura del drone: viene solo memorizzata e diventa il
        // riferimento per il calo minimo.
        st.has = true;
        st.last = s;
        st.ref = s;
        st.refValid = !s.atStation;
        st.everAtStation = s.atStation || ricaricaIpotizzata;
        detail::ricordaMisura(st, s);
        return out;
    }

    // --- Passo 3: andamento rispetto all'ultima misura ---
    double dt = s.t - st.last.t;
    double salita = s.pct - st.last.pct;
    double calo = -salita;
    double caloMax = p.maxRate() * dt + p.tolPct;
    bool stazione = st.last.atStation || s.atStation;
    std::string base = "da " + fmt(st.last.pct, 2) + "% (" + fmt(st.last.t) + " s) a " + fmt(s.pct, 2) + "% ("
                       + fmt(s.t) + " s), dt " + fmt(dt) + " s";
    if (!stazione) {
        if (ricaricaIpotizzata)
            out.push_back({"andamento", Esito::NON_APPLICABILE, motivoRicarica});
        else if (salita > p.tolPct)
            out.push_back({"andamento", Esito::VIOLATO, base + ": energia salita fuori dalla stazione"});
        else if (calo > caloMax)
            out.push_back({"andamento", Esito::VIOLATO, base + ": calo " + fmt(calo, 3) + "% oltre il massimo " + fmt(caloMax, 3) + "%"});
        else
            out.push_back({"andamento", Esito::SUPERATO, base + ": calo " + fmt(calo, 3) + "% (massimo " + fmt(caloMax, 3) + "%)"});
    }
    else {
        double salitaMax = p.chargeRate() * dt + p.tolPct;
        if (salita > salitaMax)
            out.push_back({"andamento", Esito::VIOLATO, base + " alla stazione: salita " + fmt(salita, 3) + "% oltre il massimo di ricarica " + fmt(salitaMax, 3) + "%"});
        else if (calo > caloMax)
            out.push_back({"andamento", Esito::VIOLATO, base + " alla stazione: calo " + fmt(calo, 3) + "% oltre il massimo " + fmt(caloMax, 3) + "%"});
        else
            out.push_back({"andamento", Esito::SUPERATO, base + " alla stazione: variazione " + fmt(salita, 3) + "% (salita massima " + fmt(salitaMax, 3) + "%)"});
    }

    // --- Passo 4: calo minimo sulla finestra W ---
    if (ricaricaIpotizzata) {
        // dopo una possibile ricarica il riferimento riparte da questa misura
        st.ref = s;
        st.refValid = true;
    }
    else if (s.atStation || st.last.atStation) {
        // Il drone e' alla stazione (o ci e' appena stato): il calo minimo non
        // vale. Il riferimento riparte dalla prima misura fuori dalla stazione.
        st.refValid = false;
        if (st.last.atStation && !s.atStation) {
            st.ref = s;
            st.refValid = true;
        }
    }
    else if (st.refValid && s.t - st.ref.t >= p.windowS - eps) {
        double dtRef = s.t - st.ref.t;
        double caloRef = st.ref.pct - s.pct;
        double richiesto = p.minDrop(dtRef) - p.tolPct;
        Esito e = caloRef >= richiesto ? Esito::SUPERATO : Esito::VIOLATO;
        std::string traffico;
        if (p.trafficMargin > 0 && p.networkNodes > 1)
            traffico = " [ascolto " + fmt(p.pMinW * dtRef / p.capacityJ * 100.0, 3) + "%, traffico "
                       + fmt(p.trafficMargin * (p.pMaxW * p.txTime(dtRef) + p.pRxW * p.rxTime(dtRef)) / p.capacityJ * 100.0, 3)
                       + "% con " + std::to_string(p.networkNodes) + " nodi e k=" + fmt(p.trafficMargin, 2) + "]";
        out.push_back({"calo minimo", e,
                       "da " + fmt(st.ref.pct, 2) + "% (" + fmt(st.ref.t) + " s) a " + fmt(s.pct, 2) + "% (" + fmt(s.t)
                       + " s), dt " + fmt(dtRef) + " s: calo " + fmt(caloRef, 3) + "% (minimo " + fmt(richiesto, 3) + "%)"
                       + traffico});
        st.ref = s;
    }

    st.last = s;
    st.everAtStation = st.everAtStation || s.atStation || ricaricaIpotizzata;
    detail::ricordaMisura(st, s);
    return out;
}

} // namespace ant2energy
} // namespace inet

#endif
