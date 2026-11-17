//
// Ant2BandCheck.h
//
// Regola 5 della metrica di trust: controllo sulla banda massima dichiarata.
//
// Scritto come logica pura, senza dipendenze da OMNeT++ o da INET, cosi' la
// stessa funzione usata dal protocollo puo' essere verificata dai test
// automatici in test_controllo_banda.cc.
//
// COSA CONTROLLA
// La banda massima di un drone e' il parametro max_band di Ant2, in Mbit/s, e
// corrisponde alla capacita' del collegamento fra il drone e la propria cella
// 5G: nello scenario vale 0,40 Mbit/s. Nel codice viene letta una volta
// all'avvio e non cambia mai piu'. Il drone la dichiara in ogni BANT, nella
// parte cifrata e firmata, e chi riceve la scrive nella propria tabella di stato
// sostituendo il valore precedente senza nessun controllo.
//
// Conta perche' entra nel punteggio di reclutamento nel termine della banda
// libera, c4 * (1 - T / M_T) * (M_T / 1), dove T e' il throughput dichiarato e
// M_T la banda massima dichiarata: piu' alta e' la banda massima dichiarata,
// piu' alto e' il punteggio. L'attacco attackFalseMetrics la dichiara doppia.
// Nel codice il peso c4 vale 1,25 invece di 0,25 come nel paper, quindi questo
// termine pesa cinque volte piu' degli altri tre: mentire sulla banda massima e'
// l'inganno piu' redditizio fra quelli sui valori dichiarati.
//
// I DUE CONTROLLI
//
// 1. La banda massima non cambia. Un drone onesto dichiara sempre il valore
//    della configurazione. Chi controlla memorizza la prima banda massima che
//    vede dichiarare da ogni drone osservato e la confronta con quella dei BANT
//    successivi: se cambia, la violazione e' certa. Costa una sola memoria in
//    piu' per drone osservato, e si conta solo al primo BANT e a ogni
//    cambiamento, altrimenti si accumulerebbe un esito positivo per BANT.
//
//    Questo controllo non coglie chi mente sempre allo stesso modo dal primo
//    messaggio. Non si usa la strada della GCS che conosce la configurazione
//    della missione, per la stessa ragione per cui e' stato disattivato il
//    controllo sull'energia iniziale: chi controlla non ha quei dati e non deve
//    fingere di averli.
//
// 2. Coerenza con la richiesta d'aiuto: PROVATA E SCARTATA.
//
//    L'idea era questa. Nel codice un drone chiede aiuto quando il proprio
//    throughput raggiunge l'85% della propria banda massima, oppure quando
//    l'energia scende sotto il 15%. Osservare un REQ inviato da un drone
//    significa quindi sapere che una delle due condizioni era vera in quel
//    momento, e le due grandezze sono entrambe dichiarate da lui nei BANT:
//    bastava verificare che le dichiarazioni fossero compatibili con la
//    richiesta. Un drone che dichiara la banda massima doppia alza la propria
//    soglia da 0,34 a 0,68 Mbps e si contraddirebbe nel momento in cui chiede
//    aiuto.
//
//    La prova in simulazione l'ha smentita, e il motivo e' interessante.
//    node_throughput viene ricalcolato a ogni misura sull'intervallo trascorso,
//    e la soglia viene superata da un picco di breve durata. Il BANT che
//    porterebbe quel picco spesso non arriva a nessuno, perche' il drone che ha
//    un picco di traffico e' esattamente quello che ha la coda piena e perde i
//    propri messaggi. Nella configurazione TestBandaOnesta adh[0] ha chiesto
//    aiuto a 11,865 s con un throughput di 0,37 Mbps, ma i valori che i suoi
//    BANT hanno portato agli osservatori sono 0,044 al timbro 10,579 s e 0,042
//    al timbro 15,099 s: la misura con 0,37 non e' arrivata a nessuno, e fra i
//    due timbri c'e' un buco di 4,5 secondi, piu' dell'intervallo massimo fra
//    due misure. Il controllo segnalava quindi come bugiardi otto droni onesti.
//
//    Nemmeno la versione aggregata funziona: il massimo throughput che i droni
//    onesti dichiarano in tutta la simulazione resta sotto la soglia (0,30 Mbps
//    per adh[3] e adh[4] contro una soglia di 0,34), quindi "non ha mai
//    raggiunto la soglia" non e' una prova di menzogna.
//
//    Il risultato negativo e' in se' un dato sull'osservabilita' del protocollo:
//    il throughput che innesca la richiesta d'aiuto non e' osservabile da terzi,
//    perche' e' un picco e perche' chi lo ha non riesce a farlo sapere. Resta
//    quindi scoperto il mentitore costante sulla banda massima, e coprirlo
//    richiederebbe la conoscenza a priori della configurazione, che e' stata
//    esclusa per coerenza con la scelta fatta sull'energia iniziale.
//
#ifndef __INET_ANT2BANDCHECK_H
#define __INET_ANT2BANDCHECK_H

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace ant2band {

enum class Esito { SUPERATO, VIOLATO, NON_APPLICABILE };

inline const char *esitoStr(Esito e)
{
    switch (e) {
        case Esito::SUPERATO: return "SUPERATO";
        case Esito::VIOLATO: return "VIOLATO";
        default: return "NON_APPLICABILE";
    }
}

struct BandOutcome
{
    std::string controllo;
    Esito esito;
    std::string dettaglio;
};

/** Una misura dichiarata in un BANT, nei tre valori che servono a questa regola. */
struct BandSample
{
    double t = -1;          // timbro di misura
    double maxBand = 0;     // banda massima dichiarata (Mbps)
    double throughput = 0;  // throughput dichiarato (Mbps)
    double energia = -1;    // energia dichiarata (%)
};

struct BandCheckParams
{
    double tolMbps = 1e-6;   // tolleranza sul confronto fra due bande massime
};

struct BandObservedState
{
    bool has = false;
    double prima = 0;          // prima banda massima dichiarata
    double primaT = -1;
    double ultima = 0;         // ultima banda massima dichiarata
};

namespace detail {
inline std::string fmt(double v, int dec = 3)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(dec) << v;
    return o.str();
}
}

/**
 * La banda massima dichiarata non deve cambiare.
 * Si conta solo al primo BANT di ogni drone e a ogni cambiamento.
 */
inline std::vector<BandOutcome> checkBand(BandObservedState& st, const BandSample& s,
                                          const BandCheckParams& p)
{
    using detail::fmt;
    std::vector<BandOutcome> out;
    if (s.t < 0)
        return out;

    if (!st.has) {
        st.has = true;
        st.prima = s.maxBand;
        st.primaT = s.t;
        st.ultima = s.maxBand;
        out.push_back({"banda massima", Esito::SUPERATO,
                       "prima dichiarazione: " + fmt(s.maxBand) + " Mbps al timbro " + fmt(s.t)
                       + " s, diventa il riferimento"});
        return out;
    }
    if (std::abs(s.maxBand - st.ultima) <= p.tolMbps)
        return out;   // valore invariato: niente da contare

    out.push_back({"banda massima", Esito::VIOLATO,
                   "dichiarava " + fmt(st.prima) + " Mbps dal timbro " + fmt(st.primaT)
                   + " s e ora dichiara " + fmt(s.maxBand) + " Mbps al timbro " + fmt(s.t)
                   + " s: la banda massima di un drone non cambia mai"});
    st.ultima = s.maxBand;
    return out;
}

}  // namespace ant2band

#endif
