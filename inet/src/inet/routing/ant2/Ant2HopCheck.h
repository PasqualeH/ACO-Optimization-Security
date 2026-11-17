//
// Ant2HopCheck.h
//
// Regola 6 della metrica di trust: il numero di hop dichiarato.
//
// PERCHE' CONTA, E PIU' DI QUANTO SEMBRI
// --------------------------------------
// Il numero di hop dichiarato dentro un FANT o un BANT serve a due cose, e la
// seconda e' quella che rende questa regola importante.
//
// La prima e' il punteggio di reclutamento, dove compare come c1*(1/H). Li' il
// danno e' limitato, perche' nel codice H e' un int e 1/H e' una divisione fra
// interi: vale 1 per H=1 e ZERO per qualunque H>=2. L'unica menzogna che paga,
// in quel termine, e' dichiarare di essere a un hop.
//
// La seconda e' l'instradamento, ed e' la parte grossa. Ogni volta che arriva un
// FANT o un BANT nuovo, il nodo aumenta il feromone della riga "per raggiungere
// la destinazione D passa dal vicino V" di 100.0/numHops, dove numHops e' il
// valore dichiarato nel pacchetto. Li' la divisione e' reale, quindi un nodo che
// dichiara un hop invece di tre si prende 100 punti invece di 33. Il feromone
// decade del 20% ogni cinque secondi e ogni cinque secondi computeBestNextHops()
// elegge come prossimo salto quello con il feromone piu' alto: mentire in
// continuazione significa diventare il passaggio obbligato per il traffico
// altrui. E' la costruzione di un SINKHOLE, cioe' il preludio classico di un
// attacco blackhole o greyhole, in cui il traffico attratto viene poi scartato o
// alterato.
//
// Questa regola protegge quindi l'instradamento, non solo il reclutamento.
//
// I DUE CONTROLLI
// ---------------
// 1) CONTROLLO LOCALE, certo ed esatto, a costo zero.
//    Chi riceve un messaggio sa due cose indipendenti: chi gliel'ha trasmesso
//    sul canale radio, e chi l'ha creato, che e' nel campo firmato. Se chi
//    trasmette coincide con chi ha creato, quel messaggio e' al suo primo
//    passaggio e il numero di hop dichiarato DEVE essere 1. Se chi trasmette e'
//    un altro, il messaggio ha gia' fatto almeno un salto e il numero dichiarato
//    DEVE essere almeno 2. Non ci sono tolleranze, non dipende dalla topologia e
//    non costa un byte di traffico.
//    La colpa e' sempre di CHI TRASMETTE, non di chi ha creato il messaggio:
//    l'hop va incrementato da chi inoltra, quindi un valore sbagliato in un
//    messaggio inoltrato e' responsabilita' dell'ultimo che l'ha toccato.
//
// 2) CONTROLLO SULLA CATENA DELLE TRACCE, dalla sola GCS.
//    In una traccia ogni nodo attraversato scrive la propria voce con l'hop con
//    cui l'ha ricevuta. Nella catena la voce in posizione i deve quindi riportare
//    i+1. Una discrepanza e' CERTA, ma l'attribuzione no: se due voci consecutive
//    riportano lo stesso numero, puo' essere che la seconda non abbia
//    incrementato, oppure che la prima abbia riportato male quello che aveva
//    ricevuto. Per questo la coppia viene marcata come sospetta e la colpa si
//    attribuisce per ACCUMULO su piu' giri: il colpevole compare in tutte le
//    coppie sospette che lo riguardano, mentre un innocente ci finisce solo
//    quando gli capita di stare accanto al colpevole.
//
// Qui dentro c'e' solo la logica, senza OMNeT++ e senza INET, cosi' i test
// automatici possono verificarla da sola.
//
#ifndef __INET_ANT2HOPCHECK_H
#define __INET_ANT2HOPCHECK_H

#include <cstdint>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ant2hop {

enum class Esito { SUPERATO, VIOLATO, DUBBIO, NON_APPLICABILE };

inline const char *esitoStr(Esito e)
{
    switch (e) {
        case Esito::SUPERATO:        return "SUPERATO";
        case Esito::VIOLATO:         return "VIOLATO";
        case Esito::DUBBIO:          return "DUBBIO";
        case Esito::NON_APPLICABILE: return "NON_APPLICABILE";
        default: return "?";
    }
}

struct HopCheckParams {
    // Quante coppie sospette servono prima di accusare un nodo con la catena
    // delle tracce. Sotto questa soglia resta un dubbio.
    long minCoppieSospette = 5;
    // E quale frazione delle catene in cui compare deve essere sospetta.
    double sogliaRapporto = 0.5;
    // Quanti VICINI DIVERSI devono essere coinvolti. E' la condizione che
    // distingue il colpevole dalla vittima, ed e' spiegata sotto.
    size_t minPartnerDistinti = 2;
};

/**
 * Chi e' il colpevole dentro una coppia sospetta?
 *
 * Nel protocollo un nodo riceve la traccia con un certo valore, lo scrive nella
 * propria voce e poi lo incrementa prima di inoltrarla. Se un nodo NON
 * incrementa, il valore sbagliato finisce nella voce del nodo SUCCESSIVO, che
 * ha riportato onestamente quello che ha ricevuto. Guardando una coppia sola
 * i due casi sono indistinguibili:
 *   (a) il precedente non ha incrementato, e il successivo e' una vittima;
 *   (b) il successivo ha scritto un valore piu' basso di quello ricevuto.
 *
 * Su molte catene pero' le due firme sono diverse, ed e' questo che permette di
 * attribuire la colpa. Chi non incrementa rovina il conteggio di TUTTI i vicini
 * che gli capitano dietro, quindi compare come precedente insieme a piu'
 * successori diversi. Chi invece mente sulla propria voce sbaglia chiunque lo
 * preceda, quindi compare come successivo insieme a piu' predecessori diversi.
 * Una vittima, al contrario, compare sempre accanto allo stesso nodo: il
 * colpevole.
 *
 * E' esattamente quello che si e' visto in simulazione: l'attaccante compariva
 * come precedente in diciotto coppie con due successori diversi, mentre i suoi
 * due vicini comparivano solo come successivi e solo accanto a lui. Con il solo
 * rapporto fra coppie sospette e catene attraversate venivano accusati anche
 * loro, perche' il rapporto era quasi identico.
 */
struct HopObservedState {
    // Controllo locale
    long superati = 0, violati = 0;
    // Catena delle tracce
    long coppieSospette = 0;     // in quante coppie sospette compare, in totale
    long comePrecedente = 0, comeSuccessivo = 0;
    std::set<std::string> successoriSospetti;    // chi lo segue nelle coppie sospette
    std::set<std::string> predecessoriSospetti;  // chi lo precede nelle coppie sospette
    long catene = 0;             // in quante catene compare
    bool accusato = false;       // gia' accusato: non si accusa due volte
};

/** Ruolo di un nodo dentro una coppia sospetta. */
enum class Ruolo { PRECEDENTE, SUCCESSIVO };

inline void annotaCoppiaSospetta(HopObservedState& st, Ruolo ruolo, const std::string& partner)
{
    st.coppieSospette++;
    if (ruolo == Ruolo::PRECEDENTE) {
        st.comePrecedente++;
        st.successoriSospetti.insert(partner);
    }
    else {
        st.comeSuccessivo++;
        st.predecessoriSospetti.insert(partner);
    }
}

struct HopOutcome {
    std::string controllo;
    Esito esito = Esito::NON_APPLICABILE;
    std::string dettaglio;
};

namespace detail {
inline std::string num(long v)
{
    char b[32];
    std::snprintf(b, sizeof(b), "%ld", v);
    return b;
}
inline std::string perc(double v)
{
    char b[32];
    std::snprintf(b, sizeof(b), "%.0f%%", v * 100.0);
    return b;
}
}

// ---------------------------------------------------------------------------
// 1) Controllo locale: certo
// ---------------------------------------------------------------------------

/**
 * @param dichiarato            il campo hopdistance del messaggio
 * @param trasmittenteEIlCreatore  vero se chi ha trasmesso il messaggio sul
 *                              canale e' anche chi lo ha creato e firmato
 *
 * L'esito riguarda CHI TRASMETTE, perche' e' lui che avrebbe dovuto scrivere
 * il valore giusto.
 */
inline std::vector<HopOutcome> checkHopLocale(HopObservedState& st, int dichiarato,
                                              bool trasmittenteEIlCreatore,
                                              const HopCheckParams& /*p*/)
{
    std::vector<HopOutcome> out;
    HopOutcome o;
    o.controllo = "hop dichiarati";

    if (dichiarato <= 0) {
        // Un hop non positivo non ha senso in nessun caso.
        o.esito = Esito::VIOLATO;
        o.dettaglio = "dichiara " + detail::num(dichiarato) + " hop, che non e' un valore possibile";
        st.violati++;
        out.push_back(o);
        return out;
    }

    if (trasmittenteEIlCreatore) {
        if (dichiarato == 1) {
            o.esito = Esito::SUPERATO;
            o.dettaglio = "messaggio ricevuto direttamente dal suo creatore e dichiarato a 1 hop";
            st.superati++;
        }
        else {
            o.esito = Esito::VIOLATO;
            o.dettaglio = "ha creato e trasmesso lui stesso il messaggio, quindi e' a 1 hop, ma ne dichiara "
                        + detail::num(dichiarato);
            st.violati++;
        }
    }
    else {
        if (dichiarato >= 2) {
            o.esito = Esito::SUPERATO;
            o.dettaglio = "messaggio inoltrato e dichiarato a " + detail::num(dichiarato) + " hop";
            st.superati++;
        }
        else {
            o.esito = Esito::VIOLATO;
            o.dettaglio = "sta inoltrando un messaggio creato da un altro, quindi gli hop sono almeno 2,"
                          " ma ne dichiara 1: non ha incrementato il contatore";
            st.violati++;
        }
    }
    out.push_back(o);
    return out;
}

// ---------------------------------------------------------------------------
// 2) Catena delle tracce
// ---------------------------------------------------------------------------

struct VoceCatena {
    uint32_t nodo = 0;
    int hopRicevuto = 0;
};

struct CoppiaSospetta {
    uint32_t precedente = 0, successivo = 0;
    int posizione = 0;      // indice della seconda voce nella catena
    int atteso = 0, trovato = 0;
};

/**
 * La voce in posizione i deve riportare i+1. Dove non succede, la coppia
 * (i-1, i) e' sospetta: uno dei due ha sbagliato, e da una catena sola non si
 * puo' dire quale.
 */
inline std::vector<CoppiaSospetta> analizzaCatena(const std::vector<VoceCatena>& voci)
{
    std::vector<CoppiaSospetta> out;
    for (size_t i = 1; i < voci.size(); i++) {
        int atteso = (int)i + 1;
        if (voci[i].hopRicevuto == atteso)
            continue;
        CoppiaSospetta c;
        c.precedente = voci[i - 1].nodo;
        c.successivo = voci[i].nodo;
        c.posizione = (int)i;
        c.atteso = atteso;
        c.trovato = voci[i].hopRicevuto;
        out.push_back(c);
    }
    return out;
}

/**
 * Verdetto finale sulla catena, da emettere a fine simulazione.
 *
 * Un nodo viene accusato quando compare in abbastanza coppie sospette E quando
 * quelle coppie sono una frazione rilevante delle catene in cui compare. Le due
 * condizioni insieme distinguono il colpevole dal vicino sfortunato: il primo
 * sbaglia tutte le volte, il secondo solo quando gli capita di stare accanto a
 * lui.
 */
inline std::vector<HopOutcome> verdettoCatena(HopObservedState& st, const HopCheckParams& p)
{
    std::vector<HopOutcome> out;
    if (st.catene == 0 || st.coppieSospette == 0 || st.accusato)
        return out;

    double rapporto = (double)st.coppieSospette / (double)st.catene;
    HopOutcome o;
    o.controllo = "hop nelle tracce";
    std::string base = "compare in " + detail::num(st.coppieSospette)
                     + " coppie sospette su " + detail::num(st.catene)
                     + " catene attraversate (" + detail::perc(rapporto) + ")";

    bool abbastanza = st.coppieSospette >= p.minCoppieSospette && rapporto >= p.sogliaRapporto;
    // Chi non incrementa rovina il conteggio di piu' vicini diversi; chi mente
    // sulla propria voce sbaglia dietro a piu' predecessori diversi. Una
    // vittima compare sempre accanto allo stesso nodo, ed e' questa la
    // condizione che la salva dall'accusa.
    bool nonIncrementa = st.comePrecedente >= p.minCoppieSospette
                      && st.successoriSospetti.size() >= p.minPartnerDistinti;
    bool menteSullaPropriaVoce = st.comeSuccessivo >= p.minCoppieSospette
                      && st.predecessoriSospetti.size() >= p.minPartnerDistinti;

    if (abbastanza && (nonIncrementa || menteSullaPropriaVoce)) {
        o.esito = Esito::VIOLATO;
        o.dettaglio = base + (nonIncrementa
            ? ": compare come precedente con " + detail::num((long)st.successoriSospetti.size())
              + " vicini diversi, quindi e' lui a non incrementare il contatore quando inoltra"
            : ": compare come successivo dietro " + detail::num((long)st.predecessoriSospetti.size())
              + " vicini diversi, quindi e' lui a scrivere un valore piu' basso di quello ricevuto");
        st.violati++;
        st.accusato = true;
    }
    else {
        o.esito = Esito::DUBBIO;
        size_t partner = st.successoriSospetti.size() + st.predecessoriSospetti.size();
        o.dettaglio = base + (partner <= 1
            ? ": compare sempre accanto allo stesso vicino, quindi e' piu' probabile che sia la"
              " vittima di quel vicino che il colpevole"
            : ": troppo poco per attribuire la colpa");
    }
    out.push_back(o);
    return out;
}

}   // namespace ant2hop

#endif
