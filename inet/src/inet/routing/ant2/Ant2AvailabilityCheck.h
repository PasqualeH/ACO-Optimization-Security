//
// Ant2AvailabilityCheck.h
//
// Regola 3 della metrica di trust: controllo sulla disponibilita' dichiarata
// dai droni nei BANT.
//
// Scritto come logica pura, senza dipendenze da OMNeT++ o da INET, cosi' la
// stessa funzione usata dal protocollo puo' essere verificata dai test
// automatici in test_controllo_disponibilita.cc.
//
// COSA CONTROLLA
// Nel codice la disponibilita' e' la variabile allowed_accept_request: se e'
// vera il drone puo' essere reclutato da chi chiede aiuto, e il suo valore
// entra nel calcolo del punteggio di reclutamento, perche' sendRecruiting()
// calcola il punteggio solo per i droni che risultano disponibili. Un
// attaccante che si dichiara sempre disponibile partecipa quindi a tutti i
// reclutamenti, e vincendone uno lascia senza aiuto un drone in difficolta'.
//
// A differenza di energia e posizione, la disponibilita' non viene riletta ogni
// uno-tre secondi: e' impostata all'inizio e cambia solo quando si verifica un
// evento. Nel codice attuale cambia in tre punti:
//
//   1. quando il drone accetta un REQ di reclutamento a lui destinato, dove
//      viene messa a falsa SUBITO, nello stesso istante in cui accetta, e non
//      un secondo dopo quando si sposta;
//   2. in moveUav_charge(), cioe' quando il drone parte per la stazione di
//      ricarica, nello stesso istante in cui cambia posizione;
//   3. a ricarica completata, quando viene ripristinato il valore che aveva
//      prima di andare alla stazione (preChargeAccept nel codice).
//
// Non torna mai vera dopo un reclutamento: il messaggio di congedo, che
// libererebbe il drone a fine aiuto, non e' implementato.
//
// COME SI STABILISCE LO STATO ATTESO
// Chi controlla non vede la variabile dentro il drone, ma puo' sapere quale
// dovrebbe essere, perche' ogni cambiamento e' legato a uno spostamento che la
// regola 2 sulla posizione verifica. Lo stato NON si stabilisce dall'arrivo del
// REQ: un REQ puo' non essere arrivato al drone, e punirlo per una richiesta
// che non ha ricevuto sarebbe ingiusto. Si stabilisce dallo spostamento
// confermato, che e' la prova che il REQ e' arrivato e che il drone lo ha
// accettato.
//
// Da questo segue una cosa comoda: non serve nessun margine di tolleranza
// temporale. La disponibilita' viene messa a falsa PRIMA dello spostamento (nel
// caso del reclutamento) o nello stesso istante (nel caso della ricarica),
// mentre il valore che viaggia in un BANT viene letto quando il BANT viene
// costruito, cioe' nell'istante del timbro o dopo. Quindi ogni BANT con timbro
// pari o successivo a quello della misura che mostra lo spostamento deve
// dichiarare disponibilita' falsa.
//
// LO STATO ATTESO E' L'ANCORA
// Lo stato atteso funziona come l'ancora della regola 2: avanza SOLO su uno
// spostamento verificato, mai su una dichiarazione del drone che lo contraddica.
// Quindi un drone che si dichiara disponibile dopo essere stato reclutato viola
// il controllo a OGNI BANT, e non una volta sola: la punizione dura quanto dura
// la bugia, e il numero di violazioni ne misura da se' la gravita'.
//
// Per la stessa ragione ogni dichiarazione coerente conta come controllo
// superato, e non soltanto la prima dopo un cambiamento di stato, come faceva la
// versione precedente. Non e' un esito gratuito: il riferimento e' esterno al
// drone, quindi chi mente non puo' superarlo. E porta il controllo a produrre un
// esito a ogni BANT invece di uno per reclutamento.
//
// GLI ESITI
//   SUPERATO        la disponibilita' dichiarata coincide con quella attesa
//   VIOLATO         il drone si dichiara disponibile quando non puo' esserlo:
//                   e' certo, perche' lo spostamento che lo ha reso impegnato
//                   o lo ha portato in ricarica e' stato verificato
//   NON_APPLICABILE il drone si dichiara non disponibile mentre chi controlla
//                   lo crede disponibile: puo' essere un drone onesto reso
//                   impegnato da un REQ che chi controlla non ha visto, quindi
//                   non si punisce. Oppure lo stato atteso non e' ancora noto,
//                   oppure la misura e' ripetuta o in disordine.
//
#ifndef __INET_ANT2AVAILABILITYCHECK_H
#define __INET_ANT2AVAILABILITYCHECK_H

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace ant2availability {

/** Stato in cui chi controlla crede che si trovi il drone osservato. */
enum class Stato {
    SCONOSCIUTO,     // nessuna dichiarazione ancora vista
    DISPONIBILE,     // puo' essere reclutato: deve dichiarare vero
    IMPEGNATO,       // reclutato e in aiuto a un altro drone: deve dichiarare falso
    IN_RICARICA,     // alla stazione di ricarica: deve dichiarare falso
    NON_DISPONIBILE  // si e' dichiarato non disponibile, ma chi controlla non ha
                     // osservato il motivo: puo' essere un drone non reclutabile
                     // per configurazione, oppure uno reclutato da un REQ che chi
                     // controlla non ha visto. Deve comunque dichiarare falso.
};

inline const char *statoStr(Stato s)
{
    switch (s) {
        case Stato::DISPONIBILE: return "disponibile";
        case Stato::IMPEGNATO: return "impegnato";
        case Stato::IN_RICARICA: return "in ricarica";
        case Stato::NON_DISPONIBILE: return "non disponibile (motivo non osservato)";
        default: return "sconosciuto";
    }
}

/** Una disponibilita' dichiarata in un BANT. */
struct AvailabilitySample
{
    double t = -1;            // timbro di misura, lo stesso di energia e posizione
    bool disponibile = false; // valore dichiarato
};

enum class Esito { SUPERATO, VIOLATO, DUBBIO, NON_APPLICABILE };

inline const char *esitoStr(Esito e)
{
    switch (e) {
        case Esito::SUPERATO: return "SUPERATO";
        case Esito::VIOLATO: return "VIOLATO";
        case Esito::DUBBIO: return "DUBBIO";
        default: return "NON_APPLICABILE";
    }
}

struct AvailabilityOutcome
{
    std::string controllo;
    Esito esito;
    std::string dettaglio;
};

/** Stato conservato per ogni drone osservato. */
struct AvailabilityObservedState
{
    Stato atteso = Stato::SCONOSCIUTO;
    bool has = false;             // almeno una dichiarazione vista
    double ultimoTimbro = -1;
    bool ultimaDichiarata = false;
    double istanteCambio = -1;    // timbro della misura che ha cambiato lo stato atteso
    // Valore atteso prima di andare in ricarica: a ricarica completata il codice
    // ripristina quello, quindi chi controlla deve ricordarselo.
    Stato attesoPrimaDellaRicarica = Stato::SCONOSCIUTO;
    bool primoDopoCambio = true;  // il prossimo esito va contato
    // true se lo stato atteso viene da uno spostamento verificato dalla regola
    // 2, false se e' stato dedotto da una dichiarazione del drone stesso. Nel
    // primo caso una contraddizione e' certa, nel secondo e' soltanto dubbia:
    // un drone potrebbe essersi ricaricato senza che chi controlla lo vedesse,
    // e al ritorno dalla stazione il codice ripristina la disponibilita'.
    bool statoVerificato = false;
};

namespace detail {
inline std::string fmt(double v, int dec = 3)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(dec) << v;
    return o.str();
}
}

/** Tipo della mossa confermata, tenuto separato per non dipendere dalla regola 2. */
enum class Mossa { NESSUNA, RECLUTAMENTO, ANDATA_STAZIONE, RITORNO_STAZIONE };

/**
 * Aggiorna lo stato atteso dopo uno spostamento che la regola 2 ha confermato.
 *
 * RECLUTAMENTO     il drone si e' spostato per andare ad aiutare: da ora e'
 *                  impegnato e non tornera' disponibile, perche' il congedo non
 *                  esiste nel protocollo
 * ANDATA_STAZIONE  il drone e' alla stazione: da ora e' in ricarica, e si
 *                  ricorda lo stato di prima per quando tornera'
 * RITORNO_STAZIONE la ricarica e' finita: si ripristina lo stato di prima, come
 *                  fa il codice con preChargeAccept
 *
 * timbro e' il timbro della misura che ha mostrato lo spostamento: da quel
 * momento ogni dichiarazione deve essere coerente con il nuovo stato.
 */
inline void aggiornaStato(AvailabilityObservedState& st, Mossa mossa, double timbro)
{
    switch (mossa) {
        case Mossa::RECLUTAMENTO:
            st.atteso = Stato::IMPEGNATO;
            st.istanteCambio = timbro;
            st.primoDopoCambio = true;
            st.statoVerificato = true;
            break;
        case Mossa::ANDATA_STAZIONE:
            if (st.atteso != Stato::IN_RICARICA)
                st.attesoPrimaDellaRicarica = st.atteso;
            st.atteso = Stato::IN_RICARICA;
            st.istanteCambio = timbro;
            st.primoDopoCambio = true;
            st.statoVerificato = true;
            break;
        case Mossa::RITORNO_STAZIONE:
            st.atteso = st.attesoPrimaDellaRicarica != Stato::SCONOSCIUTO
                        ? st.attesoPrimaDellaRicarica : Stato::DISPONIBILE;
            st.istanteCambio = timbro;
            st.primoDopoCambio = true;
            st.statoVerificato = true;
            break;
        default:
            break;
    }
}

/**
 * Esegue il controllo su una disponibilita' dichiarata.
 *
 * Gli esiti contati sono solo quelli che portano informazione: il primo dopo
 * ogni cambiamento di stato e quelli in cui il valore dichiarato cambia. In
 * tutti gli altri casi un drone onesto accumulerebbe centinaia di esiti
 * positivi e le poche violazioni non si vedrebbero nel totale.
 */
inline std::vector<AvailabilityOutcome> checkAvailability(AvailabilityObservedState& st,
                                                          const AvailabilitySample& s)
{
    using detail::fmt;
    std::vector<AvailabilityOutcome> out;
    const double eps = 1e-9;

    if (s.t < 0)
        return out;   // misura mai eseguita: la segnala la regola 1

    if (st.has && s.t < st.ultimoTimbro - eps)
        return out;   // dichiarazione arrivata in disordine: non aggiunge niente

    bool cambiata = !st.has || st.ultimaDichiarata != s.disponibile;
    bool ripetuta = st.has && std::abs(s.t - st.ultimoTimbro) <= eps;

    std::string dich = s.disponibile ? "disponibile" : "non disponibile";
    std::string quando = "timbro " + fmt(s.t) + " s, dichiarata " + dich
                         + ", attesa " + statoStr(st.atteso);

    // Il drone si dichiara disponibile mentre lo spostamento verificato dice
    // che e' impegnato o in ricarica: violazione certa, e va segnalata ogni
    // volta, perche' ogni BANT cosi' lo fa partecipare a un reclutamento.
    if (s.disponibile && st.atteso != Stato::DISPONIBILE && st.atteso != Stato::SCONOSCIUTO) {
        if (!ripetuta) {
            if (st.statoVerificato)
                out.push_back({"disponibilita'", Esito::VIOLATO,
                               quando + " dal timbro " + fmt(st.istanteCambio)
                               + " s, quando lo stato e' stato stabilito dallo spostamento verificato dalla regola 2"});
            else
                out.push_back({"disponibilita'", Esito::DUBBIO,
                               quando + " dal timbro " + fmt(st.istanteCambio)
                               + " s, dedotto da una sua dichiarazione e non da uno spostamento verificato:"
                               + " potrebbe essersi ricaricato senza che chi controlla lo vedesse"});
        }
    }
    else if (st.atteso == Stato::SCONOSCIUTO) {
        // Prima dichiarazione: non c'e' niente con cui confrontarla, si prende
        // per buona e diventa il riferimento. Chi controlla non conosce a priori
        // la configurazione dei droni.
        st.atteso = s.disponibile ? Stato::DISPONIBILE : Stato::NON_DISPONIBILE;
        st.istanteCambio = s.t;
        st.statoVerificato = false;
    }
    else if (!s.disponibile && st.atteso == Stato::DISPONIBILE) {
        // Si dichiara non disponibile mentre chi controlla lo crede
        // disponibile: puo' essere un drone onesto reso impegnato da un REQ che
        // chi controlla non ha visto. Non si punisce, e si adegua lo stato
        // atteso, cosi' se poi tornera' a dichiararsi disponibile la
        // contraddizione sara' sua.
        if (cambiata) {
            out.push_back({"disponibilita'", Esito::NON_APPLICABILE,
                           quando + ": possibile reclutamento non osservato da chi controlla"});
        }
        st.atteso = Stato::NON_DISPONIBILE;
        st.istanteCambio = s.t;
        st.primoDopoCambio = false;
        st.statoVerificato = false;
    }
    else if (s.disponibile && st.atteso == Stato::DISPONIBILE) {
        // Ogni dichiarazione coerente conta come controllo superato, non solo la
        // prima dopo un cambiamento. Il riferimento (lo stato atteso) non si
        // sposta quando il drone mente, quindi questo e' un confronto vero: un
        // drone che si dichiarasse disponibile dopo uno spostamento verificato
        // non potrebbe superarlo. Contarli tutti porta il controllo sulla
        // disponibilita' a produrre un esito a ogni BANT.
        if (!ripetuta) {
            out.push_back({"disponibilita'", Esito::SUPERATO, quando});
            st.primoDopoCambio = false;
        }
    }
    else if (!s.disponibile && st.atteso != Stato::DISPONIBILE) {
        if (!ripetuta) {
            out.push_back({"disponibilita'", Esito::SUPERATO, quando});
            st.primoDopoCambio = false;
        }
    }

    if (!ripetuta) {
        st.has = true;
        st.ultimoTimbro = s.t;
        st.ultimaDichiarata = s.disponibile;
    }
    return out;
}

}  // namespace ant2availability

#endif
