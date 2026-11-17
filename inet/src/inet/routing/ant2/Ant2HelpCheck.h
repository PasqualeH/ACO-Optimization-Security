//
// Ant2HelpCheck.h
//
// Regola 4 della metrica di trust: controllo sul falso aiuto.
//
// Scritto come logica pura, senza dipendenze da OMNeT++ o da INET, cosi' la
// stessa funzione usata dal protocollo puo' essere verificata dai test
// automatici in test_controllo_falso_aiuto.cc.
//
// COSA CONTROLLA
// A differenza delle regole precedenti questa non verifica un valore dichiarato
// ma un comportamento: il drone che ha vinto il reclutamento e' andato davvero
// a prestare aiuto, oppure ha lasciato il drone in difficolta' senza aiuto?
// E' l'attacco piu' dannoso del protocollo, perche' nel codice attuale chi ha
// chiesto aiuto non riceve nessuna conferma e non puo' richiederlo una seconda
// volta: se il vincitore non si presenta, il drone in difficolta' resta con la
// banda satura fino alla fine della missione.
//
// SU COSA SI APPOGGIA
// Su due cose che chi controlla ha gia', senza aggiungere nessun dato alla rete:
//
//   1. il REQ di reclutamento, annotato nel registro degli eventi della regola
//      2 sulla posizione. Dice chi ha chiesto aiuto, chi ha vinto e dove si
//      trovava chi ha chiesto aiuto, tutti campi firmati;
//   2. l'esito della regola 2 su quel drone: se lo spostamento verso chi ha
//      chiesto aiuto e' stato confermato, l'aiuto e' partito.
//
// La verifica geometrica non viene rifatta qui. Nella formalizzazione iniziale
// il controllo guardava se il BANT mostrava il drone "fra 40 e 250 metri da chi
// ha chiesto aiuto": quel criterio e' stato sostituito nella regola 2 dalla
// sfera di raggio recruitRadius centrata in (px + offset, py + offset), perche'
// l'intervallo di distanza lascia passare uno spostamento nella direzione
// opposta. Qui si riusa direttamente la conferma della regola 2, cosi' il
// criterio resta uno solo e non puo' divergere.
//
// L'ISTANTE LIMITE
// Il REQ non porta un timbro, quindi chi controlla usa l'istante in cui lo ha
// ricevuto, t_R. Il vincitore puo' averlo ricevuto fino a D secondi piu' tardi,
// dove D e' il ritardo massimo di rete, e si sposta recruitMoveDelay secondi
// dopo averlo ricevuto. L'istante limite e' quindi
//
//      istanteLimite = t_R + D + recruitMoveDelay
//
// Un BANT con timbro precedente non dice niente, perche' il drone potrebbe non
// avere ancora ricevuto il REQ o non essersi ancora spostato. Dal primo BANT
// con timbro pari o successivo all'istante limite il comportamento deve essere
// visibile, e il controllo si esegue una volta sola per ogni reclutamento.
//
// GLI ESITI
//   SUPERATO        lo spostamento verso chi ha chiesto aiuto e' confermato
//   VIOLATO         il drone si e' dichiarato impegnato ma non si e' spostato:
//                   si comporta come se avesse accettato e non presta aiuto
//   DUBBIO          non si e' spostato e continua a dichiararsi disponibile:
//                   puo' avere ignorato il REQ di proposito, ma puo' anche non
//                   averlo mai ricevuto per una collisione
//   NON_APPLICABILE il drone non poteva accettare, oppure e' andato a
//                   ricaricarsi, oppure e' impegnato in un altro reclutamento,
//                   oppure il suo spostamento e' gia' segnalato dalla regola 2
//
#ifndef __INET_ANT2HELPCHECK_H
#define __INET_ANT2HELPCHECK_H

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace ant2help {

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

struct HelpOutcome
{
    std::string controllo;
    Esito esito;
    std::string dettaglio;
};

/** Parametri del controllo. */
struct HelpCheckParams
{
    double maxNetworkDelay = 3.0;   // D
    double recruitMoveDelay = 1.0;  // ritardo fra la ricezione del REQ e lo spostamento
    double attesaMaxS = 60.0;       // oltre questa attesa la verifica viene abbandonata
};

/**
 * Un reclutamento in attesa di verifica. Viene creato quando chi controlla
 * annota un REQ di reclutamento, e risolto al primo BANT del vincitore con
 * timbro pari o successivo all'istante limite.
 */
struct Pending
{
    uint32_t drone = 0;         // il vincitore, di cui si verifica il comportamento
    uint32_t richiedente = 0;   // chi ha chiesto aiuto
    double tReq = 0;            // istante in cui chi controlla ha ricevuto il REQ
    double istanteLimite = 0;   // t_R + D + recruitMoveDelay
    unsigned int seq = 0;
    // Stato atteso del vincitore nell'istante del REQ, letto dalla regola 3.
    // Se non era disponibile, un drone onesto ignora il REQ e non c'e' niente
    // da verificare: la colpa e' di chi lo ha scelto su dati vecchi, oppure il
    // drone ha mentito sulla disponibilita' ed e' gia' punito dalla regola 3.
    bool disponibileAlReq = true;
    // L'attesa nasce da un REQ che chi controlla ha osservato di persona,
    // oppure da uno che gli ha riferito la GCS nel bollettino?
    //
    // La distinzione e' decisiva, e la prova con tutte le regole insieme l'ha
    // mostrata: un REQ riferito dalla GCS riguarda per definizione un episodio
    // che chi controlla NON ha visto, spesso concluso da parecchi secondi. Chi
    // controlla non ha quindi nessun motivo di credere che avrebbe visto lo
    // spostamento, se c'e' stato, e non puo' concluderne che non sia avvenuto.
    // Una prova di seconda mano puo' SCAGIONARE - giustificando uno spostamento
    // nella regola 2, o spiegando perche' il drone ha legittimamente ignorato
    // la richiesta - ma non puo' accusare: al massimo lascia un dubbio.
    bool daSecondaMano = false;
    // Riempiti dalla regola 2 sulla posizione mentre l'attesa e' aperta.
    bool spostamentoConfermato = false;  // si e' spostato verso chi ha chiesto aiuto
    bool spostamentoAnomalo = false;     // la regola 2 ha segnalato il suo spostamento
    bool risolto = false;
};

/** Quello che le altre regole sanno del drone nell'istante del controllo. */
struct Contesto
{
    bool allaStazione = false;          // la posizione dichiarata e' la stazione di ricarica
    bool disponibileDichiarata = true;  // disponibilita' dichiarata nel BANT in esame
};

namespace detail {
inline std::string fmt(double v, int dec = 3)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(dec) << v;
    return o.str();
}
}

/** Crea l'attesa di verifica per un REQ di reclutamento appena annotato. */
inline Pending nuovaAttesa(uint32_t drone, uint32_t richiedente, double tReq, unsigned int seq,
                           bool disponibileAlReq, const HelpCheckParams& p,
                           bool daSecondaMano = false)
{
    Pending a;
    a.daSecondaMano = daSecondaMano;
    a.drone = drone;
    a.richiedente = richiedente;
    a.tReq = tReq;
    a.istanteLimite = tReq + p.maxNetworkDelay + p.recruitMoveDelay;
    a.seq = seq;
    a.disponibileAlReq = disponibileAlReq;
    return a;
}

/**
 * Segnala l'esito della regola 2 su uno spostamento del drone, mentre una
 * verifica e' aperta. confermato indica che la regola 2 ha riconosciuto lo
 * spostamento verso chi ha chiesto aiuto; anomalo indica che ha segnalato una
 * violazione o un dubbio, caso in cui questa regola si astiene per non punire
 * due volte lo stesso fatto.
 */
inline void segnalaSpostamento(std::vector<Pending>& attese, uint32_t drone,
                               uint32_t richiedente, bool confermato, bool anomalo)
{
    for (auto& a : attese) {
        if (a.risolto || a.drone != drone)
            continue;
        if (confermato && a.richiedente == richiedente)
            a.spostamentoConfermato = true;
        if (anomalo)
            a.spostamentoAnomalo = true;
    }
}

/**
 * Esegue le verifiche scadute per un drone, al ricevere di un suo BANT.
 *
 * attese  elenco delle verifiche aperte, aggiornato dalla funzione
 * drone    il drone di cui e' arrivato il BANT
 * timbro   timbro della misura contenuta nel BANT
 * c        quello che le altre regole sanno del drone in questo momento
 */
inline std::vector<HelpOutcome> checkHelp(std::vector<Pending>& attese, uint32_t drone,
                                          double timbro, const Contesto& c,
                                          const HelpCheckParams& p)
{
    using detail::fmt;
    std::vector<HelpOutcome> out;
    if (timbro < 0)
        return out;

    for (auto& a : attese) {
        if (a.risolto || a.drone != drone)
            continue;
        if (timbro + 1e-9 < a.istanteLimite)
            continue;   // troppo presto: il drone potrebbe non essersi ancora spostato

        a.risolto = true;
        std::string quando = "reclutato dal REQ ricevuto a " + fmt(a.tReq)
                             + " s, verificato al timbro " + fmt(timbro)
                             + " s (limite " + fmt(a.istanteLimite) + " s)";

        if (a.spostamentoConfermato) {
            out.push_back({"falso aiuto", Esito::SUPERATO,
                           quando + ": spostamento verso chi ha chiesto aiuto confermato dalla regola 2"});
            continue;
        }
        if (!a.disponibileAlReq) {
            out.push_back({"falso aiuto", Esito::NON_APPLICABILE,
                           quando + ": nell'istante del REQ non risultava disponibile, quindi un drone"
                           " onesto lo ignora; se si era dichiarato disponibile senza esserlo lo segnala la regola 3"});
            continue;
        }
        // Reclutamento precedente ancora in corso. Capita quando due droni
        // chiedono aiuto a poca distanza di tempo e scelgono lo stesso
        // vincitore, perche' il secondo lo vede ancora disponibile nella propria
        // tabella: il drone accetta il primo e RIFIUTA il secondo limitandosi a
        // inoltrarlo, come prevede il codice. Non si puo' quindi chiedergli di
        // prestare aiuto anche al secondo. Lo stato atteso della regola 3 non
        // basta a riconoscerlo, perche' viene stabilito dallo spostamento
        // confermato, che chi controlla osserva piu' tardi dell'arrivo del REQ:
        // la prova sta nel registro, dove il reclutamento precedente c'e' gia'.
        // Basta che il reclutamento precedente esista: dall'istante in cui il
        // suo REQ e' arrivato il drone non era piu' selezionabile, quindi avere
        // vinto di nuovo e' un errore di chi ha scelto su dati vecchi e non una
        // colpa del drone. Il reclutamento precedente resta verificato per conto
        // proprio, quindi se e' quello che il drone non ha onorato viene contato
        // una volta, lì, e non due.
        const Pending *precedente = nullptr;
        for (auto& b : attese)
            if (&b != &a && b.drone == drone && b.tReq < a.tReq)
                if (precedente == nullptr || b.tReq > precedente->tReq)
                    precedente = &b;
        if (precedente) {
            out.push_back({"falso aiuto", Esito::NON_APPLICABILE,
                           quando + ": era gia' stato reclutato dal REQ ricevuto a "
                           + fmt(precedente->tReq) + " s, quindi non era piu' disponibile e ha"
                           " legittimamente rifiutato questa richiesta"});
            continue;
        }
        if (c.allaStazione) {
            out.push_back({"falso aiuto", Esito::NON_APPLICABILE,
                           quando + ": risulta alla stazione di ricarica, dove lo spostamento di"
                           " reclutamento viene legittimamente annullato"});
            continue;
        }
        if (a.spostamentoAnomalo) {
            out.push_back({"falso aiuto", Esito::NON_APPLICABILE,
                           quando + ": il suo spostamento e' gia' segnalato dalla regola 2, non si punisce due volte"});
            continue;
        }
        if (!c.disponibileDichiarata) {
            // Si comporta come se avesse accettato, perche' ha messo la
            // disponibilita' a falsa, ma non si e' spostato. Le spiegazioni
            // lecite sono state escluse sopra: nessun reclutamento precedente in
            // corso, non e' alla stazione, il suo spostamento non e' segnalato
            // dalla regola 2. Essere reclutato DOPO non giustifica il non avere
            // aiutato prima, quindi non e' una spiegazione.
            //
            // Tutto questo pero' regge su un presupposto: che chi controlla
            // avrebbe visto lo spostamento, se ci fosse stato. Il presupposto
            // vale per un REQ osservato di persona, non per uno riferito dalla
            // GCS, che riguarda un episodio a cui chi controlla non ha assistito
            // e che puo' essere concluso da parecchi secondi. In quel caso resta
            // un dubbio.
            if (a.daSecondaMano) {
                out.push_back({"falso aiuto", Esito::DUBBIO,
                               quando + ": si dichiara non disponibile e non risulta spostato, ma questo"
                               " reclutamento e' stato riferito dalla GCS e non osservato di persona,"
                               " quindi non si puo' escludere che lo spostamento sia avvenuto senza"
                               " essere visto"});
                continue;
            }
            out.push_back({"falso aiuto", Esito::VIOLATO,
                           quando + ": si dichiara non disponibile, quindi ha accettato, ma non si e'"
                           " spostato verso chi ha chiesto aiuto, che resta senza aiuto"});
            continue;
        }
        // Non si e' spostato e continua a dichiararsi disponibile.
        out.push_back({"falso aiuto", Esito::DUBBIO,
                       quando + ": non si e' spostato e si dichiara ancora disponibile: puo' avere"
                       " ignorato la richiesta, oppure non averla mai ricevuta"});
    }
    return out;
}

/**
 * Scarta le verifiche risolte e quelle per cui non e' mai arrivato un BANT
 * utile entro attesaMaxS. Restituisce quante ne sono state abbandonate, un dato
 * che misura quanto spesso chi controlla non riesce a chiudere una verifica.
 */
inline int ripulisciAttese(std::vector<Pending>& attese, double ora, const HelpCheckParams& p)
{
    // Le verifiche chiuse non si scartano subito: servono da storia, perche' un
    // reclutamento precedente spiega il rifiuto di uno successivo. Si scartano
    // solo quando sono abbastanza vecchie, e fra queste si contano come
    // abbandonate quelle che non sono mai state chiuse.
    int abbandonate = 0;
    size_t scrivi = 0;
    for (size_t leggi = 0; leggi < attese.size(); leggi++) {
        const Pending& a = attese[leggi];
        if (ora - a.istanteLimite > p.attesaMaxS) {
            if (!a.risolto)
                abbandonate++;
            continue;
        }
        attese[scrivi++] = attese[leggi];
    }
    attese.resize(scrivi);
    return abbandonate;
}

}  // namespace ant2help

#endif
