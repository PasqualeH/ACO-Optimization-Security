//
// Ant2PositionCheck.h
//
// Regola 2 della metrica di trust: controllo sulla posizione dichiarata dai
// droni nei BANT.
//
// Scritto come logica pura, senza dipendenze da OMNeT++ o da INET, cosi' la
// stessa funzione usata dal protocollo puo' essere verificata dai test
// automatici in test_controllo_posizione.cc.
//
// COSA CONTROLLA
// Nel progetto i droni sono fermi: la mobilita' e' di tipo LinearMobility con
// velocita' zero (speed = 0mps nel file di configurazione) e la posizione cambia
// solo con chiamate esplicite a setPosition(). Gli spostamenti che il protocollo
// prevede sono tre (il quarto, il ritorno dopo aver prestato aiuto, richiede il
// messaggio di congedo e non e' implementato):
//
//   1. Reclutamento. Il drone scelto si sposta recruitMoveDelay secondi dopo
//      aver ricevuto il REQ di reclutamento. La destinazione non e' in una
//      direzione qualsiasi: moveUav() calcola
//          x = recruitOffset + px + r*cos(a)
//          y = recruitOffset + py + r*sin(a)
//          z = recruitAltitude
//      con px, py posizione di chi ha chiesto aiuto, r casuale fra 0 e
//      recruitRadius e a casuale. La destinazione cade quindi dentro una sfera
//      di raggio recruitRadius centrata in (px + offset, py + offset, quota).
//      Il controllo verifica proprio questo, e non un intervallo di distanza da
//      chi ha chiesto aiuto: con l'intervallo un attaccante che si sposta nella
//      direzione opposta passerebbe, con la sfera no.
//
//   2. Andata alla stazione di ricarica. Dopo l'avviso di batteria scarica il
//      drone si sposta alla stazione, in posizione fissa, dopo
//      chargeDepartureDelay secondi.
//
//   3. Ritorno dalla stazione. A ricarica completata il drone torna nella
//      posizione che aveva prima di andare alla stazione.
//
// Da questo segue il principio del controllo: un drone e' fermo per natura e si
// muove SOLO in presenza di un evento che lo autorizzi. Una posizione dichiarata
// diversa dall'ultima legittima, senza un evento che la giustifichi, e' una
// bugia.
//
// L'ANCORA
// Il termine di confronto non e' la misura precedente, ma l'ULTIMA POSIZIONE
// RICONOSCIUTA LEGITTIMA, che chiamiamo ancora. La differenza e' decisiva.
//
// Se confrontassimo ogni misura con quella precedente, un drone che al secondo
// 40 salta a una posizione falsa e poi la ripete coerentemente violerebbe una
// volta sola: dal BANT successivo le due misure a confronto sarebbero entrambe
// false e uguali, quindi il controllo risulterebbe superato. La bugia sarebbe
// punita una volta e poi dimenticata, pur continuando.
//
// Con l'ancora, invece, il riferimento non si sposta quando il drone mente:
// l'ancora avanza SOLO su uno spostamento riconosciuto lecito. Quindi ogni BANT
// successivo viene confrontato con l'ultima posizione vera e viola di nuovo,
// finche' il drone non torna all'ancora o non arriva un evento che giustifichi
// davvero di essere dove dice. La punizione dura quanto dura la bugia, e il
// numero di violazioni misura da se' la gravita', senza bisogno di definire una
// severita' a parte.
//
// COME SI GIUSTIFICA UNO SPOSTAMENTO
// Ogni nodo che riceve un REQ, dopo la verifica della firma e la decifratura,
// annota l'evento in un registro: tipo (reclutamento se mittente e destinatario
// del REQ sono diversi, avviso di batteria scarica se coincidono), drone
// interessato (il destinatario), posizione di chi ha chiesto aiuto, istante in
// cui lui stesso ha ricevuto il REQ, numero di sequenza. Le tre giustificazioni
// possibili sono tutte verificabili senza fidarsi del drone:
//
//   - un REQ di reclutamento a lui indirizzato, con destinazione dentro la sfera
//     prevista: il REQ e' firmato e porta la posizione del richiedente;
//   - l'arrivo alla stazione di ricarica, che e' un punto fisso noto a tutti;
//   - il rientro dalla stazione nella posizione da cui era partito, che chi
//     controlla ha gia' visto.
//
// IL DUBBIO E IL BOLLETTINO DEI REQ
// Un REQ puo' non essere arrivato a chi controlla: il canale e' wireless, il
// broadcast non ha riscontri ne' ritrasmissioni. Condannare subito uno
// spostamento non giustificato significherebbe quindi, su un solo pacchetto
// perso, accusare un drone onesto per decine di BANT consecutivi: con l'ancora
// l'errore non resta isolato, si moltiplica.
//
// Per questo uno spostamento senza evento osservato non e' una violazione: e'
// un DUBBIO SOSPESO. Resta in attesa, e viene deciso dal bollettino dei REQ che
// la GCS pubblica firmato (sezione RecordReq del bollettino delle impronte):
//
//   - se il bollettino porta un REQ che giustifica lo spostamento, il dubbio
//     diventa SUPERATO e l'ancora avanza;
//   - se arriva un bollettino emesso dopo lo spostamento e quel REQ non c'e',
//     allora nemmeno la GCS lo ha visto: il dubbio diventa VIOLAZIONE CERTA;
//   - finche' il bollettino non arriva, il dubbio resta dubbio e non punisce.
//
// Questo poggia sull'ipotesi di fiducia che il progetto fa sulle GCS: il loro
// registro dei REQ e' considerato completo e autentico. E' la stessa ipotesi su
// cui si regge la regola 0.
//
// GLI ESITI
//   SUPERATO        il drone e' all'ancora, oppure si e' spostato in modo
//                   giustificato e coerente con l'evento
//   VIOLATO         c'e' l'evento ma la destinazione non corrisponde, oppure il
//                   bollettino della GCS ha escluso che un evento esistesse
//   DUBBIO          spostamento senza evento osservato, in attesa del bollettino
//   NON_APPLICABILE misura ripetuta, in disordine, prima misura di un drone,
//                   oppure ritorno dalla stazione con partenza non osservata
//
// La coerenza del timbro di misura non viene ricontrollata qui: la verifica la
// fa la regola 1 sull'energia, sullo stesso timbro, perche' updateThroughput()
// legge posizione ed energia nello stesso istante.
//
#ifndef __INET_ANT2POSITIONCHECK_H
#define __INET_ANT2POSITIONCHECK_H

#include <cmath>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace ant2position {

/** Punto nello spazio, per non dipendere da inet::Coord. */
struct Vec3
{
    double x = 0, y = 0, z = 0;
    Vec3() = default;
    Vec3(double x_, double y_, double z_) : x(x_), y(y_), z(z_) {}
};

inline double distanza(const Vec3& a, const Vec3& b)
{
    double dx = a.x - b.x, dy = a.y - b.y, dz = a.z - b.z;
    return std::sqrt(dx * dx + dy * dy + dz * dz);
}

/** Tipo di evento annotato nel registro, ricavato dal REQ. */
enum class TipoEvento {
    RECLUTAMENTO,   // mittente e destinatario del REQ diversi: chi chiede aiuto recluta
    AVVISO          // mittente e destinatario coincidono: avviso di batteria scarica
};

/** Un evento osservato, cioe' un REQ ricevuto da chi controlla. */
struct MoveEvent
{
    TipoEvento tipo = TipoEvento::RECLUTAMENTO;
    uint32_t drone = 0;       // drone interessato: destinatario del REQ
    uint32_t richiedente = 0; // chi ha chiesto aiuto: mittente del REQ (serve alla regola 4)
    Vec3 posRichiedente;      // posizione di chi ha chiesto aiuto (solo reclutamento)
    double istante = 0;       // istante in cui chi controlla ha ricevuto il REQ
    unsigned int seq = 0;     // numero di sequenza del REQ
    bool usato = false;       // l'evento ha gia' giustificato uno spostamento
};

/** Una misura di posizione dichiarata in un BANT. */
struct PositionSample
{
    double t = -1;            // timbro di misura (lo stesso dell'energia)
    Vec3 pos;                 // posizione dichiarata
    double energia = -1;      // energia dichiarata con lo stesso timbro, per il ritorno dalla ricarica
    std::string fonte = "BANT";  // messaggio di provenienza: "BANT" o "una voce di traccia"
};

/** Parametri del controllo. */
struct PositionCheckParams
{
    double tolPosM = 10.0;          // tolleranza sulla destinazione (m)
    double tolFermoM = 1.0;         // sotto questa distanza il drone e' considerato fermo (m)
    double maxNetworkDelay = 3.0;   // D: ritardo massimo di rete (s)
    double recruitOffset = 100.0;   // spostamento fisso su x e y rispetto a chi chiede aiuto (m)
    double recruitRadius = 100.0;   // raggio casuale aggiunto allo spostamento (m)
    double recruitAltitude = 50.0;  // quota a cui moveUav() porta il drone (m)
    double recruitMoveDelay = 1.0;  // ritardo fra REQ di reclutamento e spostamento (s)
    double chargeDepartureDelay = 1.0;  // ritardo fra avviso di batteria scarica e partenza (s)
    Vec3 stazione = Vec3(1000, 1000, 50);  // posizione della stazione di ricarica
    // Margine oltre il quale un bollettino emesso dopo lo spostamento e' ritenuto
    // capace di decidere il dubbio: se la GCS non aveva quel REQ, non lo ha visto.
    double margineBollettino = 3.0;

    /** Centro della sfera in cui moveUav() porta il drone reclutato. */
    Vec3 bersaglioReclutamento(const Vec3& posRichiedente) const
    {
        return Vec3(posRichiedente.x + recruitOffset,
                    posRichiedente.y + recruitOffset,
                    recruitAltitude);
    }
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

/**
 * Spostamento che il controllo ha riconosciuto come avvenuto e lecito. Serve
 * alla regola 3 sulla disponibilita': e' lo spostamento, e non l'arrivo del
 * REQ, a provare che il drone ha ricevuto la richiesta e l'ha accettata, quindi
 * da quel momento la disponibilita' che dichiara deve essere falsa.
 */
enum class Mossa { NESSUNA, RECLUTAMENTO, ANDATA_STAZIONE, RITORNO_STAZIONE };

struct PositionOutcome
{
    std::string controllo;   // nome del controllo, per il log
    Esito esito;
    std::string dettaglio;
    Mossa mossa = Mossa::NESSUNA;   // valorizzata solo sugli esiti SUPERATO
    // Chi ha chiesto aiuto, sullo spostamento di reclutamento confermato: serve
    // alla regola 4 sul falso aiuto per sapere verso chi il drone e' andato.
    uint32_t richiedente = 0;
    // Timbro della misura a cui l'esito si riferisce. Sugli esiti prodotti
    // risolvendo un dubbio sospeso e' il timbro di quella vecchia misura, non
    // quello della misura in arrivo.
    double timbro = -1;
};

/** Una posizione gia' dichiarata, per riconoscere le contraddizioni. */
struct TimbroNoto
{
    double t = -1;
    Vec3 pos;
    std::string fonte;
};

/** Quante misure recenti si conservano per il confronto sullo stesso timbro. */
constexpr size_t STORICO_TIMBRI = 8;

/**
 * Uno spostamento non giustificato, in attesa del bollettino dei REQ della GCS.
 * Si conserva la posizione dichiarata e la finestra in cui lo spostamento puo'
 * essere avvenuto, cioe' dal timbro dell'ancora al timbro della misura.
 */
struct DubbioPosizione
{
    double t = -1;        // timbro della misura che ha dichiarato la posizione nuova
    Vec3 pos;             // posizione dichiarata
    double tAncora = -1;  // timbro dell'ancora al momento del dubbio
    Vec3 ancora;          // ancora al momento del dubbio
};

/** Tetto ai dubbi conservati: oltre questo i piu' vecchi vengono abbandonati. */
constexpr size_t DUBBI_SOSPESI = 64;

/** Stato conservato per ogni drone osservato. */
struct PositionObservedState
{
    bool has = false;             // almeno una misura gia' vista
    PositionSample last;          // ultima misura, per riconoscere ripetizioni e disordine
    // L'ancora: ultima posizione riconosciuta legittima, e il suo timbro. Non
    // avanza quando il drone dichiara uno spostamento non giustificato.
    bool ancoraNota = false;
    Vec3 ancora;
    double tAncora = -1;
    bool ancoraAllaStazione = false;  // l'ancora e' la stazione di ricarica
    bool posPrecedenteNota = false;
    Vec3 posPrimaDellaStazione;   // posizione da cui e' partito per la stazione
    std::vector<TimbroNoto> storico;    // ultime posizioni dichiarate, per timbro
    std::vector<DubbioPosizione> sospesi;  // dubbi in attesa del bollettino
    long dubbiAbbandonati = 0;    // dubbi scartati per il tetto, mai decisi
};

namespace detail {
inline std::string fmt(double v, int dec = 2)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(dec) << v;
    return o.str();
}

inline std::string fmtPos(const Vec3& p)
{
    return "(" + fmt(p.x, 1) + ", " + fmt(p.y, 1) + ", " + fmt(p.z, 1) + ")";
}

/** Aggiunge una posizione allo storico dei timbri, tenendo le piu' recenti. */
inline void ricordaPosizione(PositionObservedState& st, const PositionSample& s)
{
    for (auto& v : st.storico)
        if (std::abs(v.t - s.t) <= 1e-9)
            return;
    st.storico.push_back({s.t, s.pos, s.fonte});
    if (st.storico.size() > STORICO_TIMBRI)
        st.storico.erase(st.storico.begin());
}
}  // namespace detail

/**
 * Risultato della ricerca di una giustificazione per uno spostamento.
 *
 * trovata        esiste un evento che spiega lo spostamento: e' lecito
 * condannaCerta  si puo' condannare subito, senza aspettare il bollettino,
 *                perche' l'evento c'e' ma la destinazione non corrisponde
 * nonGiudicabile chi controlla non ha gli elementi per giudicare (per esempio il
 *                ritorno dalla stazione con partenza non osservata)
 * Se nessuno dei tre e' vero, lo spostamento e' un dubbio da sospendere.
 */
struct Giustificazione
{
    bool trovata = false;
    bool condannaCerta = false;
    bool nonGiudicabile = false;
    Mossa mossa = Mossa::NESSUNA;
    uint32_t richiedente = 0;
    MoveEvent *ev = nullptr;      // evento da consumare, se trovata
    std::string spiegazione;      // testo per il log
};

/**
 * Cerca una giustificazione per uno spostamento dall'ancora alla posizione
 * 'nuova', avvenuto fra i timbri t0 (ancora) e t (misura).
 *
 * L'evento scatena lo spostamento dopo un ritardo dalla ricezione del REQ da
 * parte del drone interessato. Chi controlla pero' ha ricevuto il REQ in un
 * istante che puo' differire fino a D secondi da quello del drone, perche' il
 * REQ attraversa la rete su percorsi diversi. L'istante dello spostamento e'
 * quindi compreso fra istante + ritardo - D e istante + ritardo + D, e deve
 * intersecare la finestra [t0, t].
 *
 * La funzione non modifica il registro: il consumo dell'evento lo fa chi chiama,
 * perche' solo lui sa se l'esito viene effettivamente registrato.
 */
inline Giustificazione giustificaSpostamento(const PositionObservedState& st, const Vec3& nuova,
                                             double t0, double t, const PositionCheckParams& p,
                                             std::vector<MoveEvent>& registro, uint32_t drone)
{
    using detail::fmt;
    using detail::fmtPos;
    Giustificazione g;
    const bool nuovaAllaStazione = distanza(nuova, p.stazione) <= p.tolPosM;

    // --- Caso 1: il drone e' arrivato alla stazione di ricarica ---
    if (nuovaAllaStazione && !st.ancoraAllaStazione) {
        MoveEvent *scelto = nullptr;
        for (auto& e : registro) {
            if (e.usato || e.drone != drone || e.tipo != TipoEvento::AVVISO)
                continue;
            double primo = e.istante + p.chargeDepartureDelay - p.maxNetworkDelay;
            double ultimo = e.istante + p.chargeDepartureDelay + p.maxNetworkDelay;
            if (ultimo < t0 || primo > t)
                continue;
            if (!scelto || e.istante > scelto->istante)
                scelto = &e;
        }
        if (scelto) {
            g.trovata = true;
            g.mossa = Mossa::ANDATA_STAZIONE;
            g.ev = scelto;
            g.spiegazione = "andata alla stazione, giustificata dall'avviso di batteria scarica ricevuto a "
                            + fmt(scelto->istante, 3) + " s";
        }
        else {
            g.spiegazione = "arrivo alla stazione senza avviso di batteria scarica osservato";
        }
        return g;
    }

    // --- Caso 2: il drone era alla stazione e se ne e' andato ---
    if (st.ancoraAllaStazione) {
        if (!st.posPrecedenteNota) {
            g.nonGiudicabile = true;
            g.spiegazione = "ritorno dalla stazione, ma la posizione di partenza non e' nota a chi controlla";
        }
        else if (distanza(nuova, st.posPrimaDellaStazione) <= p.tolPosM) {
            g.trovata = true;
            g.mossa = Mossa::RITORNO_STAZIONE;
            g.spiegazione = "ritorno dalla stazione nella posizione di partenza "
                            + fmtPos(st.posPrimaDellaStazione);
        }
        else {
            // La stazione e' un punto noto e la posizione di partenza l'abbiamo
            // vista: non serve nessun REQ per giudicare, quindi si condanna
            // subito senza aspettare il bollettino.
            g.condannaCerta = true;
            g.spiegazione = "lasciata la stazione per una posizione diversa da quella di partenza "
                            + fmtPos(st.posPrimaDellaStazione) + ", distante "
                            + fmt(distanza(nuova, st.posPrimaDellaStazione), 1) + " m";
        }
        return g;
    }

    // --- Caso 3: spostamento di reclutamento ---
    //
    // Fra l'ancora e la misura possono essere arrivati PIU' REQ di reclutamento
    // diretti allo stesso drone: succede quando due droni chiedono aiuto a poca
    // distanza di tempo e scelgono entrambi lo stesso vincitore, perche' il
    // secondo lo vede ancora disponibile nella propria tabella di stato. Il
    // drone accetta il primo, mette la disponibilita' a falsa e poi RIFIUTA il
    // secondo limitandosi a inoltrarlo, quindi si sposta verso chi ha mandato il
    // primo. Non si puo' percio' prendere l'evento piu' recente e bocciare il
    // drone se non corrisponde: si provano tutti gli eventi compatibili e lo
    // spostamento e' giustificato se almeno uno di essi lo spiega.
    MoveEvent *piuVicino = nullptr;
    double scartoMigliore = 0;
    int compatibili = 0;
    const double limite = p.recruitRadius + p.tolPosM;
    for (auto& e : registro) {
        if (e.usato || e.drone != drone || e.tipo != TipoEvento::RECLUTAMENTO)
            continue;
        double primo = e.istante + p.recruitMoveDelay - p.maxNetworkDelay;
        double ultimo = e.istante + p.recruitMoveDelay + p.maxNetworkDelay;
        if (ultimo < t0 || primo > t)
            continue;
        compatibili++;
        double scarto = distanza(nuova, p.bersaglioReclutamento(e.posRichiedente));
        if (piuVicino == nullptr || scarto < scartoMigliore) {
            piuVicino = &e;
            scartoMigliore = scarto;
        }
        if (scarto <= limite && !g.trovata) {
            g.trovata = true;
            g.mossa = Mossa::RECLUTAMENTO;
            g.richiedente = e.richiedente;
            g.ev = &e;
        }
    }

    std::string quanti = compatibili > 1 ? " (" + std::to_string(compatibili) + " REQ compatibili esaminati)" : "";
    if (g.trovata) {
        g.spiegazione = "reclutamento del REQ ricevuto a " + fmt(g.ev->istante, 3)
                        + " s, destinazione a "
                        + fmt(distanza(nuova, p.bersaglioReclutamento(g.ev->posRichiedente)), 1)
                        + " m dal centro previsto " + fmtPos(p.bersaglioReclutamento(g.ev->posRichiedente))
                        + " (limite " + fmt(limite, 1) + " m)" + quanti;
    }
    else if (compatibili > 0) {
        // C'e' un REQ che lo autorizzava a muoversi, ma non verso dove dice di
        // essere andato: il termine di confronto ce l'abbiamo, la condanna e'
        // certa senza aspettare il bollettino.
        g.condannaCerta = true;
        g.spiegazione = "nessuno dei REQ di reclutamento compatibili spiega la destinazione; il piu' vicino e' quello ricevuto a "
                        + fmt(piuVicino->istante, 3) + " s, che la vorrebbe entro " + fmt(limite, 1)
                        + " m da " + fmtPos(p.bersaglioReclutamento(piuVicino->posRichiedente))
                        + " mentre dista " + fmt(scartoMigliore, 1) + " m" + quanti;
    }
    else {
        g.spiegazione = "nessun evento osservato che giustifichi lo spostamento";
    }
    return g;
}

namespace detail {
/** Sposta l'ancora su una posizione riconosciuta legittima. */
inline void spostaAncora(PositionObservedState& st, const Vec3& nuova, double t,
                         const PositionCheckParams& p, Mossa mossa)
{
    if (mossa == Mossa::ANDATA_STAZIONE) {
        st.posPrimaDellaStazione = st.ancora;
        st.posPrecedenteNota = st.ancoraNota;
    }
    st.ancora = nuova;
    st.tAncora = t;
    st.ancoraNota = true;
    st.ancoraAllaStazione = distanza(nuova, p.stazione) <= p.tolPosM;
}
}  // namespace detail

/**
 * Esegue il controllo sulla posizione di una misura nuova.
 *
 * st       stato del drone osservato, aggiornato dalla funzione
 * s        misura appena arrivata (timbro, posizione, energia dichiarata)
 * p        parametri
 * registro eventi osservati, un evento compatibile viene consumato
 */
inline std::vector<PositionOutcome> checkPosition(PositionObservedState& st, const PositionSample& s,
                                                  const PositionCheckParams& p,
                                                  std::vector<MoveEvent>& registro,
                                                  uint32_t drone)
{
    using detail::fmt;
    using detail::fmtPos;
    std::vector<PositionOutcome> out;
    const double eps = 1e-9;

    // --- Coerenza della misura: stesso timbro, stessa posizione ---
    // updateThroughput() legge la posizione una volta sola e la scrive con quel
    // timbro in tutti i messaggi, quindi due dichiarazioni con lo stesso timbro
    // devono riportare la stessa posizione. Se differiscono, il drone ha firmato
    // due posizioni diverse per la stessa lettura: e' una contraddizione fra due
    // suoi messaggi, non un effetto della rete. Vale fra un BANT e una voce di
    // traccia e fra due BANT.
    for (const auto& v : st.storico) {
        if (std::abs(v.t - s.t) <= eps && distanza(v.pos, s.pos) > p.tolFermoM) {
            out.push_back({"coerenza della posizione", Esito::VIOLATO,
                           "timbro " + fmt(s.t, 3) + " s dichiarato " + fmtPos(v.pos) + " in " + v.fonte
                           + " e " + fmtPos(s.pos) + " in " + s.fonte + ", distanti "
                           + fmt(distanza(v.pos, s.pos), 1) + " m",
                           Mossa::NESSUNA, 0, s.t});
            return out;
        }
    }

    if (!st.has) {
        // Prima misura: non c'e' niente con cui confrontarla. Diventa l'ancora.
        st.has = true;
        st.last = s;
        detail::spostaAncora(st, s.pos, s.t, p, Mossa::NESSUNA);
        detail::ricordaPosizione(st, s);
        out.push_back({"posizione", Esito::NON_APPLICABILE,
                       "prima misura osservata, " + fmtPos(s.pos) + " al timbro " + fmt(s.t, 3)
                       + " s: diventa il riferimento", Mossa::NESSUNA, 0, s.t});
        return out;
    }
    if (std::abs(s.t - st.last.t) <= eps) {
        out.push_back({"posizione", Esito::NON_APPLICABILE,
                       "stesso timbro dell'ultima misura (" + fmt(s.t, 3) + " s): misura ripetuta",
                       Mossa::NESSUNA, 0, s.t});
        return out;
    }
    if (s.t < st.last.t) {
        out.push_back({"posizione", Esito::NON_APPLICABILE,
                       "timbro " + fmt(s.t, 3) + " s piu' vecchio dell'ultima misura ("
                       + fmt(st.last.t, 3) + " s): arrivata in disordine",
                       Mossa::NESSUNA, 0, s.t});
        return out;
    }

    st.last = s;
    detail::ricordaPosizione(st, s);

    const double scostamento = distanza(s.pos, st.ancora);

    // --- Il drone e' all'ancora: fermo dove deve stare ---
    //
    // Questo e' un controllo vero e va contato. Un drone che mente sulla
    // posizione non puo' superarlo: la sua dichiarazione si discosta
    // dall'ancora, che non si e' mossa. E' il caso normale di un drone onesto,
    // perche' nel progetto i droni sono fermi, e porta il controllo sulla
    // posizione a produrre un esito a ogni BANT invece di uno per reclutamento.
    if (scostamento <= p.tolFermoM) {
        out.push_back({"posizione", Esito::SUPERATO,
                       "fermo al riferimento " + fmtPos(st.ancora) + " (timbro "
                       + fmt(st.tAncora, 3) + " s), scostamento " + fmt(scostamento, 2) + " m",
                       Mossa::NESSUNA, 0, s.t});
        return out;
    }

    // --- Il drone dichiara una posizione diversa dall'ancora ---
    std::string intervallo = "da " + fmtPos(st.ancora) + " (riferimento, timbro " + fmt(st.tAncora, 3)
                             + " s) a " + fmtPos(s.pos) + " (timbro " + fmt(s.t, 3)
                             + " s), scostamento " + fmt(scostamento, 1) + " m";

    Giustificazione g = giustificaSpostamento(st, s.pos, st.tAncora, s.t, p, registro, drone);

    if (g.trovata) {
        if (g.ev)
            g.ev->usato = true;
        out.push_back({"posizione", Esito::SUPERATO, intervallo + ": " + g.spiegazione,
                       g.mossa, g.richiedente, s.t});
        detail::spostaAncora(st, s.pos, s.t, p, g.mossa);
        return out;
    }
    if (g.nonGiudicabile) {
        out.push_back({"posizione", Esito::NON_APPLICABILE, intervallo + ": " + g.spiegazione,
                       Mossa::NESSUNA, 0, s.t});
        // L'ancora avanza comunque: chi controlla non puo' giudicare, e tenerla
        // ferma produrrebbe violazioni a ripetizione su un fatto non giudicabile.
        detail::spostaAncora(st, s.pos, s.t, p, Mossa::NESSUNA);
        return out;
    }
    if (g.condannaCerta) {
        out.push_back({"posizione", Esito::VIOLATO, intervallo + ": " + g.spiegazione,
                       Mossa::NESSUNA, 0, s.t});
        // L'ancora NON avanza: il drone sta dichiarando una posizione illecita e
        // ogni BANT successivo che la ripete deve violare di nuovo.
        return out;
    }

    // Nessun evento osservato: dubbio sospeso, in attesa del bollettino dei REQ.
    out.push_back({"posizione", Esito::DUBBIO,
                   intervallo + ": " + g.spiegazione + ", in attesa del bollettino dei REQ della GCS",
                   Mossa::NESSUNA, 0, s.t});
    DubbioPosizione d;
    d.t = s.t;
    d.pos = s.pos;
    d.tAncora = st.tAncora;
    d.ancora = st.ancora;
    st.sospesi.push_back(d);
    if (st.sospesi.size() > DUBBI_SOSPESI) {
        st.sospesi.erase(st.sospesi.begin());
        st.dubbiAbbandonati++;
    }
    return out;
}

/**
 * Decide i dubbi sospesi alla luce del registro aggiornato.
 *
 * Va chiamata dopo ogni arrivo di REQ, sia visto di persona sia pubblicato dal
 * bollettino della GCS.
 *
 * ultimoBollettino e' l'istante del piu' recente bollettino dei REQ ricevuto
 * dalla GCS, oppure un valore negativo se non ne e' ancora arrivato nessuno. Un
 * dubbio si trasforma in violazione certa solo se esiste un bollettino emesso
 * abbastanza dopo lo spostamento: significa che nemmeno la GCS, che vede tutti i
 * REQ, ne aveva uno che lo giustificasse.
 *
 * bollettinoCopreDa e' l'istante del REQ piu' vecchio contenuto in quella
 * sezione. Il bollettino ha un tetto al numero di righe, quindi i REQ piu'
 * vecchi possono essere stati tagliati: un dubbio la cui finestra comincia prima
 * di quell'istante non si condanna, perche' il REQ che lo giustificava potrebbe
 * essere fra quelli tagliati. Se la sezione era vuota la GCS non conosceva
 * nessun REQ, e allora copre tutto: si passa un valore molto negativo.
 */
inline std::vector<PositionOutcome> risolviDubbiPosizione(PositionObservedState& st,
                                                          const PositionCheckParams& p,
                                                          std::vector<MoveEvent>& registro,
                                                          uint32_t drone,
                                                          double ultimoBollettino,
                                                          double bollettinoCopreDa)
{
    using detail::fmt;
    using detail::fmtPos;
    std::vector<PositionOutcome> out;
    std::vector<DubbioPosizione> restano;

    for (auto& d : st.sospesi) {
        std::string intervallo = "da " + fmtPos(d.ancora) + " (riferimento, timbro " + fmt(d.tAncora, 3)
                                 + " s) a " + fmtPos(d.pos) + " (timbro " + fmt(d.t, 3) + " s)";

        // Lo stato dell'ancora al momento del dubbio: serve a riprodurre la
        // stessa ricerca di allora, non quella di adesso. Si costruisce uno
        // stato minimo con i soli campi che la ricerca usa.
        PositionObservedState allora;
        allora.ancora = d.ancora;
        allora.tAncora = d.tAncora;
        allora.ancoraNota = true;
        allora.ancoraAllaStazione = distanza(d.ancora, p.stazione) <= p.tolPosM;
        allora.posPrecedenteNota = st.posPrecedenteNota;
        allora.posPrimaDellaStazione = st.posPrimaDellaStazione;

        Giustificazione g = giustificaSpostamento(allora, d.pos, d.tAncora, d.t, p, registro, drone);

        if (g.trovata) {
            if (g.ev)
                g.ev->usato = true;
            out.push_back({"posizione", Esito::SUPERATO,
                           intervallo + ": dubbio sciolto dal bollettino dei REQ, " + g.spiegazione,
                           g.mossa, g.richiedente, d.t});
            // Se l'ancora e' rimasta indietro, ora avanza: lo spostamento era lecito.
            if (d.t >= st.tAncora)
                detail::spostaAncora(st, d.pos, d.t, p, g.mossa);
            continue;
        }
        if (g.condannaCerta) {
            out.push_back({"posizione", Esito::VIOLATO,
                           intervallo + ": " + g.spiegazione, Mossa::NESSUNA, 0, d.t});
            continue;
        }
        if (ultimoBollettino >= d.t + p.margineBollettino && d.tAncora >= bollettinoCopreDa) {
            out.push_back({"posizione", Esito::VIOLATO,
                           intervallo + ": nessun REQ che lo giustifichi ne' fra quelli osservati"
                           " ne' fra quelli pubblicati dalla GCS nel bollettino di "
                           + fmt(ultimoBollettino, 3) + " s", Mossa::NESSUNA, 0, d.t});
            continue;
        }
        restano.push_back(d);   // il bollettino che decide non e' ancora arrivato
    }

    st.sospesi.swap(restano);
    return out;
}

/**
 * Lo spostamento di reclutamento viene annullato se, allo scadere del timer, il
 * drone e' andato a ricaricarsi: moveUav() in quel caso esce senza spostare.
 * Chi controlla deve quindi sapere che un evento di reclutamento senza
 * spostamento non e' una violazione se il drone risulta alla stazione. Questa
 * funzione serve a consumare quegli eventi, cosi' non restano nel registro a
 * giustificare uno spostamento successivo.
 */
inline void consumaReclutamentiAnnullati(std::vector<MoveEvent>& registro, uint32_t drone,
                                         bool droneAllaStazione)
{
    if (!droneAllaStazione)
        return;
    for (auto& e : registro)
        if (!e.usato && e.drone == drone && e.tipo == TipoEvento::RECLUTAMENTO)
            e.usato = true;
}

/**
 * Scarta dal registro gli eventi troppo vecchi per giustificare uno spostamento.
 *
 * L'eta' massima deve essere abbastanza lunga da coprire l'attesa del
 * bollettino: un evento buttato via prima che il bollettino arrivi farebbe
 * condannare un drone onesto.
 */
inline void ripuliscoRegistro(std::vector<MoveEvent>& registro, double ora, double eta)
{
    size_t scrivi = 0;
    for (size_t leggi = 0; leggi < registro.size(); leggi++) {
        if (ora - registro[leggi].istante <= eta && !registro[leggi].usato)
            registro[scrivi++] = registro[leggi];
    }
    registro.resize(scrivi);
}

}  // namespace ant2position

#endif
