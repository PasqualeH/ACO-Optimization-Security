//
// Ant2DigestCheck.h
//
// Regola 0 della metrica di trust: coerenza fra canali (equivocazione).
//
// PERCHE' ESISTE QUESTA REGOLA
// ----------------------------
// Le cinque regole gia' implementate guardano tutte un canale solo: le misure
// che arrivano dentro i BANT. Sono quindi tutte cieche davanti a un attaccante
// che dichiara una cosa ai droni vicini e un'altra alla GCS, oppure una cosa a
// un vicino e un'altra a un altro vicino. In letteratura questo si chiama
// equivocazione, ed e' l'unica classe di attacco che un osservatore solo, con
// un canale solo, non puo' cogliere nemmeno in linea di principio.
//
// La GCS raccoglie le stesse grandezze su due canali diversi: le voci di
// traccia, che i droni scrivono quando una traccia li attraversa, e i BANT che
// riceve come qualunque altro osservatore. Se pubblica ai droni un'impronta
// crittografica di quello che ha ricevuto, ogni drone puo' confrontarla con
// l'impronta di quello che ha ricevuto lui. Se le due impronte della stessa
// lettura non coincidono, il drone ha dichiarato due cose diverse: violazione
// certa, senza soglie e senza stime.
//
// PERCHE' L'IMPRONTA E NON I VALORI
// ---------------------------------
// Al controllo non serve sapere quale dei due valori fosse falso, serve sapere
// che sono diversi. Mandare 8 byte di impronta invece di 148 byte di record
// costa circa cinque volte meno traffico, e il traffico va sul canale del
// cluster, che e' quello congestionato. In cambio si perde la possibilita' di
// dire quale dichiarazione fosse quella falsa, che alla metrica di trust non
// serve.
//
// QUALI CAMPI ENTRANO NELL'IMPRONTA, E PERCHE' NON TUTTI
// ------------------------------------------------------
// Il timbro di misura e' l'istante in cui il drone ha letto i propri dati:
// viene fissato in updateThroughput(), che nella stessa riga aggiorna anche
// throughput, posizione ed energia. Quelle grandezze sono quindi LEGATE ALLA
// LETTURA: due messaggi con lo stesso timbro le portano per forza identiche, se
// il drone e' onesto. La banda massima non cambia mai nel codice, quindi e'
// sicura anche lei.
//
// Non sono invece legati alla lettura 'allowed_accept_request' e 'cluster_id':
// il primo diventa falso nell'istante in cui il drone accetta un REQ e cambia
// ancora alla partenza per la ricarica, il secondo cambia quando il drone viene
// reclutato in un altro cluster. Entrambi possono quindi cambiare FRA DUE
// MESSAGGI CHE PORTANO LO STESSO TIMBRO, perche' quegli eventi non rinfrescano
// il timbro. Metterli nell'impronta avrebbe accusato di equivocazione droni
// perfettamente onesti. Restano fuori, ed e' un limite dichiarato: un
// attaccante che equivoca solo sulla disponibilita' sfugge a questa regola.
// La disponibilita' resta comunque coperta dalla regola 3, che e' la piu'
// severa delle cinque.
//
// COSA FA QUESTO FILE E COSA NO
// -----------------------------
// Qui c'e' solo la logica: la memoria delle letture osservate, il confronto
// delle impronte, gli esiti e la contabilita' dell'annullamento. L'impronta
// vera e propria (SHA-512 troncato) viene calcolata in Ant2Digest.cc, dove la
// libreria crittografica e' disponibile: qui l'impronta e' un semplice numero a
// 64 bit, cosi' questo file si compila da solo e i test non hanno bisogno ne'
// di OMNeT++ ne' della crittografia.
//
#ifndef __INET_ANT2DIGESTCHECK_H
#define __INET_ANT2DIGESTCHECK_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace ant2digest {

/** Stato di verifica di una lettura osservata. */
enum class Stato {
    NON_VERIFICATA,   // la GCS non ha (ancora) pubblicato un'impronta per questa lettura
    CONFERMATA,       // impronta della GCS ricevuta e coincidente
    CONTRADDETTA      // impronta della GCS ricevuta e diversa: equivocazione
};

inline const char *statoStr(Stato s)
{
    switch (s) {
        case Stato::NON_VERIFICATA: return "NON_VERIFICATA";
        case Stato::CONFERMATA:     return "CONFERMATA";
        case Stato::CONTRADDETTA:   return "CONTRADDETTA";
        default: return "?";
    }
}

/** Esito di un singolo controllo. */
enum class Esito { SUPERATO, VIOLATO, NON_APPLICABILE };

inline const char *esitoStr(Esito e)
{
    switch (e) {
        case Esito::SUPERATO:        return "SUPERATO";
        case Esito::VIOLATO:         return "VIOLATO";
        case Esito::NON_APPLICABILE: return "NON_APPLICABILE";
        default: return "?";
    }
}

/** Canale da cui proviene l'impronta pubblicata dalla GCS. */
enum class Fonte { IGNOTA, BANT, TRACCIA };

inline const char *fonteStr(Fonte f)
{
    switch (f) {
        case Fonte::BANT:    return "un BANT ricevuto dalla GCS";
        case Fonte::TRACCIA: return "una voce di traccia";
        default:             return "fonte ignota";
    }
}

/**
 * Una lettura osservata di un drone: il timbro la identifica, l'impronta
 * riassume i valori, lo stato dice se la GCS l'ha confermata o contraddetta.
 *
 * I tre contatori servono all'annullamento. Quando il drone esegue le cinque
 * regole su questa lettura, gli esiti che quelle regole producono vengono
 * annotati qui. Se piu' tardi la lettura risulta contraddetta, quegli esiti
 * vengono tolti dai totali: giudicare il contenuto di una dichiarazione che
 * sappiamo falsificata non ha senso, e al posto loro resta la violazione certa
 * di questa regola, che e' piu' grave di qualunque esito annullato. Per questo
 * l'annullamento non puo' mai avvantaggiare un attaccante.
 */
struct Misura {
    double timbro = -1;
    uint64_t impronta = 0;
    Stato stato = Stato::NON_VERIFICATA;
    long superati = 0, violati = 0, dubbi = 0;   // esiti delle regole 1-5 su questa lettura
    bool annullata = false;                      // gli esiti sono gia' stati tolti
};

/** Quante letture per drone osservato restano in memoria. */
constexpr size_t STORICO_IMPRONTE = 8;

/**
 * Un'impronta pubblicata dalla GCS per una lettura che questo nodo non ha
 * (ancora) ricevuto.
 *
 * Capita, perche' i due canali non sono sincronizzati: fra due letture un drone
 * manda piu' BANT e puo' ricevere una traccia in qualunque momento, quindi a
 * volte la voce di traccia parte prima del BANT corrispondente e l'impronta
 * arriva per prima. Tenerla da parte fa si' che il confronto scatti quando
 * arriva il secondo dei due pezzi, quale che sia, invece di andare perduto.
 */
struct ImprontaAttesa {
    double timbro = -1;
    uint64_t impronta = 0;
    Fonte fonte = Fonte::IGNOTA;
};

/** Quante impronte in attesa si tengono per drone osservato. */
constexpr size_t ATTESE_IMPRONTE = 8;

/** Memoria che un nodo tiene su un drone osservato. */
/** Quante letture gia' accertate false restano in memoria. */
constexpr size_t MEMORIA_CONTESE = 64;

struct DigestObservedState {
    std::vector<Misura> storico;   // la piu' recente in fondo, al massimo STORICO_IMPRONTE
    std::vector<ImprontaAttesa> attese;   // impronte arrivate prima del messaggio
    // Timbri delle letture gia' accertate false. Serve una memoria PIU' LUNGA
    // dello storico: la GCS ripubblica l'allerta parecchie volte perche' arrivi
    // a tutti, e nel frattempo lo storico, che tiene solo otto letture, ha gia'
    // dimenticato quella contestata. Senza questa memoria la stessa bugia
    // verrebbe contata una decina di volte, gonfiando i totali senza aggiungere
    // nessuna informazione.
    std::vector<double> timbriContesi;

    // Contabilita'
    long superati = 0, violati = 0, nonApplicabili = 0;
    long confermate = 0, contraddette = 0;
    long annullatiSuperati = 0, annullatiViolati = 0, annullatiDubbi = 0;
    // Equivocazione colta senza la GCS: due messaggi ricevuti direttamente da
    // questo osservatore, stesso timbro, impronte diverse.
    long violatiLocali = 0;
};

struct DigestCheckParams {
    // Due timbri si considerano la stessa lettura se distano meno di questo.
    // I timbri viaggiano come double copiati byte per byte, quindi in pratica
    // o sono identici o sono letture diverse: la tolleranza serve solo a non
    // dipendere dal confronto esatto fra numeri in virgola mobile.
    double tolTimbro = 1e-9;
};

/** Esito di un controllo, piu' le istruzioni di annullamento per il chiamante. */
struct DigestOutcome {
    std::string controllo;
    Esito esito = Esito::NON_APPLICABILE;
    std::string dettaglio;
    double timbro = -1;
    // Se vero, il chiamante deve togliere dai propri totali gli esiti indicati,
    // perche' derivavano da una lettura risultata falsificata.
    bool annulla = false;
    long annullaSuperati = 0, annullaViolati = 0, annullaDubbi = 0;
};

namespace detail {

inline bool stessoTimbro(double a, double b, const DigestCheckParams& p)
{
    double d = a - b;
    if (d < 0) d = -d;
    return d <= p.tolTimbro;
}

inline std::string fmt(double v, int dec)
{
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.*f", dec, v);
    return buf;
}

inline std::string fmtImpronta(uint64_t v)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)v);
    return buf;
}

}   // namespace detail

/** Cerca la lettura con quel timbro; nullptr se non c'e'. */
/** La lettura con quel timbro risulta gia' accertata falsa? */
inline bool giaContesa(const DigestObservedState& st, double timbro, const DigestCheckParams& p)
{
    for (double t : st.timbriContesi)
        if (detail::stessoTimbro(t, timbro, p))
            return true;
    return false;
}

inline void ricordaContesa(DigestObservedState& st, double timbro, const DigestCheckParams& p)
{
    if (giaContesa(st, timbro, p))
        return;
    st.timbriContesi.push_back(timbro);
    while (st.timbriContesi.size() > MEMORIA_CONTESE)
        st.timbriContesi.erase(st.timbriContesi.begin());
}

inline Misura *cercaMisura(DigestObservedState& st, double timbro, const DigestCheckParams& p)
{
    for (auto& m : st.storico)
        if (detail::stessoTimbro(m.timbro, timbro, p))
            return &m;
    return nullptr;
}

/**
 * Cuore del confronto: la lettura esiste in memoria e non e' ancora stata
 * verificata. Usato sia quando l'impronta arriva dopo il messaggio sia quando
 * arriva prima e viene recuperata dalle attese.
 */
inline DigestOutcome confrontaImpronta(DigestObservedState& st, Misura& m, double timbro,
                                       uint64_t improntaGcs, Fonte fonte)
{
    DigestOutcome o;
    o.timbro = timbro;
    o.controllo = "coerenza fra canali";

    if (m.impronta == improntaGcs) {
        m.stato = Stato::CONFERMATA;
        st.confermate++;
        st.superati++;
        o.esito = Esito::SUPERATO;
        o.dettaglio = "i valori della lettura con timbro " + detail::fmt(timbro, 3)
                    + " coincidono con quelli arrivati alla GCS";
        return o;
    }

    m.stato = Stato::CONTRADDETTA;
    ricordaContesa(st, timbro, DigestCheckParams());
    st.contraddette++;
    st.violati++;
    o.esito = Esito::VIOLATO;
    o.dettaglio = "alla stessa lettura (timbro " + detail::fmt(timbro, 3)
                + ") questo nodo ha ricevuto valori con impronta " + detail::fmtImpronta(m.impronta)
                + " mentre alla GCS, da " + std::string(fonteStr(fonte))
                + ", ne sono arrivati con impronta " + detail::fmtImpronta(improntaGcs)
                + ": il drone ha dichiarato due cose diverse";
    if (!m.annullata && (m.superati || m.violati || m.dubbi)) {
        o.annulla = true;
        o.annullaSuperati = m.superati;
        o.annullaViolati = m.violati;
        o.annullaDubbi = m.dubbi;
        st.annullatiSuperati += m.superati;
        st.annullatiViolati += m.violati;
        st.annullatiDubbi += m.dubbi;
        m.annullata = true;
    }
    return o;
}

/**
 * Da chiamare quando arriva un messaggio firmato dal drone osservato (un BANT,
 * oppure una voce di traccia raccolta da questo nodo), con l'impronta dei suoi
 * campi legati alla lettura.
 *
 * Se la lettura e' nuova, viene aggiunta allo storico. Se il timbro c'era gia'
 * ma l'impronta e' diversa, lo stesso drone ha mandato due messaggi diversi
 * dalla stessa lettura: e' equivocazione colta direttamente da questo
 * osservatore, senza nessun aiuto della GCS, ed e' una violazione certa.
 */
inline std::vector<DigestOutcome> registraMisura(DigestObservedState& st, double timbro,
                                                 uint64_t impronta, const DigestCheckParams& p)
{
    std::vector<DigestOutcome> out;
    if (timbro < 0)
        return out;   // misura mai eseguita: niente da registrare

    Misura *m = cercaMisura(st, timbro, p);
    if (m != nullptr) {
        if (m->stato == Stato::CONTRADDETTA || giaContesa(st, timbro, p))
            return out;   // gia' accertata falsa: non si conta due volte
        if (m->impronta != impronta) {
            ricordaContesa(st, timbro, p);
            DigestOutcome o;
            o.controllo = "coerenza fra messaggi";
            o.esito = Esito::VIOLATO;
            o.timbro = timbro;
            o.dettaglio = "due messaggi con lo stesso timbro " + detail::fmt(timbro, 3)
                        + " portano valori diversi (impronte " + detail::fmtImpronta(m->impronta)
                        + " e " + detail::fmtImpronta(impronta)
                        + "): il drone ha dichiarato due cose diverse dalla stessa lettura";
            st.violati++;
            st.violatiLocali++;
            // La lettura e' falsificata: valgono le stesse conseguenze del caso
            // in cui a smentirla sia la GCS.
            if (!m->annullata && (m->superati || m->violati || m->dubbi)) {
                o.annulla = true;
                o.annullaSuperati = m->superati;
                o.annullaViolati = m->violati;
                o.annullaDubbi = m->dubbi;
                st.annullatiSuperati += m->superati;
                st.annullatiViolati += m->violati;
                st.annullatiDubbi += m->dubbi;
                m->annullata = true;
            }
            m->stato = Stato::CONTRADDETTA;
            out.push_back(o);
        }
        return out;
    }
    if (giaContesa(st, timbro, p))
        return out;   // lettura gia' accertata falsa: non si registra di nuovo

    Misura nuova;
    nuova.timbro = timbro;
    nuova.impronta = impronta;
    st.storico.push_back(nuova);
    while (st.storico.size() > STORICO_IMPRONTE)
        st.storico.erase(st.storico.begin());

    // Se la GCS aveva gia' pubblicato l'impronta di questa lettura prima che il
    // messaggio arrivasse, il confronto scatta adesso invece di andare perduto.
    for (size_t i = 0; i < st.attese.size(); i++) {
        if (!detail::stessoTimbro(st.attese[i].timbro, timbro, p))
            continue;
        out.push_back(confrontaImpronta(st, st.storico.back(), timbro,
                                        st.attese[i].impronta, st.attese[i].fonte));
        // il non applicabile contato quando l'impronta era arrivata orfana non
        // rappresenta piu' una mancanza di copertura: il confronto e' avvenuto
        if (st.nonApplicabili > 0)
            st.nonApplicabili--;
        st.attese.erase(st.attese.begin() + i);
        break;
    }
    return out;
}

/**
 * Da chiamare subito dopo aver eseguito le regole 1-5 su una lettura: annota
 * quanti esiti quelle regole hanno prodotto, cosi' che un eventuale
 * annullamento sappia che cosa togliere.
 */
inline void annotaEsiti(DigestObservedState& st, double timbro,
                        long superati, long violati, long dubbi,
                        const DigestCheckParams& p)
{
    Misura *m = cercaMisura(st, timbro, p);
    if (m == nullptr || m->annullata)
        return;
    m->superati += superati;
    m->violati += violati;
    m->dubbi += dubbi;
}

/**
 * Confronto con un'impronta pubblicata dalla GCS.
 *
 * Tre casi soltanto:
 *   - la lettura non e' fra quelle osservate da questo nodo: NON_APPLICABILE,
 *     e si conta, perche' il numero di non applicabili e' la misura della
 *     copertura del meccanismo;
 *   - impronte uguali: SUPERATO, e la lettura diventa confermata;
 *   - impronte diverse: VIOLATO certo, la lettura diventa contraddetta e gli
 *     esiti che le regole 1-5 ne avevano tratto vengono annullati.
 *
 * Una lettura gia' verificata non viene riesaminata: la GCS ripubblica le
 * stesse impronte in piu' bollettini di fila per resistere alla perdita di
 * pacchetti, e senza questo controllo i contatori si gonfierebbero.
 */
inline std::vector<DigestOutcome> checkDigest(DigestObservedState& st, double timbro,
                                              uint64_t improntaGcs, Fonte fonte,
                                              const DigestCheckParams& p)
{
    std::vector<DigestOutcome> out;
    DigestOutcome o;
    o.timbro = timbro;
    o.controllo = "coerenza fra canali";

    Misura *m = cercaMisura(st, timbro, p);
    if (m == nullptr) {
        o.esito = Esito::NON_APPLICABILE;
        o.dettaglio = "la GCS ha pubblicato l'impronta della lettura con timbro "
                    + detail::fmt(timbro, 3) + " ma questo nodo non l'ha ricevuta";
        st.nonApplicabili++;
        // Potrebbe arrivare piu' tardi: si tiene da parte, senza duplicati.
        bool gia = false;
        for (auto& a : st.attese)
            if (detail::stessoTimbro(a.timbro, timbro, p))
                gia = true;
        if (!gia) {
            ImprontaAttesa a;
            a.timbro = timbro;
            a.impronta = improntaGcs;
            a.fonte = fonte;
            st.attese.push_back(a);
            while (st.attese.size() > ATTESE_IMPRONTE)
                st.attese.erase(st.attese.begin());
        }
        out.push_back(o);
        return out;
    }

    if (m->stato != Stato::NON_VERIFICATA)
        return out;   // gia' verificata in un bollettino precedente

    out.push_back(confrontaImpronta(st, *m, timbro, improntaGcs, fonte));
    return out;
}

/**
 * La GCS ha pubblicato DUE impronte diverse per la stessa lettura.
 *
 * E' il caso piu' forte di tutti, ed e' quello che si presenta quando
 * l'attaccante dichiara una cosa nei BANT e un'altra nelle voci di traccia: la
 * GCS riceve entrambe e le pubblica entrambe. Qui non serve nemmeno che il
 * drone abbia la propria copia della lettura: due dichiarazioni firmate dallo
 * stesso nodo, nate dalla stessa lettura e con contenuto diverso, sono gia' la
 * prova. Se il drone la copia ce l'ha, gli esiti che le regole 1-5 ne avevano
 * tratto vengono annullati come negli altri casi.
 */
inline std::vector<DigestOutcome> segnalaContesa(DigestObservedState& st, double timbro,
                                                 uint64_t impA, uint64_t impB,
                                                 Fonte fonteA, Fonte fonteB,
                                                 const DigestCheckParams& p)
{
    std::vector<DigestOutcome> out;
    if (timbro < 0 || impA == impB)
        return out;
    if (giaContesa(st, timbro, p))
        return out;   // gia' accertata falsa: l'allerta ripetuta non si riconta
    ricordaContesa(st, timbro, p);

    Misura *m = cercaMisura(st, timbro, p);
    if (m == nullptr) {
        // Il drone non ha quella lettura, ma la prova e' completa lo stesso.
        // La si registra come falsificata, cosi' se il messaggio arrivera' piu'
        // tardi non verra' contato un'altra volta.
        Misura nuova;
        nuova.timbro = timbro;
        nuova.impronta = impA;
        nuova.stato = Stato::CONTRADDETTA;
        st.storico.push_back(nuova);
        while (st.storico.size() > STORICO_IMPRONTE)
            st.storico.erase(st.storico.begin());
        m = &st.storico.back();
    }

    DigestOutcome o;
    o.timbro = timbro;
    o.controllo = "coerenza fra canali";
    o.esito = Esito::VIOLATO;
    o.dettaglio = "alla GCS sono arrivate due dichiarazioni diverse della stessa lettura (timbro "
                + detail::fmt(timbro, 3) + "): impronta " + detail::fmtImpronta(impA)
                + " da " + std::string(fonteStr(fonteA)) + ", impronta " + detail::fmtImpronta(impB)
                + " da " + std::string(fonteStr(fonteB))
                + ": il drone ha dichiarato due cose diverse";
    m->stato = Stato::CONTRADDETTA;
    st.contraddette++;
    st.violati++;
    if (!m->annullata && (m->superati || m->violati || m->dubbi)) {
        o.annulla = true;
        o.annullaSuperati = m->superati;
        o.annullaViolati = m->violati;
        o.annullaDubbi = m->dubbi;
        st.annullatiSuperati += m->superati;
        st.annullatiViolati += m->violati;
        st.annullatiDubbi += m->dubbi;
        m->annullata = true;
    }
    out.push_back(o);
    return out;
}

/** Quante letture in memoria non hanno ancora ricevuto un'impronta dalla GCS. */
inline long nonVerificate(const DigestObservedState& st)
{
    long n = 0;
    for (auto& m : st.storico)
        if (m.stato == Stato::NON_VERIFICATA)
            n++;
    return n;
}

// ---------------------------------------------------------------------------
// Formato del bollettino che la GCS pubblica nel proprio cluster
// ---------------------------------------------------------------------------
//
// Il contenuto e' diviso in SEZIONI, ciascuna con un tipo e un numero di
// record. Una sezione di tipo sconosciuto viene saltata leggendone la
// lunghezza: questo permette di aggiungere domani la sezione degli hop senza
// cambiare il formato e senza rendere incompatibile quello che avremo gia'
// provato. E' l'unico motivo per cui il bollettino non e' una lista piatta.
//
namespace wire {

enum class TipoSezione : uint8_t {
    IMPRONTE = 1,   // impronte delle letture osservate dalla GCS
    REQ      = 2,   // registro dei reclutamenti osservati dalla GCS
    HOP      = 3    // riservata alla regola sugli hop, non ancora usata
};

/** Una riga della sezione delle impronte: 21 byte. */
struct RecordImpronta {
    uint32_t nodo = 0;
    double timbro = -1;
    uint64_t impronta = 0;
    uint8_t fonte = 0;    // valore di Fonte
};
constexpr size_t LEN_IMPRONTA = 4 + 8 + 8 + 1;

/**
 * Una riga della sezione dei REQ: 44 byte.
 *
 * Sono i fatti che un drone non puo' procurarsi da solo, perche' un REQ
 * raggiunge solo una parte degli osservatori: nelle misure fatte, un REQ e'
 * arrivato a 6 osservatori su 18, mentre le GCS ne hanno visti 7 o 8 su 8.
 * Questa sezione e' cio' che trasforma in certezze i dubbi delle regole 2 e 4.
 */
struct RecordReq {
    uint32_t mittente = 0;        // chi ha chiesto aiuto
    uint32_t destinatario = 0;    // drone scelto (uguale al mittente = avviso di batteria)
    double x = 0, y = 0, z = 0;   // posizione del richiedente, serve alla regola 2
    uint32_t seq = 0;
    double istante = 0;
};
constexpr size_t LEN_REQ = 4 + 4 + 8 * 3 + 4 + 8;

/** Intestazione di una sezione: tipo (1) + numero di record (2). */
constexpr size_t LEN_INTESTAZIONE_SEZIONE = 3;

namespace det {
template <typename T> inline void put(std::vector<uint8_t>& v, const T& x)
{
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&x);
    v.insert(v.end(), p, p + sizeof(T));
}
template <typename T> inline T get(const uint8_t *&p)
{
    T x;
    std::memcpy(&x, p, sizeof(T));
    p += sizeof(T);
    return x;
}
}

/** Dati associati (autenticati) di un bollettino. */
inline std::vector<uint8_t> bollettinoAad(uint32_t origin, uint32_t giro, uint32_t contatore,
                                          uint32_t numByte)
{
    using det::put;
    std::vector<uint8_t> v;
    const char dom[4] = {'D', 'G', 'S', '0'};
    v.insert(v.end(), dom, dom + 4);
    put(v, origin); put(v, giro); put(v, contatore); put(v, numByte);
    return v;
}

inline void scriviSezioneImpronte(std::vector<uint8_t>& v, const std::vector<RecordImpronta>& recs)
{
    using det::put;
    if (recs.empty())
        return;
    put(v, (uint8_t)TipoSezione::IMPRONTE);
    put(v, (uint16_t)recs.size());
    for (auto& r : recs) {
        put(v, r.nodo);
        put(v, r.timbro);
        put(v, r.impronta);
        put(v, r.fonte);
    }
}

inline void scriviSezioneReq(std::vector<uint8_t>& v, const std::vector<RecordReq>& recs)
{
    using det::put;
    if (recs.empty())
        return;
    put(v, (uint8_t)TipoSezione::REQ);
    put(v, (uint16_t)recs.size());
    for (auto& r : recs) {
        put(v, r.mittente);
        put(v, r.destinatario);
        put(v, r.x); put(v, r.y); put(v, r.z);
        put(v, r.seq);
        put(v, r.istante);
    }
}

/**
 * Legge il bollettino. Restituisce false solo se il contenuto e' malformato,
 * cioe' se una sezione dichiara piu' record di quanti ce ne stiano: una sezione
 * di tipo sconosciuto non e' un errore, viene saltata.
 */
/**
 * Legge le sezioni di un bollettino.
 *
 * sezioneReq, se passato, dice se la SEZIONE dei REQ era presente, cosa diversa
 * dall'essere vuota: una sezione vuota significa che la GCS non conosceva nessun
 * REQ, e vale come prova; una sezione assente significa soltanto che la GCS non
 * pubblica i REQ, e non prova niente. La regola 2 condanna un dubbio solo nel
 * primo caso.
 */
inline bool leggiBollettino(const std::vector<uint8_t>& v,
                            std::vector<RecordImpronta>& impronte,
                            std::vector<RecordReq>& req,
                            bool *sezioneReq = nullptr)
{
    using det::get;
    impronte.clear();
    req.clear();
    if (sezioneReq)
        *sezioneReq = false;
    size_t off = 0;
    while (off < v.size()) {
        if (v.size() - off < LEN_INTESTAZIONE_SEZIONE)
            return false;
        const uint8_t *p = v.data() + off;
        uint8_t tipo = get<uint8_t>(p);
        uint16_t n = get<uint16_t>(p);
        off += LEN_INTESTAZIONE_SEZIONE;
        size_t lenRec;
        switch ((TipoSezione)tipo) {
            case TipoSezione::IMPRONTE: lenRec = LEN_IMPRONTA; break;
            case TipoSezione::REQ:
                lenRec = LEN_REQ;
                if (sezioneReq)
                    *sezioneReq = true;
                break;
            default:
                // Sezione sconosciuta: non sappiamo quanto e' lunga una riga,
                // quindi non possiamo saltarla in modo sicuro e ci fermiamo
                // qui. Le sezioni note vengono scritte sempre per prime.
                return true;
        }
        if (v.size() - off < (size_t)n * lenRec)
            return false;
        for (uint16_t i = 0; i < n; i++) {
            const uint8_t *q = v.data() + off + (size_t)i * lenRec;
            if ((TipoSezione)tipo == TipoSezione::IMPRONTE) {
                RecordImpronta r;
                r.nodo = get<uint32_t>(q);
                r.timbro = get<double>(q);
                r.impronta = get<uint64_t>(q);
                r.fonte = get<uint8_t>(q);
                impronte.push_back(r);
            }
            else {
                RecordReq r;
                r.mittente = get<uint32_t>(q);
                r.destinatario = get<uint32_t>(q);
                r.x = get<double>(q); r.y = get<double>(q); r.z = get<double>(q);
                r.seq = get<uint32_t>(q);
                r.istante = get<double>(q);
                req.push_back(r);
            }
        }
        off += (size_t)n * lenRec;
    }
    return true;
}

}   // namespace wire

}   // namespace ant2digest

#endif
