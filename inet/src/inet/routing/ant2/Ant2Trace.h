//
// Ant2Trace.h
//
// Traceroute delle GCS: formato delle voci e funzioni di supporto "pure",
// senza dipendenze da OMNeT++/INET, verificate dai test automatici
// (test_trace.cc).
//
// Una voce e' aggiunta da ogni nodo che la traccia attraversa (bersaglio
// compreso). Contiene, in chiaro dentro il payload cifrato:
//   - l'identita' del nodo e quella del nodo da cui ha ricevuto la traccia;
//   - l'istante di ricezione e il valore di hopdistance con cui l'ha ricevuta;
//   - gli stessi parametri che il nodo dichiara nei BANT: throughput, energia,
//     posizione, banda massima, cluster, disponibilita', timbro di misura;
//   - l'elenco dei vicini che il nodo sente (al massimo MAX_VICINI), con cui
//     le GCS ricostruiscono il grafo dei collegamenti.
//
// Formato sul canale di una voce:
//   identita' (4, in chiaro) | contatore (4, in chiaro) |
//   payload cifrato (PLAIN_LEN) | tag AEAD (tagLen) | firma (SIG_LEN)
// identita' e contatore restano in chiaro perche' servono a chi verifica per
// scegliere la chiave pubblica e ricalcolare il nonce; sono comunque
// autenticati (fanno parte dei dati associati e della firma).
//
// La firma di ogni voce copre: dati associati | payload cifrato | tag |
// firma della voce precedente (per la prima voce, la firma della GCS). Le voci
// formano cosi' una catena: togliere, modificare o riordinare una voce rompe
// tutte le firme successive.
//

#ifndef __INET_ANT2TRACE_H
#define __INET_ANT2TRACE_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

namespace inet {
namespace ant2trace {

enum Esito : uint8_t {
    IN_CORSO = 0,        // andata in corso / ritorno di una traccia arrivata al bersaglio
    ROTTA_MANCANTE = 1,  // un nodo non aveva una rotta verso il bersaglio
    LIMITE_HOP = 2,      // raggiunto il numero massimo di passaggi
    CICLO = 3            // il prossimo nodo era gia' nel percorso
};

inline const char *esitoStr(uint8_t e)
{
    switch (e) {
        case IN_CORSO: return "completa";
        case ROTTA_MANCANTE: return "rotta mancante";
        case LIMITE_HOP: return "limite hop";
        case CICLO: return "ciclo";
        default: return "?";
    }
}

/** Contenuto di una voce (payload in chiaro). */
struct EntryData
{
    uint32_t node = 0;        // identita' del nodo (indirizzo wlan0)
    uint32_t prev = 0;        // identita' del nodo da cui ha ricevuto la traccia
    double recvTime = 0;      // istante di ricezione (s)
    int32_t hopRecv = 0;      // hopdistance con cui ha ricevuto la traccia
    // parametri dei BANT
    double throughput = 0;
    double energy = 0;
    double x = 0, y = 0, z = 0;
    double maxBand = 0;
    int32_t cluster = 0;
    uint8_t allowed = 0;
    double timbro = -1;
    std::vector<uint32_t> vicini;   // indirizzi dei vicini sentiti di recente (al massimo MAX_VICINI)
};

/** Numero massimo di vicini riportati in una voce. */
constexpr size_t MAX_VICINI = 12;

/** Lunghezza del payload in chiaro di una voce. */
constexpr size_t PLAIN_LEN = 4 + 4 + 8 + 4 + 8 + 8 + 8 * 3 + 8 + 4 + 1 + 8 + 1 + 4 * MAX_VICINI;   // 130 byte

/** Lunghezza di una voce sul canale. */
inline size_t entryWireLen(int tagLen, int sigLen) { return 4 + 4 + PLAIN_LEN + tagLen + sigLen; }

namespace detail {
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

inline std::vector<uint8_t> pack(const EntryData& e)
{
    using detail::put;
    std::vector<uint8_t> v;
    v.reserve(PLAIN_LEN);
    put(v, e.node); put(v, e.prev); put(v, e.recvTime); put(v, e.hopRecv);
    put(v, e.throughput); put(v, e.energy); put(v, e.x); put(v, e.y); put(v, e.z);
    put(v, e.maxBand); put(v, e.cluster); put(v, e.allowed); put(v, e.timbro);
    uint8_t nv = (uint8_t)std::min(e.vicini.size(), MAX_VICINI);
    put(v, nv);
    for (size_t i = 0; i < MAX_VICINI; i++)
        put(v, i < nv ? e.vicini[i] : (uint32_t)0);
    return v;
}

inline bool unpack(const std::vector<uint8_t>& v, EntryData& e)
{
    using detail::get;
    if (v.size() != PLAIN_LEN)
        return false;
    const uint8_t *p = v.data();
    e.node = get<uint32_t>(p); e.prev = get<uint32_t>(p); e.recvTime = get<double>(p); e.hopRecv = get<int32_t>(p);
    e.throughput = get<double>(p); e.energy = get<double>(p);
    e.x = get<double>(p); e.y = get<double>(p); e.z = get<double>(p);
    e.maxBand = get<double>(p); e.cluster = get<int32_t>(p); e.allowed = get<uint8_t>(p); e.timbro = get<double>(p);
    uint8_t nv = get<uint8_t>(p);
    if (nv > MAX_VICINI)
        return false;
    e.vicini.clear();
    for (size_t i = 0; i < MAX_VICINI; i++) {
        uint32_t a = get<uint32_t>(p);
        if (i < nv)
            e.vicini.push_back(a);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Snapshot di un cluster, scambiato tra le GCS
// ---------------------------------------------------------------------------

/** Numero massimo di nodi del percorso riportati per ogni record. */
constexpr size_t MAX_PERCORSO = 4;

/** Un nodo dello snapshot di un cluster: dati, hop dalla GCS e percorso. */
struct SnapRecord
{
    EntryData dati;
    uint8_t hop = 0;                   // hop dalla GCS che lo ha tracciato
    std::vector<uint32_t> percorso;    // nodi intermedi + il nodo stesso (al massimo MAX_PERCORSO)
};

constexpr size_t SNAP_REC_LEN = PLAIN_LEN + 1 + 1 + 4 * MAX_PERCORSO;   // 148 byte

inline std::vector<uint8_t> packSnapshot(const std::vector<SnapRecord>& recs)
{
    using detail::put;
    std::vector<uint8_t> v;
    for (auto& r : recs) {
        std::vector<uint8_t> d = pack(r.dati);
        v.insert(v.end(), d.begin(), d.end());
        put(v, r.hop);
        uint8_t np = (uint8_t)std::min(r.percorso.size(), MAX_PERCORSO);
        put(v, np);
        for (size_t i = 0; i < MAX_PERCORSO; i++)
            put(v, i < np ? r.percorso[i] : (uint32_t)0);
    }
    return v;
}

inline bool unpackSnapshot(const std::vector<uint8_t>& v, std::vector<SnapRecord>& out)
{
    using detail::get;
    out.clear();
    if (v.size() % SNAP_REC_LEN != 0)
        return false;
    for (size_t off = 0; off < v.size(); off += SNAP_REC_LEN) {
        SnapRecord r;
        std::vector<uint8_t> d(v.begin() + off, v.begin() + off + PLAIN_LEN);
        if (!unpack(d, r.dati))
            return false;
        const uint8_t *p = v.data() + off + PLAIN_LEN;
        r.hop = get<uint8_t>(p);
        uint8_t np = get<uint8_t>(p);
        if (np > MAX_PERCORSO)
            return false;
        for (size_t i = 0; i < MAX_PERCORSO; i++) {
            uint32_t a = get<uint32_t>(p);
            if (i < np)
                r.percorso.push_back(a);
        }
        out.push_back(r);
    }
    return true;
}

/** Dati associati (autenticati) di uno snapshot scambiato tra GCS. */
inline std::vector<uint8_t> snapshotAad(uint32_t origin, uint32_t giro, uint32_t contatore, uint32_t numRecord)
{
    std::vector<uint8_t> v;
    const char dom[4] = {'S', 'N', 'P', '0'};
    v.insert(v.end(), dom, dom + 4);
    detail::put(v, origin); detail::put(v, giro); detail::put(v, contatore); detail::put(v, numRecord);
    return v;
}

/** Dati associati (autenticati ma in chiaro) di una voce. */
inline std::vector<uint8_t> entryAad(uint32_t origin, uint32_t target, uint32_t traceId,
                                     uint32_t index, uint32_t node, uint32_t counter)
{
    std::vector<uint8_t> v;
    detail::put(v, origin); detail::put(v, target); detail::put(v, traceId);
    detail::put(v, index); detail::put(v, node); detail::put(v, counter);
    return v;
}

/** Dati firmati dalla GCS all'origine della traccia. */
inline std::vector<uint8_t> originSigned(uint32_t origin, uint32_t target, uint32_t traceId)
{
    std::vector<uint8_t> v;
    const char dom[4] = {'T', 'R', 'C', '0'};
    v.insert(v.end(), dom, dom + 4);
    detail::put(v, origin); detail::put(v, target); detail::put(v, traceId);
    return v;
}

/** Messaggio firmato da un nodo per la propria voce (catena). */
inline std::vector<uint8_t> entrySigned(const std::vector<uint8_t>& aad, const std::vector<uint8_t>& ciphertext,
                                        const uint8_t *tag, int tagLen, const uint8_t *prevSig, int sigLen)
{
    std::vector<uint8_t> v = aad;
    v.insert(v.end(), ciphertext.begin(), ciphertext.end());
    v.insert(v.end(), tag, tag + tagLen);
    v.insert(v.end(), prevSig, prevSig + sigLen);
    return v;
}

/**
 * Controllo di coerenza del percorso ricostruito dalla GCS: ogni voce deve
 * dichiarare come nodo precedente quello della voce prima (per la prima voce,
 * la GCS). Restituisce l'indice della prima voce incoerente, -1 se tutte
 * coerenti.
 */
inline int primaVoceIncoerente(const std::vector<EntryData>& voci, uint32_t origin)
{
    for (size_t i = 0; i < voci.size(); i++) {
        uint32_t atteso = i == 0 ? origin : voci[i - 1].node;
        if (voci[i].prev != atteso)
            return (int)i;
    }
    return -1;
}

} // namespace ant2trace
} // namespace inet

#endif
