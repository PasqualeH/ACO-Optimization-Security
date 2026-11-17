//
// test_trace.cc - test automatici del formato delle voci del traceroute delle
// GCS (Ant2Trace.h) e della catena di firme, con le stesse primitive
// crittografiche usate dal protocollo (Ascon-AEAD128 ed Ed25519).
//
// Come gli altri test, tutto il file e' racchiuso in una #ifdef, cosi' la
// build di INET lo compila come file vuoto. Per eseguirlo, dalla cartella
// inet/src/inet/routing/ant2/:
//
//   g++ -std=c++17 -DANT2_TEST_STANDALONE -I. -I../../.. -o test_trace \
//       test_trace.cc Ant2Aead.cc Ant2Sign.cc \
//       crypto/ascon/*.cc crypto/aead/*.cc crypto/ed25519/*.cc crypto/ecdsa/uECC.cc \
//       crypto/xoodyak/*.cc crypto/tinyjambu/*.cc crypto/lwc-common/*.cc
//   ./test_trace
//

#ifdef ANT2_TEST_STANDALONE

#include <cstdio>
#include <map>
#include "inet/routing/ant2/Ant2Trace.h"
#include "inet/routing/ant2/Ant2Aead.h"
#include "inet/routing/ant2/Ant2Sign.h"
extern "C" {
#include "crypto/ed25519/sha512.h"
}

using namespace inet;
using namespace inet::ant2trace;

static int falliti = 0, eseguiti = 0;
static void verifica(bool c, const char *d)
{
    eseguiti++;
    if (!c) falliti++;
    std::printf("[%s] %s\n", c ? " OK " : "FAIL", d);
}

static const ant2aead::Algorithm AEAD = ant2aead::ASCON128;
static const ant2sign::Algorithm SIG = ant2sign::ED25519;
static uint8_t chiaveGruppo[32];

struct Nodo { uint32_t ind; uint8_t pub[64], priv[64]; uint32_t contatore = 0; };
static std::map<uint32_t, Nodo> flotta;

static Nodo& nuovoNodo(uint32_t ind)
{
    Nodo n; n.ind = ind;
    uint8_t seme[32];
    for (int i = 0; i < 32; i++) seme[i] = (uint8_t)(ind * 31 + i);
    ant2sign::generateKeypair(SIG, seme, n.pub, n.priv);
    flotta[ind] = n;
    return flotta[ind];
}

static void nonceDi(uint32_t nodo, uint32_t contatore, uint8_t out[16])
{
    // Stesso schema di Ant2Crypto::deriveNonce: i primi 16 byte dell'impronta
    // SHA-512 di "ANT2" || nodo || altro nodo || contatore || tipo, dove per le
    // voci di traccia l'altro nodo e' 0 (il contatore e' del nodo stesso) e il
    // tipo e' MSG_TRACE, cioe' 4.
    uint8_t buf[17];
    memcpy(buf, "ANT2", 4);
    memcpy(buf + 4, &nodo, 4);
    uint32_t peer = 0;
    memcpy(buf + 8, &peer, 4);
    memcpy(buf + 12, &contatore, 4);
    buf[16] = 4;
    uint8_t digest[64];
    sha512(buf, sizeof(buf), digest);
    memset(out, 0, 16);
    memcpy(out, digest, 16);
}

// Una traccia, come la vede la GCS al ritorno
struct Voce { uint32_t nodo, contatore; std::vector<uint8_t> ct; uint8_t tag[16]; uint8_t firma[64]; };
struct Traccia { uint32_t origine, bersaglio, id; uint8_t firmaOrigine[64]; std::vector<Voce> voci; };

static void aggiungiVoce(Traccia& t, Nodo& n, const EntryData& dati)
{
    Voce v; v.nodo = n.ind; v.contatore = ++n.contatore;
    std::vector<uint8_t> pt = pack(dati);
    std::vector<uint8_t> aad = entryAad(t.origine, t.bersaglio, t.id, (uint32_t)t.voci.size(), v.nodo, v.contatore);
    uint8_t nonce[16]; nonceDi(v.nodo, v.contatore, nonce);
    v.ct.resize(pt.size());
    ant2aead::encrypt(AEAD, chiaveGruppo, nonce, aad.data(), aad.size(), pt.data(), pt.size(), v.ct.data(), v.tag);
    const uint8_t *prec = t.voci.empty() ? t.firmaOrigine : t.voci.back().firma;
    std::vector<uint8_t> m = entrySigned(aad, v.ct, v.tag, 16, prec, 64);
    ant2sign::sign(SIG, n.priv, n.pub, m.data(), m.size(), v.firma);
    t.voci.push_back(v);
}

// Verifica della GCS: restituisce l'indice della prima voce non valida (-1 se tutte valide)
static int verificaTraccia(const Traccia& t, std::vector<EntryData>& out)
{
    out.clear();
    for (size_t i = 0; i < t.voci.size(); i++) {
        const Voce& v = t.voci[i];
        auto f = flotta.find(v.nodo);
        if (f == flotta.end()) return (int)i;
        std::vector<uint8_t> aad = entryAad(t.origine, t.bersaglio, t.id, (uint32_t)i, v.nodo, v.contatore);
        const uint8_t *prec = i == 0 ? t.firmaOrigine : t.voci[i - 1].firma;
        std::vector<uint8_t> m = entrySigned(aad, v.ct, v.tag, 16, prec, 64);
        if (!ant2sign::verify(SIG, f->second.pub, m.data(), m.size(), v.firma)) return (int)i;
        uint8_t nonce[16]; nonceDi(v.nodo, v.contatore, nonce);
        std::vector<uint8_t> pt(v.ct.size());
        if (!ant2aead::decrypt(AEAD, chiaveGruppo, nonce, aad.data(), aad.size(), v.ct.data(), v.ct.size(), v.tag, pt.data()))
            return (int)i;
        EntryData e;
        if (!unpack(pt, e) || e.node != v.nodo) return (int)i;
        out.push_back(e);
    }
    return -1;
}

static EntryData dati(uint32_t nodo, uint32_t prec, double t, int h, double energia)
{
    EntryData e; e.node = nodo; e.prev = prec; e.recvTime = t; e.hopRecv = h;
    e.energy = energia; e.throughput = 0.25; e.x = 300; e.y = 500; e.z = 50;
    e.maxBand = 0.4; e.cluster = 1; e.allowed = 1; e.timbro = t - 0.5;
    return e;
}

static Traccia tracciaOnesta(Nodo& gcs, Nodo& a, Nodo& b, Nodo& c, bool attaccoHop)
{
    Traccia t; t.origine = gcs.ind; t.bersaglio = c.ind; t.id = 7;
    std::vector<uint8_t> o = originSigned(t.origine, t.bersaglio, t.id);
    ant2sign::sign(SIG, gcs.priv, gcs.pub, o.data(), o.size(), t.firmaOrigine);
    aggiungiVoce(t, a, dati(a.ind, gcs.ind, 10.001, 1, 80.0));
    aggiungiVoce(t, b, dati(b.ind, a.ind, 10.002, 2, 60.0));
    // con l'attacco agli hop b non incrementa: c riceve h = 2 invece di 3
    aggiungiVoce(t, c, dati(c.ind, b.ind, 10.003, attaccoHop ? 2 : 3, 40.0));
    return t;
}

int main()
{
    for (int i = 0; i < 32; i++) chiaveGruppo[i] = (uint8_t)(200 - i);
    Nodo& gcs = nuovoNodo(0x0A000101);
    Nodo& a = nuovoNodo(0x0A000102);
    Nodo& b = nuovoNodo(0x0A000103);
    Nodo& c = nuovoNodo(0x0A000104);

    std::printf("== Formato della voce ==\n");
    {
        EntryData e = dati(5, 4, 12.345, 3, 77.77);
        e.vicini = {11, 12, 13};
        std::vector<uint8_t> v = pack(e);
        EntryData r;
        verifica(v.size() == PLAIN_LEN && PLAIN_LEN == 130, "payload in chiaro di 130 byte (12 vicini al massimo)");
        verifica(unpack(v, r) && r.node == 5 && r.prev == 4 && r.hopRecv == 3 && r.energy == 77.77 && r.timbro == e.timbro,
                 "pack/unpack restituiscono gli stessi valori");
        verifica(r.vicini.size() == 3 && r.vicini[0] == 11 && r.vicini[2] == 13, "l'elenco dei vicini viene conservato");
        e.vicini.assign(20, 7);
        verifica(unpack(pack(e), r) && r.vicini.size() == MAX_VICINI, "oltre 12 vicini se ne riportano 12");
        verifica(entryWireLen(16, 64) == 218, "voce sul canale: 218 byte con tag da 16 e firma da 64");
    }

    std::printf("\n== Traccia onesta GCS -> A -> B -> C ==\n");
    Traccia t = tracciaOnesta(gcs, a, b, c, false);
    std::vector<EntryData> voci;
    {
        int bad = verificaTraccia(t, voci);
        verifica(bad == -1 && voci.size() == 3, "tutte le firme e le cifrature sono valide");
        verifica(primaVoceIncoerente(voci, gcs.ind) == -1, "ogni voce indica come precedente il nodo della voce prima");
        verifica(voci[0].hopRecv == 1 && voci[1].hopRecv == 2 && voci[2].hopRecv == 3, "hop ricevuti 1, 2, 3");
        verifica(voci[2].energy == 40.0 && voci[1].energy == 60.0, "la GCS legge i parametri dichiarati da ogni nodo");
    }

    std::printf("\n== Manomissioni ==\n");
    {
        Traccia m = t; m.voci[1].ct[10] ^= 0x01;
        verifica(verificaTraccia(m, voci) == 1, "un byte cambiato nella voce di B: scoperto alla voce 1");
    }
    {
        Traccia m = t; m.voci.erase(m.voci.begin() + 1);
        verifica(verificaTraccia(m, voci) == 1, "voce di B tolta: la voce di C non si verifica piu' (catena rotta)");
    }
    {
        Traccia m = t; std::swap(m.voci[0], m.voci[1]);
        verifica(verificaTraccia(m, voci) == 0, "voci di A e B scambiate: scoperto alla voce 0");
    }
    {
        Traccia m = t; m.bersaglio = a.ind;
        verifica(verificaTraccia(m, voci) == 0, "bersaglio cambiato: nessuna voce si verifica");
    }
    {
        Traccia m = t; m.voci[2].firma[0] ^= 0xFF;
        verifica(verificaTraccia(m, voci) == 2, "firma di C alterata: scoperto alla voce 2");
    }
    {
        // B scrive una voce a nome di A (non ha la chiave privata di A)
        Traccia m; m.origine = gcs.ind; m.bersaglio = c.ind; m.id = 8;
        std::vector<uint8_t> o = originSigned(m.origine, m.bersaglio, m.id);
        ant2sign::sign(SIG, gcs.priv, gcs.pub, o.data(), o.size(), m.firmaOrigine);
        Nodo falso = b; falso.ind = a.ind;   // identita' di A, chiave di B
        aggiungiVoce(m, falso, dati(a.ind, gcs.ind, 10.001, 1, 80.0));
        verifica(verificaTraccia(m, voci) == 0, "voce falsa a nome di un altro nodo: firma non valida");
    }
    {
        Traccia m = tracciaOnesta(gcs, a, b, c, false);
        // C dichiara come precedente A invece di B: firma valida, ma percorso incoerente
        m.voci.pop_back();
        aggiungiVoce(m, c, dati(c.ind, a.ind, 10.003, 3, 40.0));
        verifica(verificaTraccia(m, voci) == -1 && primaVoceIncoerente(voci, gcs.ind) == 2,
                 "nodo precedente dichiarato in modo incoerente: segnalato alla voce 2");
    }

    std::printf("\n== Nodo che non incrementa gli hop ==\n");
    {
        Traccia m = tracciaOnesta(gcs, a, b, c, true);
        verifica(verificaTraccia(m, voci) == -1, "le firme restano valide (il campo hop e' in chiaro)");
        verifica(voci[1].hopRecv == 2 && voci[2].hopRecv == 2,
                 "nello snapshot B e C compaiono entrambi con h2: il nodo che non ha incrementato e' B");
    }

    std::printf("\n== Snapshot di un cluster scambiato tra GCS ==\n");
    {
        std::vector<SnapRecord> recs(3);
        for (int i = 0; i < 3; i++) {
            recs[i].dati = dati(100 + i, 1, 20.0 + i, 1, 50.0 + i);
            recs[i].dati.vicini = {(uint32_t)(200 + i)};
            recs[i].hop = (uint8_t)(i + 1);
            for (int k = 0; k <= i; k++) recs[i].percorso.push_back(300 + k);
        }
        recs[2].percorso.assign(6, 9);   // percorso piu' lungo del massimo
        std::vector<uint8_t> v = packSnapshot(recs);
        std::vector<SnapRecord> out;
        verifica(v.size() == 3 * SNAP_REC_LEN && SNAP_REC_LEN == 148, "3 record da 148 byte");
        verifica(unpackSnapshot(v, out) && out.size() == 3 && out[1].dati.energy == 51.0 && out[1].hop == 2
                 && out[1].percorso.size() == 2 && out[0].dati.vicini[0] == 200, "pack/unpack dello snapshot");
        verifica(out[2].percorso.size() == MAX_PERCORSO, "percorso troncato a 4 nodi");
        v.pop_back();
        verifica(!unpackSnapshot(v, out), "snapshot di lunghezza sbagliata rifiutato");
        verifica(9 * SNAP_REC_LEN + 16 + 64 + 32 < 1480, "9 record stanno in un pacchetto senza frammentazione");

        // cifratura e firma dello snapshot come nel protocollo
        Nodo& g2 = flotta[gcs.ind];
        std::vector<uint8_t> pt = packSnapshot(recs);
        std::vector<uint8_t> aad = snapshotAad(g2.ind, 4, 1, 3);
        uint8_t nonce[16]; memset(nonce, 0, 16); memcpy(nonce, &g2.ind, 4); nonce[4] = 1; nonce[12] = 5;
        std::vector<uint8_t> ct(pt.size()); uint8_t tag[16], firma[64];
        ant2aead::encrypt(AEAD, chiaveGruppo, nonce, aad.data(), aad.size(), pt.data(), pt.size(), ct.data(), tag);
        std::vector<uint8_t> m = aad; m.insert(m.end(), ct.begin(), ct.end()); m.insert(m.end(), tag, tag + 16);
        ant2sign::sign(SIG, g2.priv, g2.pub, m.data(), m.size(), firma);
        verifica(ant2sign::verify(SIG, g2.pub, m.data(), m.size(), firma), "snapshot firmato dalla GCS: firma valida");
        std::vector<uint8_t> aad2 = snapshotAad(g2.ind, 5, 1, 3);   // giro cambiato
        std::vector<uint8_t> m2 = aad2; m2.insert(m2.end(), ct.begin(), ct.end()); m2.insert(m2.end(), tag, tag + 16);
        verifica(!ant2sign::verify(SIG, g2.pub, m2.data(), m2.size(), firma), "numero di giro alterato: firma non valida");
    }

    std::printf("\n%d test eseguiti, %d falliti\n", eseguiti, falliti);
    return falliti == 0 ? 0 : 1;
}

#endif // ANT2_TEST_STANDALONE
