//
// Ant2Trace.cc - traceroute delle GCS e snapshot della rete.
//
// Ogni GCS (traceEnabled = true), a intervalli casuali tra traceIntervalMin e
// traceIntervalMax contati dalla chiusura del giro precedente, lancia un
// "giro" di tracce: una traccia verso ogni nodo presente nella sua tabella di
// stato. Le tracce rimaste senza risposta dopo traceRetryDelay vengono
// rilanciate una seconda volta. Ogni passaggio della traccia e' trasmesso in
// unicast al nodo successivo, con conferma e ritrasmissione del livello MAC. Ogni traccia segue la tabella di
// routing dei nodi; ogni nodo attraversato aggiunge una voce con i parametri
// che dichiara nei BANT (vedi Ant2Trace.h) e la passa al vicino indicato dalla
// sua tabella per il bersaglio. Il bersaglio aggiunge la sua voce e rimanda la
// traccia indietro lungo lo stesso percorso. La GCS verifica le voci (firme a
// catena e cifratura) e, alla chiusura del giro, scrive lo snapshot della rete
// nel file ant2_snapshot_<...>.log: percorso e hop verso ogni nodo, e l'ultimo
// dato noto di ogni nodo.
//
// Nessun controllo della metrica di trust viene eseguito qui: lo snapshot e'
// solo raccolto e registrato.
//

#include "inet/routing/ant2/Ant2.h"

#include <iomanip>
#include <sstream>
#include <algorithm>

#include "inet/common/ProtocolTag_m.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/networklayer/ipv4/Ipv4Route.h"

namespace inet {
namespace ant2 {

using namespace ant2trace;

static const int TRACE_PACKET_KIND = 3;   // = TRACE_PACKET in Ant2.cc

// ---------------------------------------------------------------------------
// Lettura delle voci dal formato sul canale
// ---------------------------------------------------------------------------
namespace {

struct WireEntry {
    uint32_t node = 0, counter = 0;
    std::vector<uint8_t> ct;
    uint8_t tag[Ant2Crypto::MAX_TAG_LEN] = {0};
    uint8_t sig[Ant2Crypto::SIG_LEN] = {0};
};

size_t wireLen(int tagLen) { return entryWireLen(tagLen, Ant2Crypto::SIG_LEN); }

WireEntry readEntry(const TraceM2 *t, int i, int tagLen)
{
    WireEntry w;
    size_t off = (size_t)i * wireLen(tagLen);
    auto byte = [&](size_t k) { return t->getEntries(off + k); };
    uint8_t buf[8];
    for (int k = 0; k < 4; k++) buf[k] = byte(k);
    memcpy(&w.node, buf, 4);
    for (int k = 0; k < 4; k++) buf[k] = byte(4 + k);
    memcpy(&w.counter, buf, 4);
    w.ct.resize(PLAIN_LEN);
    for (size_t k = 0; k < PLAIN_LEN; k++) w.ct[k] = byte(8 + k);
    for (int k = 0; k < tagLen; k++) w.tag[k] = byte(8 + PLAIN_LEN + k);
    for (int k = 0; k < Ant2Crypto::SIG_LEN; k++) w.sig[k] = byte(8 + PLAIN_LEN + tagLen + k);
    return w;
}

void signatureOf(const TraceM2 *t, int i, int tagLen, uint8_t out[Ant2Crypto::SIG_LEN])
{
    if (i < 0) {
        for (int k = 0; k < Ant2Crypto::SIG_LEN; k++) out[k] = t->getOriginSignature(k);
        return;
    }
    size_t off = (size_t)i * wireLen(tagLen) + 8 + PLAIN_LEN + tagLen;
    for (int k = 0; k < Ant2Crypto::SIG_LEN; k++) out[k] = t->getEntries(off + k);
}

uint32_t nodeOf(const TraceM2 *t, int i, int tagLen)
{
    size_t off = (size_t)i * wireLen(tagLen);
    uint8_t buf[4];
    for (int k = 0; k < 4; k++) buf[k] = t->getEntries(off + k);
    uint32_t n;
    memcpy(&n, buf, 4);
    return n;
}

std::string fmtD(double v, int dec)
{
    std::ostringstream o;
    o << std::fixed << std::setprecision(dec) << v;
    return o.str();
}

} // namespace

// ---------------------------------------------------------------------------
// Indirizzi del nodo
// ---------------------------------------------------------------------------

Ipv4Address Ant2::ownIdentity() const
{
    // identita' crittografica del nodo: indirizzo della prima interfaccia wlan
    return interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
}

bool Ant2::isOwnAddress(const Ipv4Address& a) const
{
    for (auto ie : wirelessInterfaces)
        if (ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress() == a)
            return true;
    return a == x2ppp_address && !a.isUnspecified();
}

// ---------------------------------------------------------------------------
// Giro di tracce (solo GCS)
// ---------------------------------------------------------------------------

void Ant2::startTraceRound()
{
    if (traceRoundOpen)
        closeTraceRound(false);
    traceRound++;
    traceRoundStart = simTime().dbl();
    traceRoundOpen = true;
    traceCurrent.clear();

    // Bersagli: i nodi del cluster della GCS, cioe' quelli della tabella di
    // stato che nell'ultimo BANT hanno dichiarato lo stesso cluster della GCS
    // (un drone reclutato da un altro cluster dichiara il nuovo cluster).
    // I nodi degli altri cluster li traccia la loro GCS, che invia lo
    // snapshot alle altre.
    std::vector<Ipv4Address> bersagli;
    std::set<uint32_t> visti;
    for (auto& e : statusTable) {
        Ipv4Address a(e.destinationAddress.c_str());
        if (a.isUnspecified() || isOwnAddress(a) || visti.count(a.getInt()))
            continue;
        // Normalmente ogni GCS traccia solo il proprio cluster, e i bersagli
        // sono quasi tutti a un hop: le catene risultano lunghe una voce sola e
        // il controllo sulla catena degli hop non ha nulla da confrontare.
        // Con traceAllClusters si tracciano anche i nodi degli altri cluster,
        // che sono a piu' salti, cosi' le catene diventano lunghe davvero.
        // Costa traffico, quindi e' spento di default e serve a misurare.
        if (!traceAllClusters && e.cluster_id != cluster_id)
            continue;
        visti.insert(a.getInt());
        bersagli.push_back(a);
    }
    for (size_t i = 0; i < bersagli.size(); i++)
        sendTraceTo(bersagli[i], i * traceStagger);

    // Secondo tentativo per le tracce senza risposta; il giro si chiude
    // traceTimeout dopo i secondi tentativi (vedi retryMissingTraces()).
    double ultimaPartenza = bersagli.empty() ? 0 : (bersagli.size() - 1) * traceStagger;
    if (traceRetryTimer->isScheduled())
        cancelEvent(traceRetryTimer);
    if (traceCloseTimer->isScheduled())
        cancelEvent(traceCloseTimer);
    if (traceRoundTimer->isScheduled())
        cancelEvent(traceRoundTimer);
    if (bersagli.empty())
        scheduleAfter(traceTimeout, traceCloseTimer);
    else
        scheduleAfter(ultimaPartenza + traceRetryDelay, traceRetryTimer);
}

void Ant2::retryMissingTraces()
{
    if (!traceRoundOpen)
        return;
    std::vector<uint32_t> bersagli;
    for (auto& kv : traceCurrent) {
        TraceResult& r = kv.second;
        if (!r.risposta && r.esito == IN_CORSO && !r.secondoTentativo && !r.sostituita) {
            r.sostituita = true;
            bersagli.push_back(r.target);
        }
    }
    for (size_t i = 0; i < bersagli.size(); i++) {
        sendTraceTo(Ipv4Address(bersagli[i]), i * traceStagger, true);
        traceRetried++;
    }
    double ultimaPartenza = bersagli.empty() ? 0 : (bersagli.size() - 1) * traceStagger;
    if (traceCloseTimer->isScheduled())
        cancelEvent(traceCloseTimer);
    scheduleAfter(ultimaPartenza + traceTimeout, traceCloseTimer);
}

unsigned int Ant2::sendTraceTo(Ipv4Address target, double delay, bool secondoTentativo)
{
    unsigned int id = ++traceNextId;
    TraceResult rec;
    rec.target = target.getInt();
    rec.sent = simTime().dbl() + delay;
    rec.secondoTentativo = secondoTentativo;
    traceSent++;

    // Prossimo passaggio secondo la tabella di routing della GCS
    Ipv4Route *r = rt->findBestMatchingRoute(target);
    if (r == nullptr || r->getNetmask() != Ipv4Address::ALLONES_ADDRESS) {
        rec.esito = ROTTA_MANCANTE;
        rec.note = "la GCS non ha una rotta verso il nodo";
        traceNoRoute++;
        traceCurrent[id] = rec;
        return id;
    }
    Ipv4Address next = r->getGateway().isUnspecified() ? target : r->getGateway();
    traceCurrent[id] = rec;

    auto t = makeShared<TraceM2>();
    Ipv4Address me = ownIdentity();
    t->setOrigin(me);
    t->setTarget(target);
    t->setTraceId(id);
    t->setHopdistance(1);
    t->setRitorno(false);
    t->setEsito(IN_CORSO);
    t->setNumEntries(0);
    uint8_t sig[Ant2Crypto::SIG_LEN] = {0};
    if (securityEnabled)
        crypto.sign(originSigned(me.getInt(), target.getInt(), id), sig);
    for (int k = 0; k < Ant2Crypto::SIG_LEN; k++)
        t->setOriginSignature(k, sig[k]);
    sendTracePacket(t, next, delay);
    return id;
}

void Ant2::closeTraceRound(bool rischedula)
{
    if (!traceRoundOpen)
        return;
    traceRoundOpen = false;
    if (traceCloseTimer != nullptr && traceCloseTimer->isScheduled())
        cancelEvent(traceCloseTimer);
    if (traceRetryTimer != nullptr && traceRetryTimer->isScheduled())
        cancelEvent(traceRetryTimer);
    // Giro successivo: intervallo casuale contato dalla chiusura di questo,
    // cosi' due giri non si sovrappongono.
    if (rischedula && traceRoundTimer != nullptr) {
        if (traceRoundTimer->isScheduled())
            cancelEvent(traceRoundTimer);
        scheduleAfter(uniform(traceIntervalMin, traceIntervalMax), traceRoundTimer);
    }

    int complete = 0, rotta = 0, senza = 0, manomesse = 0;
    std::string elencoRotta, elencoSenza;
    for (auto& kv : traceCurrent) {
        TraceResult& r = kv.second;
        if (r.sostituita)
            continue;   // primo tentativo senza risposta, sostituito dal secondo
        std::string nome = scenNomeDi(Ipv4Address(r.target));
        if (r.manomessa) {
            manomesse++;
        }
        else if (r.risposta && r.esito == IN_CORSO) {
            complete++;
        }
        else if (r.esito == ROTTA_MANCANTE || r.esito == LIMITE_HOP || r.esito == CICLO) {
            rotta++;
            elencoRotta += (elencoRotta.empty() ? "" : ", ") + nome;
        }
        else if (!r.risposta) {
            senza++;
            traceMissing++;
            elencoSenza += (elencoSenza.empty() ? "" : ", ") + nome;
        }
    }

    std::ofstream& log = snapshotLogFile();
    log << "=== " << host->getFullName() << "  giro " << traceRound << "  da " << fmtD(traceRoundStart, 3)
        << " a " << fmtD(simTime().dbl(), 3) << " s | tracce " << (complete + rotta + senza + manomesse) << ": complete " << complete
        << ", interrotte " << rotta << (elencoRotta.empty() ? "" : " (" + elencoRotta + ")")
        << ", senza risposta " << senza << (elencoSenza.empty() ? "" : " (" + elencoSenza + ")")
        << ", manomesse " << manomesse << "\n";

    // Percorsi, in ordine di nome del bersaglio
    std::vector<const TraceResult *> ordinati;
    for (auto& kv : traceCurrent)
        if (!kv.second.sostituita)
            ordinati.push_back(&kv.second);
    std::sort(ordinati.begin(), ordinati.end(), [](const TraceResult *a, const TraceResult *b) {
        return scenNomeDi(Ipv4Address(a->target)) < scenNomeDi(Ipv4Address(b->target));
    });
    for (auto r : ordinati) {
        log << "  " << std::left << std::setw(13) << scenNomeDi(Ipv4Address(r->target)) << std::right;
        if (!r->risposta && r->esito == IN_CORSO) {
            log << "nessuna risposta" << (r->secondoTentativo ? " (neanche al secondo tentativo)" : "") << "\n";
            continue;
        }
        if (!r->risposta) {
            log << esitoStr(r->esito) << ": " << r->note << "\n";
            continue;
        }
        if (r->manomessa)
            log << "MANOMESSA alla voce " << r->voceManomessa << " (" << r->note << ")";
        else if (r->esito == IN_CORSO)
            log << "completa, " << r->voci.size() << " hop, andata e ritorno " << fmtD(r->received - r->sent, 4) << " s";
        else
            log << esitoStr(r->esito) << " presso " << (r->voci.empty() ? std::string("?") : scenNomeDi(Ipv4Address(r->voci.back().node)));
        if (!r->note.empty() && !r->manomessa)
            log << " (" << r->note << ")";
        if (r->secondoTentativo)
            log << " [secondo tentativo]";
        log << " | " << host->getFullName();
        for (auto& v : r->voci)
            log << " -> " << scenNomeDi(Ipv4Address(v.node)) << " (h" << v.hopRecv << ", " << fmtD(v.recvTime, 4) << ")";
        log << "\n";
    }

    // Ultimo dato noto di ogni nodo: quelli tracciati da questa GCS e quelli
    // ricevuti con gli snapshot delle altre GCS (si tiene il dato piu' recente).
    log << "  nodi (ultimo dato noto; 'visto' = istante in cui il nodo ha scritto la voce; 'da' = GCS che lo ha tracciato):\n";
    std::map<uint32_t, std::pair<EntryData, std::string>> tutti;
    for (auto& kv : traceNodeInfo)
        tutti[kv.first] = {kv.second, host->getFullName()};
    for (auto& rs : remoteSnapshots)
        for (auto& r : rs.second.record) {
            auto f = tutti.find(r.dati.node);
            if (f == tutti.end() || r.dati.recvTime > f->second.first.recvTime)
                tutti[r.dati.node] = {r.dati, scenNomeDi(Ipv4Address(rs.first))};
        }
    std::vector<std::pair<std::string, const EntryData *>> nodi;
    std::map<std::string, std::string> fonte;
    for (auto& kv : tutti) {
        std::string nome = scenNomeDi(Ipv4Address(kv.first));
        nodi.push_back({nome, &kv.second.first});
        fonte[nome] = kv.second.second;
    }
    std::sort(nodi.begin(), nodi.end(), [](const std::pair<std::string, const EntryData *>& a,
                                           const std::pair<std::string, const EntryData *>& b) { return a.first < b.first; });
    for (auto& n : nodi) {
        const EntryData& e = *n.second;
        log << "    " << std::left << std::setw(13) << n.first << std::right
            << "energia " << fmtD(e.energy, 2) << "% (timbro " << fmtD(e.timbro, 3) << ")"
            << "  pos (" << fmtD(e.x, 0) << ", " << fmtD(e.y, 0) << ", " << fmtD(e.z, 0) << ")"
            << "  disponibile " << (e.allowed ? "SI" : "NO")
            << "  banda " << fmtD(e.maxBand, 2) << "  throughput " << fmtD(e.throughput, 3)
            << "  cluster " << e.cluster << "  [visto " << fmtD(e.recvTime, 3) << ", da " << fonte[n.first] << "]\n";
    }
    // Snapshot ricevuti dalle altre GCS
    for (auto& rs : remoteSnapshots)
        log << "  snapshot di " << scenNomeDi(Ipv4Address(rs.first)) << " (cluster " << rs.second.cluster << "): giro "
            << rs.second.giro << ", chiuso a " << fmtD(rs.second.istante, 3) << " s, ricevuto a " << fmtD(rs.second.ricevuto, 3)
            << " s, " << rs.second.record.size() << " nodi\n";
    log.flush();

    if (rischedula) {
        sendClusterSnapshot();   // snapshot del cluster alle altre GCS
        sendDigestBulletin();    // bollettino delle impronte ai droni del cluster
        writeTopology();         // topologia completa ricostruita
    }
}

// ---------------------------------------------------------------------------
// Trasmissione e ricezione delle tracce (tutti i nodi)
// ---------------------------------------------------------------------------

void Ant2::noteNeighborInterface(Packet *packet)
{
    auto l3 = packet->findTag<L3AddressInd>();
    auto ifi = packet->findTag<InterfaceInd>();
    if (l3 != nullptr && ifi != nullptr && !l3->getSrcAddress().isUnspecified()) {
        uint32_t a = l3->getSrcAddress().toIpv4().getInt();
        traceNeighborIf[a] = ifi->getInterfaceId();
        traceNeighborSeen[a] = simTime().dbl();
    }
}

double Ant2::neighborDistance(const Ipv4Address& a) const
{
    std::string s = a.str();
    for (auto& e : statusTable)
        if (e.destinationAddress == s)
            return e.distance;
    return -1;   // non noto
}

void Ant2::sendTracePacket(const Ptr<TraceM2>& t, Ipv4Address receiver, double delay, int ifaceId)
{
    int tagLen = crypto.tagLen();
    size_t lunghezza = 4 * 4 + 4 + 1 + 1 + Ant2Crypto::SIG_LEN + 4 + (size_t)t->getNumEntries() * wireLen(tagLen);
    // Modo di trasmissione (vedi traceUnicastMaxDistance in Ant2.ned):
    //  - UNICAST, con conferma e ritrasmissione del livello MAC, se il vicino
    //    e' vicino (distanza nota e non oltre traceUnicastMaxDistance) e si sa
    //    su quale interfaccia e' stato sentito;
    //  - altrimenti BROADCAST su tutte le interfacce, ripetuto
    //    traceBroadcastCopies volte (il ricevente scarta le copie in piu').
    if (ifaceId < 0) {
        auto f = traceNeighborIf.find(receiver.getInt());
        if (f != traceNeighborIf.end())
            ifaceId = f->second;
    }
    double distanza = neighborDistance(receiver);
    bool unicast = distanza >= 0 && distanza <= traceUnicastMaxDistance;
    // L'unicast usa sempre la prima interfaccia (wlan0, quella rivolta al
    // cluster): sulla seconda interfaccia delle GCS (wlan1, 11 Mbps, verso il
    // satellite) l'unicast verso i droni falliva (prova con il solo unicast).
    if (unicast)
        ifaceId = interface80211ptr->getInterfaceId();
    if (!unicast) {
        traceHopBroadcast++;
        for (int copia = 0; copia < traceBroadcastCopies; copia++) {
            for (auto ie : wirelessInterfaces) {
                auto c = staticPtrCast<TraceM2>(t->dupShared());
                c->setReceiver(receiver);
                c->setChunkLength(B(lunghezza));
                auto packet = new Packet("Trace", c);
                auto addressReq = packet->addTag<L3AddressReq>();
                addressReq->setDestAddress(Ipv4Address(255, 255, 255, 255));
                addressReq->setSrcAddress(ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
                packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
                packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
                packet->setKind(TRACE_PACKET_KIND);
                contaTrafficoControllo("TRACE", (int)lunghezza);
                sendDelayed(packet, delay + copia * 0.003, "ipOut");
            }
        }
        return;
    }
    traceHopUnicast++;
    std::vector<NetworkInterface *> interfacce;
    for (auto ie : wirelessInterfaces)
        if (ifaceId < 0 || ie->getInterfaceId() == ifaceId)
            interfacce.push_back(ie);
    if (interfacce.empty())
        interfacce = wirelessInterfaces;
    for (auto ie : interfacce) {
        auto c = staticPtrCast<TraceM2>(t->dupShared());
        c->setReceiver(receiver);
        c->setChunkLength(B(lunghezza));
        auto packet = new Packet("Trace", c);
        Ipv4Address src = ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
        auto addressReq = packet->addTag<L3AddressReq>();
        addressReq->setDestAddress(receiver);
        addressReq->setSrcAddress(src);
        packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
        packet->addTag<NextHopAddressReq>()->setNextHopAddress(receiver);   // direttamente al vicino
        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
        packet->setKind(TRACE_PACKET_KIND);
        contaTrafficoControllo("TRACE", (int)lunghezza);
        sendDelayed(packet, delay, "ipOut");
    }
}

void Ant2::appendTraceEntry(const Ptr<TraceM2>& t, Ipv4Address prev)
{
    int tagLen = crypto.tagLen();
    Ipv4Address me = ownIdentity();

    // Stessi valori che il nodo dichiara nei BANT (vedi buildSecureBant): un
    // nodo con attackFalseMetrics dichiara anche qui i suoi valori falsi.
    EntryData e;
    e.node = me.getInt();
    e.prev = prev.getInt();
    e.recvTime = simTime().dbl();
    e.hopRecv = t->getHopdistance();
    e.throughput = attackFalseMetrics ? 0.0 : node_throughput;
    e.energy = attackFalseMetrics ? 100.0 : node_energy;
    Coord posDich = posizioneDichiarata(false);
    e.x = posDich.x; e.y = posDich.y; e.z = posDich.z;
    e.maxBand = attackFalseMetrics ? max_band * 2.0 : max_band;
    e.cluster = cluster_id;
    e.allowed = (attackFalseMetrics || allowed_accept_request) ? 1 : 0;
    e.timbro = node_measure_time.dbl();
    // Vicini sentiti di recente, dal piu' recente
    std::vector<std::pair<double, uint32_t>> vic;
    for (auto& kv : traceNeighborSeen)
        if (simTime().dbl() - kv.second <= traceNeighborTimeout && !isOwnAddress(Ipv4Address(kv.first)))
            vic.push_back({kv.second, kv.first});
    std::sort(vic.begin(), vic.end(), [](const std::pair<double, uint32_t>& a, const std::pair<double, uint32_t>& b) { return a.first > b.first; });
    for (size_t i = 0; i < vic.size() && i < MAX_VICINI; i++)
        e.vicini.push_back(vic[i].second);
    std::vector<uint8_t> pt = pack(e);

    uint32_t counter = ++traceEntryCounter;
    uint32_t index = t->getNumEntries();
    std::vector<uint8_t> aad = entryAad(t->getOrigin().getInt(), t->getTarget().getInt(), t->getTraceId(),
                                        index, me.getInt(), counter);
    std::vector<uint8_t> ct;
    uint8_t tag[Ant2Crypto::MAX_TAG_LEN] = {0};
    uint8_t sig[Ant2Crypto::SIG_LEN] = {0};
    if (securityEnabled) {
        uint8_t nonce[Ant2Crypto::NONCE_LEN];
        // 0 come secondo nodo: per le voci di traccia il contatore e' del nodo
        // stesso e cresce di uno a ogni voce, quindi la coppia (nodo, contatore)
        // e' gia' unica e non serve un altro indirizzo nel nonce.
        crypto.deriveNonce(me.getInt(), 0, counter, Ant2Crypto::MSG_TRACE, nonce);
        if (!crypto.encrypt(pt, aad, nonce, ct, tag))
            throw cRuntimeError("Ant2: cifratura della voce di traccia fallita");
        uint8_t prevSig[Ant2Crypto::SIG_LEN];
        signatureOf(t.get(), (int)index - 1, tagLen, prevSig);
        crypto.sign(entrySigned(aad, ct, tag, tagLen, prevSig, Ant2Crypto::SIG_LEN), sig);
    }
    else
        ct = pt;   // baseline senza sicurezza: voce in chiaro

    size_t off = t->getEntriesArraySize();
    t->setEntriesArraySize(off + wireLen(tagLen));
    auto putByte = [&](uint8_t b) { t->setEntries(off++, b); };
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&e.node);
    for (int k = 0; k < 4; k++) putByte(p[k]);
    p = reinterpret_cast<const uint8_t *>(&counter);
    for (int k = 0; k < 4; k++) putByte(p[k]);
    for (size_t k = 0; k < PLAIN_LEN; k++) putByte(ct[k]);
    for (int k = 0; k < tagLen; k++) putByte(tag[k]);
    for (int k = 0; k < Ant2Crypto::SIG_LEN; k++) putByte(sig[k]);
    t->setNumEntries(index + 1);
}

static std::string chiaveUpstream(const TraceM2 *t)
{
    std::ostringstream k;
    k << t->getOrigin().getInt() << "/" << t->getTraceId();
    return k.str();
}

void Ant2::traceTurnAround(const Ptr<TraceM2>& t, uint8_t esito)
{
    int tagLen = crypto.tagLen();
    t->setRitorno(true);
    t->setEsito(esito);
    // Si rimanda la traccia al nodo da cui e' arrivata all'andata.
    auto u = traceUpstream.find(chiaveUpstream(t.get()));
    if (u != traceUpstream.end()) {
        sendTracePacket(t, u->second.addr, 0, u->second.ifaceId);
        return;
    }
    int n = t->getNumEntries();   // l'ultima voce e' di questo nodo
    Ipv4Address next = n >= 2 ? Ipv4Address(nodeOf(t.get(), n - 2, tagLen)) : t->getOrigin();
    sendTracePacket(t, next, 0);
}

void Ant2::handleTrace(Packet *packet)
{
    auto t = staticPtrCast<TraceM2>(packet->peekData<TraceM2>()->dupShared());
    TraceUpstream da;
    if (auto l3 = packet->findTag<L3AddressInd>())
        da.addr = l3->getSrcAddress().toIpv4();
    if (auto ifi = packet->findTag<InterfaceInd>())
        da.ifaceId = ifi->getInterfaceId();
    da.t = simTime().dbl();
    delete packet;
    if (!isOwnAddress(t->getReceiver()))
        return;   // trasmissione destinata a un altro nodo

    // Doppioni (stessa traccia ricevuta su piu' interfacce)
    std::ostringstream chiave;
    chiave << t->getOrigin().getInt() << "/" << t->getTraceId() << "/" << t->getRitorno() << "/" << t->getNumEntries();
    if (traceSeen.count(chiave.str()))
        return;
    if (traceSeen.size() > 20000)
        traceSeen.clear();
    traceSeen.insert(chiave.str());

    int tagLen = crypto.tagLen();
    int n = t->getNumEntries();

    if (t->getRitorno()) {
        if (isOwnAddress(t->getOrigin())) {
            handleTraceResult(t);
            return;
        }
        // Inoltro del ritorno al nodo da cui la traccia era arrivata all'andata
        auto u = traceUpstream.find(chiaveUpstream(t.get()));
        if (u != traceUpstream.end()) {
            sendTracePacket(t, u->second.addr, 0, u->second.ifaceId);
            return;
        }
        Ipv4Address me = ownIdentity();
        int k = -1;
        for (int i = 0; i < n; i++)
            if (nodeOf(t.get(), i, tagLen) == me.getInt())
                k = i;
        if (k < 0)
            return;
        Ipv4Address next = k > 0 ? Ipv4Address(nodeOf(t.get(), k - 1, tagLen)) : t->getOrigin();
        sendTracePacket(t, next, 0);
        return;
    }

    // Andata: si ricorda da chi e' arrivata la traccia (per il ritorno)
    if (traceUpstream.size() > 2000) {
        for (auto it = traceUpstream.begin(); it != traceUpstream.end();)
            it = (simTime().dbl() - it->second.t > 30) ? traceUpstream.erase(it) : std::next(it);
    }
    if (!da.addr.isUnspecified())
        traceUpstream[chiaveUpstream(t.get())] = da;

    // Andata: questo nodo aggiunge la propria voce
    Ipv4Address prev = n > 0 ? Ipv4Address(nodeOf(t.get(), n - 1, tagLen)) : t->getOrigin();
    appendTraceEntry(t, prev);

    if (isOwnAddress(t->getTarget())) {
        traceTurnAround(t, IN_CORSO);   // bersaglio raggiunto
        return;
    }
    if (t->getNumEntries() >= traceMaxHops) {
        traceTurnAround(t, LIMITE_HOP);
        return;
    }
    Ipv4Route *r = rt->findBestMatchingRoute(t->getTarget());
    if (r == nullptr || r->getNetmask() != Ipv4Address::ALLONES_ADDRESS) {
        traceTurnAround(t, ROTTA_MANCANTE);
        return;
    }
    Ipv4Address next = r->getGateway().isUnspecified() ? t->getTarget() : r->getGateway();
    bool ciclo = next == t->getOrigin() || isOwnAddress(next);
    for (int i = 0; i < t->getNumEntries() && !ciclo; i++)
        if (nodeOf(t.get(), i, tagLen) == next.getInt())
            ciclo = true;
    if (ciclo) {
        traceTurnAround(t, CICLO);
        return;
    }
    // Come per gli altri messaggi: chi inoltra incrementa hopdistance
    // (un nodo con attackHopDistance non lo fa).
    if (!attackHopDistance)
        t->setHopdistance(t->getHopdistance() + 1);
    sendTracePacket(t, next, 0);
}

void Ant2::handleTraceResult(const Ptr<const TraceM2>& t)
{
    auto it = traceCurrent.find(t->getTraceId());
    if (it == traceCurrent.end() || !traceRoundOpen) {
        traceLate++;   // risposta di un giro gia' chiuso
        return;
    }
    TraceResult& r = it->second;
    if (r.risposta)
        return;
    if (r.sostituita) {
        // Arriva la risposta al primo tentativo dopo che e' partito il secondo:
        // vale il primo, il secondo (se ancora senza risposta) non si conta.
        r.sostituita = false;
        for (auto& kv : traceCurrent)
            if (kv.first != it->first && kv.second.target == r.target && kv.second.secondoTentativo && !kv.second.risposta)
                kv.second.sostituita = true;
    }
    r.risposta = true;
    if (r.secondoTentativo)
        traceRetryOk++;
    r.received = simTime().dbl();
    r.esito = t->getEsito();

    int tagLen = crypto.tagLen();
    int n = t->getNumEntries();
    uint32_t origin = t->getOrigin().getInt();
    for (int i = 0; i < n; i++) {
        WireEntry w = readEntry(t.get(), i, tagLen);
        std::vector<uint8_t> pt;
        if (securityEnabled) {
            std::vector<uint8_t> aad = entryAad(origin, t->getTarget().getInt(), t->getTraceId(), (uint32_t)i, w.node, w.counter);
            uint8_t prevSig[Ant2Crypto::SIG_LEN];
            signatureOf(t.get(), i - 1, tagLen, prevSig);
            const char *motivo = nullptr;
            if (!crypto.isKnownNode(w.node))
                motivo = "nodo non presente nel registro della flotta";
            else if (!crypto.verify(entrySigned(aad, w.ct, w.tag, tagLen, prevSig, Ant2Crypto::SIG_LEN), w.sig, w.node))
                motivo = "firma non valida";
            else {
                uint8_t nonce[Ant2Crypto::NONCE_LEN];
                crypto.deriveNonce(w.node, 0, w.counter, Ant2Crypto::MSG_TRACE, nonce);
                if (!crypto.decrypt(w.ct, w.tag, aad, nonce, pt))
                    motivo = "cifratura non verificata";
            }
            if (motivo != nullptr) {
                r.manomessa = true;
                r.voceManomessa = i;
                r.note = std::string(motivo) + ", nodo " + scenNomeDi(Ipv4Address(w.node));
                traceTampered++;
                logScarto("TRACE", Ipv4Address(w.node), motivo, traceTampered);
                break;
            }
        }
        else
            pt = w.ct;
        EntryData e;
        if (!unpack(pt, e) || e.node != w.node) {
            r.manomessa = true;
            r.voceManomessa = i;
            r.note = "voce malformata";
            traceTampered++;
            break;
        }
        r.voci.push_back(e);
    }

    int incoerente = primaVoceIncoerente(r.voci, origin);
    if (!r.manomessa && incoerente >= 0)
        r.note = "la voce " + std::to_string(incoerente) + " dichiara un nodo precedente diverso da quello del percorso";

    // Regola 6: la catena delle voci dice chi non incrementa il contatore degli
    // hop. La rottura e' certa, la colpa si attribuisce per accumulo su piu'
    // giri, perche' da una catena sola non si distingue il colpevole dal nodo
    // che lo precede.
    if (!r.manomessa)
        checkCatenaTraccia(r.voci);

    if (!r.manomessa) {
        if (r.esito == IN_CORSO)
            traceComplete++;
        else
            traceNoRoute++;
        // Ultimo dato noto di ogni nodo attraversato (si tiene il piu' recente)
        for (auto& e : r.voci) {
            auto f = traceNodeInfo.find(e.node);
            if (f == traceNodeInfo.end() || e.recvTime >= f->second.recvTime)
                traceNodeInfo[e.node] = e;
            // Regola 1: le voci di traccia sono misure firmate come quelle dei
            // BANT, quindi passano per lo stesso controllo sull'energia. Il
            // timbro si confronta con l'istante in cui la voce e' stata
            // scritta, non con l'arrivo della traccia: in quel momento il nodo
            // aveva appena letto i propri dati, quindi l'eta' ammessa e' il
            // solo intervallo massimo fra due misure, piu' una tolleranza.
            checkEnergyRule(Ipv4Address(e.node), e.energy, Coord(e.x, e.y, e.z), e.timbro,
                            "una voce di traccia", e.recvTime, energyTraceMaxAge);
            // Regola 2: la voce di traccia dichiara anche la posizione con lo
            // stesso timbro, quindi serve al confronto sulla coerenza fra quello
            // che il drone scrive nei BANT e quello che scrive nelle tracce.
            checkPositionRule(Ipv4Address(e.node), Coord(e.x, e.y, e.z), e.timbro, e.energy,
                              "una voce di traccia");
            // Regola 0: la voce di traccia e' il secondo canale. Su una GCS questa
            // chiamata fa due cose: confronta con quello che la GCS ha gia' visto
            // nei BANT, e raccoglie l'impronta da pubblicare nel bollettino.
            digestNotaMisura(Ipv4Address(e.node), e.timbro, e.throughput, e.energy,
                             Coord(e.x, e.y, e.z), e.maxBand, ant2digest::Fonte::TRACCIA);
        }
    }
}

// ---------------------------------------------------------------------------
// File dello snapshot (uno per run, condiviso da tutte le GCS)
// ---------------------------------------------------------------------------

std::ofstream& Ant2::snapshotLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_snapshot", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Snapshot della rete raccolto dalle GCS con i traceroute (vedi Ant2Trace.cc)\n"
            << "# Per ogni giro di una GCS:\n"
            << "#   - riga '===': GCS, numero del giro, istanti di inizio e di chiusura, esito delle tracce\n"
            << "#   - una riga per ogni nodo bersaglio: esito, numero di hop, tempo di andata e ritorno e\n"
            << "#     percorso. Per ogni nodo del percorso: (hN, t) = hopdistance con cui ha ricevuto la\n"
            << "#     traccia e istante di ricezione. Un nodo che inoltra senza incrementare gli hop fa\n"
            << "#     comparire due valori di h uguali di seguito.\n"
            << "#   - 'nodi': l'ultimo dato noto di ogni nodo (gli stessi parametri dei BANT).\n"
            << "# Esiti: completa; rotta mancante / limite hop / ciclo (la traccia si e' interrotta presso\n"
            << "# un nodo); nessuna risposta (la traccia o la risposta si e' persa); MANOMESSA (una voce non\n"
            << "# supera la verifica di firma o cifratura). [secondo tentativo] = la traccia e' stata\n"
            << "# rilanciata perche' il primo tentativo non aveva avuto risposta entro traceRetryDelay.\n"
            << "#   grep '^===' file      riepilogo di tutti i giri\n"
            << "#   grep 'adh\\[7\\]' file   tutto cio' che riguarda adh[7]\n\n";
    }
    return log;
}

// ---------------------------------------------------------------------------
// Snapshot per cluster scambiati tra le GCS
// ---------------------------------------------------------------------------

static const int SNAP_PACKET_KIND = 4;   // = SNAP_PACKET in Ant2.cc

void Ant2::sendClusterSnapshot()
{
    // Record: ogni nodo del cluster tracciato in questo giro (ultimo dato
    // noto, hop dalla GCS e percorso). Un nodo non raggiunto in questo giro
    // compare con hop 0 e con il suo ultimo dato noto.
    std::vector<SnapRecord> recs;
    std::set<uint32_t> inclusi;
    for (auto& kv : traceCurrent) {
        const TraceResult& r = kv.second;
        if (r.sostituita || inclusi.count(r.target))
            continue;
        auto f = traceNodeInfo.find(r.target);
        if (f == traceNodeInfo.end())
            continue;   // nodo mai raggiunto: nessun dato da inviare
        SnapRecord rec;
        rec.dati = f->second;
        bool raggiunto = r.risposta && !r.manomessa && r.esito == IN_CORSO && !r.voci.empty();
        rec.hop = raggiunto ? (uint8_t)r.voci.size() : 0;
        if (raggiunto)
            for (size_t i = 0; i < r.voci.size() && i < MAX_PERCORSO; i++)
                rec.percorso.push_back(r.voci[i].node);
        recs.push_back(rec);
        inclusi.insert(r.target);
    }
    // Al massimo 8 droni per messaggio, piu' il record della GCS (sotto i
    // 1500 byte dell'MTU)
    if (recs.size() > 8)
        recs.resize(8);
    // Record della GCS stessa: i vicini che sente (droni del cluster e
    // satellite). La GCS e' fidata, quindi questi collegamenti valgono anche
    // se dichiarati da una sola parte: uniscono i cluster nella topologia.
    {
        SnapRecord self;
        self.dati.node = ownIdentity().getInt();
        self.dati.prev = self.dati.node;
        self.dati.recvTime = simTime().dbl();
        self.dati.energy = node_energy;
        Coord posSelf = posizioneDichiarata(false);
        self.dati.x = posSelf.x; self.dati.y = posSelf.y; self.dati.z = posSelf.z;
        self.dati.cluster = cluster_id;
        self.dati.timbro = node_measure_time.dbl();
        std::vector<std::pair<double, uint32_t>> vic;
        for (auto& kv : traceNeighborSeen)
            if (simTime().dbl() - kv.second <= traceNeighborTimeout && !isOwnAddress(Ipv4Address(kv.first)))
                vic.push_back({kv.second, kv.first});
        std::sort(vic.begin(), vic.end(), [](const std::pair<double, uint32_t>& a, const std::pair<double, uint32_t>& b) { return a.first > b.first; });
        for (size_t i = 0; i < vic.size() && i < MAX_VICINI; i++)
            self.dati.vicini.push_back(vic[i].second);
        recs.push_back(self);
    }

    Ipv4Address me = ownIdentity();
    uint32_t contatore = ++snapshotCounter;
    std::vector<uint8_t> pt = packSnapshot(recs);
    std::vector<uint8_t> aad = snapshotAad(me.getInt(), traceRound, contatore, recs.size());
    std::vector<uint8_t> ct;
    uint8_t tag[Ant2Crypto::MAX_TAG_LEN] = {0};
    uint8_t sig[Ant2Crypto::SIG_LEN] = {0};
    if (securityEnabled) {
        uint8_t nonce[Ant2Crypto::NONCE_LEN];
        crypto.deriveNonce(me.getInt(), 0, contatore, Ant2Crypto::MSG_SNAP, nonce);
        if (!crypto.encrypt(pt, aad, nonce, ct, tag))
            throw cRuntimeError("Ant2: cifratura dello snapshot fallita");
        std::vector<uint8_t> firmato = aad;
        firmato.insert(firmato.end(), ct.begin(), ct.end());
        firmato.insert(firmato.end(), tag, tag + crypto.tagLen());
        crypto.sign(firmato, sig);
    }
    else
        ct = pt;

    auto s = makeShared<SnapM2>();
    s->setOrigin(me);
    s->setGiro(traceRound);
    s->setContatore(contatore);
    s->setIstante(simTime().dbl());
    s->setCluster(cluster_id);
    s->setNumRecord(recs.size());
    s->setPayloadArraySize(ct.size());
    for (size_t i = 0; i < ct.size(); i++)
        s->setPayload(i, ct[i]);
    s->setAuthTagArraySize(crypto.tagLen());
    for (int i = 0; i < crypto.tagLen(); i++)
        s->setAuthTag(i, tag[i]);
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        s->setSignature(i, sig[i]);
    std::ostringstream k;
    k << me.getInt() << "/" << contatore;
    snapSeen.insert(k.str());
    snapSent++;
    sendSnapPacket(s);
}

void Ant2::sendSnapPacket(const Ptr<SnapM2>& s)
{
    // In broadcast verso la rete tra GCS e satellite: una GCS trasmette solo
    // sulle interfacce diverse dalla prima (wlan1), cosi' lo snapshot non
    // finisce nel canale del proprio cluster; il satellite, che ha una sola
    // interfaccia, trasmette su quella.
    size_t lunghezza = 4 + 4 + 4 + 8 + 4 + 4 + s->getPayloadArraySize() + s->getAuthTagArraySize() + Ant2Crypto::SIG_LEN;
    std::vector<NetworkInterface *> interfacce;
    for (size_t i = 0; i < wirelessInterfaces.size(); i++)
        if (wirelessInterfaces.size() == 1 || i > 0)
            interfacce.push_back(wirelessInterfaces[i]);
    for (int copia = 0; copia < snapshotCopies; copia++) {
        for (auto ie : interfacce) {
            auto c = staticPtrCast<SnapM2>(s->dupShared());
            c->setChunkLength(B(lunghezza));
            auto packet = new Packet("Snapshot", c);
            auto addressReq = packet->addTag<L3AddressReq>();
            addressReq->setDestAddress(Ipv4Address(255, 255, 255, 255));
            addressReq->setSrcAddress(ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
            packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
            packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
            packet->setKind(SNAP_PACKET_KIND);
            contaTrafficoControllo("TRACE", (int)lunghezza);
            sendDelayed(packet, copia * 0.003, "ipOut");
        }
    }
}

void Ant2::handleSnapshot(Packet *packet)
{
    auto s = staticPtrCast<SnapM2>(packet->peekData<SnapM2>()->dupShared());
    delete packet;
    if (!snapshotRelay)
        return;   // i droni ignorano gli snapshot
    std::ostringstream k;
    k << s->getOrigin().getInt() << "/" << s->getContatore();
    if (snapSeen.count(k.str()))
        return;   // gia' visto (copia o inoltro di un altro nodo)
    if (snapSeen.size() > 5000)
        snapSeen.clear();
    snapSeen.insert(k.str());

    // Le GCS verificano e conservano lo snapshot
    if (traceEnabled && !isOwnAddress(s->getOrigin())) {
        uint32_t origin = s->getOrigin().getInt();
        std::vector<uint8_t> ct(s->getPayloadArraySize());
        for (size_t i = 0; i < ct.size(); i++)
            ct[i] = s->getPayload(i);
        std::vector<uint8_t> aad = snapshotAad(origin, s->getGiro(), s->getContatore(), s->getNumRecord());
        std::vector<uint8_t> pt;
        bool valido = true;
        if (securityEnabled) {
            uint8_t tag[Ant2Crypto::MAX_TAG_LEN] = {0};
            uint8_t sig[Ant2Crypto::SIG_LEN];
            if ((int)s->getAuthTagArraySize() != crypto.tagLen())
                valido = false;
            else {
                for (int i = 0; i < crypto.tagLen(); i++)
                    tag[i] = s->getAuthTag(i);
                for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
                    sig[i] = s->getSignature(i);
                std::vector<uint8_t> firmato = aad;
                firmato.insert(firmato.end(), ct.begin(), ct.end());
                firmato.insert(firmato.end(), tag, tag + crypto.tagLen());
                uint8_t nonce[Ant2Crypto::NONCE_LEN];
                crypto.deriveNonce(origin, 0, s->getContatore(), Ant2Crypto::MSG_SNAP, nonce);
                valido = crypto.isKnownNode(origin) && crypto.verify(firmato, sig, origin)
                         && crypto.decrypt(ct, tag, aad, nonce, pt);
            }
        }
        else
            pt = ct;
        std::vector<SnapRecord> recs;
        if (valido && unpackSnapshot(pt, recs) && (int)recs.size() == s->getNumRecord()) {
            RemoteSnap& rs = remoteSnapshots[origin];
            if (s->getGiro() >= rs.giro || rs.record.empty()) {
                rs.cluster = s->getCluster();
                rs.giro = s->getGiro();
                rs.istante = s->getIstante();
                rs.ricevuto = simTime().dbl();
                rs.record = recs;
            }
            snapReceived++;
        }
        else {
            snapRejected++;
            logScarto("SNAPSHOT", s->getOrigin(), "firma, cifratura o formato non validi", snapRejected);
        }
    }

    // GCS e satellite inoltrano lo snapshot una volta
    sendSnapPacket(s);
}

// ---------------------------------------------------------------------------
// Topologia completa ricostruita da ogni GCS (file ant2_topologia_<...>.log)
// ---------------------------------------------------------------------------

std::ofstream& Ant2::topologyLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_topologia", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Topologia della rete ricostruita da ogni GCS alla chiusura di ogni suo giro, unendo il\n"
            << "# proprio snapshot (cluster della GCS) con gli ultimi snapshot ricevuti dalle altre GCS.\n"
            << "#   collegamenti: coppie di nodi consecutive nei percorsi tracciati (provate dalle firme)\n"
            << "#     e coppie di nodi che si dichiarano vicini a vicenda nelle voci;\n"
            << "#   hop minimi: numero minimo di passaggi tra due droni su quei collegamenti\n"
            << "#     ('-' = nessun percorso noto). Un BANT non puo' arrivare con meno hop di cosi'.\n\n";
    }
    return log;
}

void Ant2::writeTopology()
{
    // Nodi e dati: proprio snapshot + snapshot ricevuti
    std::map<std::string, std::set<std::string>> adiacenza;
    std::map<std::string, std::set<std::string>> dichiarati;   // vicini dichiarati da ogni nodo
    std::set<std::string> droni;
    auto aggiungiPercorso = [&](const std::string& gcs, const std::vector<uint32_t>& percorso) {
        std::string prec = gcs;
        for (uint32_t n : percorso) {
            std::string nome = scenNomeDi(Ipv4Address(n));
            adiacenza[prec].insert(nome);
            adiacenza[nome].insert(prec);
            prec = nome;
        }
    };
    auto aggiungiDati = [&](const EntryData& e) {
        std::string nome = scenNomeDi(Ipv4Address(e.node));
        if (nome.rfind("adh", 0) == 0)
            droni.insert(nome);
        for (uint32_t v : e.vicini)
            dichiarati[nome].insert(scenNomeDi(Ipv4Address(v)));
    };
    std::string me = host->getFullName();
    for (auto& kv : traceCurrent) {
        const TraceResult& r = kv.second;
        if (r.sostituita || !r.risposta || r.manomessa)
            continue;
        std::vector<uint32_t> p;
        for (auto& v : r.voci)
            p.push_back(v.node);
        aggiungiPercorso(me, p);
    }
    for (auto& kv : traceNodeInfo)
        if (kv.second.cluster == cluster_id)
            aggiungiDati(kv.second);
    // Collegamenti dichiarati da una GCS (fidata): valgono da soli
    auto aggiungiVicinoGcs = [&](const std::string& gcs, uint32_t v) {
        std::string nome = scenNomeDi(Ipv4Address(v));
        adiacenza[gcs].insert(nome);
        adiacenza[nome].insert(gcs);
    };
    for (auto& kv : traceNeighborSeen)
        if (simTime().dbl() - kv.second <= traceNeighborTimeout && !isOwnAddress(Ipv4Address(kv.first)))
            aggiungiVicinoGcs(me, kv.first);
    std::string fonti;
    for (auto& rs : remoteSnapshots) {
        std::string g = scenNomeDi(Ipv4Address(rs.first));
        fonti += ", " + g + " (giro " + std::to_string(rs.second.giro) + ", " + fmtD(simTime().dbl() - rs.second.istante, 1) + " s fa)";
        for (auto& r : rs.second.record) {
            if (r.dati.node == rs.first) {   // record della GCS che ha inviato lo snapshot
                for (uint32_t v : r.dati.vicini)
                    aggiungiVicinoGcs(g, v);
                continue;
            }
            aggiungiDati(r.dati);
            if (r.hop > 0)
                aggiungiPercorso(g, r.percorso);
        }
    }
    // Vicini dichiarati a vicenda
    for (auto& kv : dichiarati)
        for (auto& v : kv.second)
            if (dichiarati.count(v) && dichiarati[v].count(kv.first)) {
                adiacenza[kv.first].insert(v);
                adiacenza[v].insert(kv.first);
            }
    size_t collegamenti = 0;
    std::ostringstream elenco;
    for (auto& kv : adiacenza)
        for (auto& v : kv.second)
            if (kv.first < v) {
                collegamenti++;
                elenco << " " << kv.first << "-" << v;
            }

    std::ofstream& log = topologyLogFile();
    log << "=== " << me << "  giro " << traceRound << "  t=" << fmtD(simTime().dbl(), 3) << " s | droni " << droni.size()
        << ", collegamenti " << collegamenti << " | snapshot usati: " << me << " (questo giro)" << fonti << "\n";
    log << "  collegamenti:" << elenco.str() << "\n";
    // Hop minimi tra droni (ricerca in ampiezza)
    std::vector<std::string> lista(droni.begin(), droni.end());
    std::sort(lista.begin(), lista.end(), [](const std::string& a, const std::string& b) {
        int ia = atoi(a.c_str() + 4), ib = atoi(b.c_str() + 4);
        return ia < ib;
    });
    log << "  hop minimi" << std::string(4, ' ');
    for (auto& d : lista)
        log << std::setw(8) << d;
    log << "\n";
    for (auto& a : lista) {
        std::map<std::string, int> dist;
        std::vector<std::string> coda{a};
        dist[a] = 0;
        for (size_t i = 0; i < coda.size(); i++)
            for (auto& v : adiacenza[coda[i]])
                if (!dist.count(v)) {
                    dist[v] = dist[coda[i]] + 1;
                    coda.push_back(v);
                }
        log << "  " << std::left << std::setw(12) << a << std::right;
        for (auto& b : lista)
            log << std::setw(8) << (dist.count(b) ? std::to_string(dist[b]) : std::string("-"));
        log << "\n";
    }
    log.flush();
}

} // namespace ant2
} // namespace inet
