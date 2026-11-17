//
// Ant2Digest.cc
//
// Regola 0 della metrica di trust: coerenza fra canali (equivocazione).
// La logica pura sta in Ant2DigestCheck.h, verificata dai test automatici in
// test_controllo_impronta.cc. Qui c'e' il collegamento con il protocollo:
//
//   lato drone (e lato GCS, che e' un osservatore come gli altri)
//     - improntaLettura(): calcola l'impronta dei campi legati alla lettura;
//     - digestNotaMisura(): la memorizza quando arriva un messaggio firmato;
//     - digestAttribuisciEsiti(): annota quanti esiti le regole 1-5 hanno
//       prodotto su quella lettura, cosi' da poterli annullare se la lettura
//       risulta poi falsificata;
//     - handleDigest(): riceve il bollettino della GCS ed esegue il confronto.
//
//   lato GCS
//     - digestRaccogliLettura() / digestRaccogliReq(): accumulano il materiale;
//     - sendDigestBulletin(): lo pubblica nel proprio cluster alla chiusura di
//       ogni giro di tracce.
//
#include "inet/routing/ant2/Ant2.h"

#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/common/ProtocolTag_m.h"

#include <sstream>

extern "C" {
#include "crypto/ed25519/sha512.h"
}

namespace inet {
namespace ant2 {

using namespace ant2digest;

static const int DIGEST_PACKET_KIND = 5;   // = DIGEST_PACKET in Ant2.cc

// ---------------------------------------------------------------------------
// L'impronta di una lettura
// ---------------------------------------------------------------------------

uint64_t Ant2::improntaLettura(uint32_t nodo, double timbro, double throughput,
                               double energia, const Coord& pos, double maxBand)
{
    // Entrano SOLO i campi legati alla lettura, cioe' quelli che updateThroughput()
    // aggiorna nella stessa riga in cui fissa il timbro, piu' la banda massima,
    // che nel codice non cambia mai. Restano fuori allowed_accept_request e
    // cluster_id, che cambiano su eventi (accettazione di un REQ, partenza per
    // la ricarica, reclutamento) e quindi possono differire legittimamente fra
    // due messaggi che portano lo stesso timbro: metterli qui avrebbe accusato
    // di equivocazione droni perfettamente onesti.
    //
    // I valori vengono copiati byte per byte come sono arrivati, senza nessuna
    // riconversione: due parti che hanno ricevuto la stessa dichiarazione hanno
    // gli stessi bit, e basta un arrotondamento diverso per creare un falso
    // positivo. SHA-512 e' quella gia' compilata nel progetto per la firma
    // Ed25519, quindi non si aggiunge nessuna libreria; si usano i primi 8 byte
    // dell'impronta, che danno una probabilita' di collisione dell'ordine di
    // 2^-64 per confronto.
    const double campi[7] = { timbro, throughput, energia, pos.x, pos.y, pos.z, maxBand };
    uint8_t buf[8 + 4 + 8 * 7];
    size_t off = 0;
    memcpy(buf + off, "ANT2SNAP", 8); off += 8;
    memcpy(buf + off, &nodo, 4);      off += 4;
    for (int i = 0; i < 7; i++) {
        memcpy(buf + off, &campi[i], 8);
        off += 8;
    }

    uint8_t digest[64];
    sha512(buf, sizeof(buf), digest);
    uint64_t out = 0;
    memcpy(&out, digest, 8);
    return out;
}

// ---------------------------------------------------------------------------
// Lato osservatore: memoria delle letture e confronto
// ---------------------------------------------------------------------------

void Ant2::digestResolveNome(const Ipv4Address& src, DigestObserved& o)
{
    if (o.valido)
        return;
    o.nome = scenNomeDi(src);
    o.valido = !o.nome.empty();
}

void Ant2::digestNotaMisura(const Ipv4Address& src, double timbro, double throughput,
                            double energia, const Coord& pos, double maxBand, Fonte fonte)
{
    if (!digestCheckEnabled || legacyEnergy || timbro < 0)
        return;
    if (isOwnAddress(src))
        return;   // le proprie dichiarazioni non si controllano

    uint64_t imp = improntaLettura(src.getInt(), timbro, throughput, energia, pos, maxBand);

    // Se questo nodo e' una GCS che pubblica, la lettura entra anche nel
    // materiale del prossimo bollettino.
    if (digestPublish)
        digestRaccogliLettura(src.getInt(), timbro, imp, fonte);

    DigestObserved& o = digestObserved[src.getInt()];
    digestResolveNome(src, o);
    auto esiti = registraMisura(o.st, timbro, imp, digestParams);
    digestApplicaEsiti(src, o, esiti);
}

Ant2::TotaliRegole Ant2::totaliRegole() const
{
    TotaliRegole t;
    t.superati = energyCheckSuperati + positionCheckSuperati + availabilityCheckSuperati
               + helpCheckSuperati + bandCheckSuperati;
    t.violati = energyCheckViolati + positionCheckViolati + availabilityCheckViolati
              + helpCheckViolati + bandCheckViolati;
    t.dubbi = positionCheckDubbi + availabilityCheckDubbi + helpCheckDubbi;
    return t;
}

void Ant2::digestAttribuisciEsiti(const Ipv4Address& src, double timbro, const TotaliRegole& prima)
{
    if (!digestCheckEnabled || legacyEnergy || timbro < 0)
        return;
    auto it = digestObserved.find(src.getInt());
    if (it == digestObserved.end())
        return;
    TotaliRegole dopo = totaliRegole();
    annotaEsiti(it->second.st, timbro,
                dopo.superati - prima.superati,
                dopo.violati - prima.violati,
                dopo.dubbi - prima.dubbi,
                digestParams);
}

void Ant2::digestApplicaEsiti(const Ipv4Address& src, DigestObserved& o,
                              const std::vector<DigestOutcome>& esiti)
{
    if (esiti.empty())
        return;
    std::string io = getContainingNode(this)->getFullName();
    for (auto& e : esiti) {
        switch (e.esito) {
            case Esito::SUPERATO:        digestCheckSuperati++; break;
            case Esito::VIOLATO:         digestCheckViolati++; break;
            case Esito::NON_APPLICABILE: digestCheckNonApplicabili++; break;
        }
        if (e.controllo == "coerenza fra messaggi" && e.esito == Esito::VIOLATO)
            digestCheckViolatiLocali++;

        // Annullamento degli esiti che le regole 1-5 avevano tratto da una
        // lettura che ora sappiamo falsificata. Non puo' avvantaggiare
        // l'attaccante: al posto degli esiti tolti resta la violazione certa
        // di questa regola, che e' appena stata contata qui sopra.
        if (e.annulla) {
            digestAnnullatiSuperati += e.annullaSuperati;
            digestAnnullatiViolati += e.annullaViolati;
            digestAnnullatiDubbi += e.annullaDubbi;
        }

        bool daRegistrare = (e.esito != Esito::SUPERATO) || digestCheckLogAll;
        if (e.esito == Esito::NON_APPLICABILE && !digestCheckLogAll)
            daRegistrare = false;   // sono tanti: riempirebbero il registro
        if (daRegistrare) {
            digestCheckLogFile() << simTime() << "  " << io << "  " << o.nome << "  "
                                 << e.controllo << "  " << esitoStr(e.esito) << "  " << e.dettaglio;
            if (e.annulla)
                digestCheckLogFile() << "  [annullati " << e.annullaSuperati << " superati, "
                                     << e.annullaViolati << " violati, " << e.annullaDubbi
                                     << " dubbi delle altre regole]";
            digestCheckLogFile() << "\n";
            digestCheckLogFile().flush();
        }
    }
}

// ---------------------------------------------------------------------------
// Lato GCS: raccolta del materiale
// ---------------------------------------------------------------------------

void Ant2::digestRaccogliLettura(uint32_t nodo, double timbro, uint64_t impronta, Fonte fonte)
{
    auto& v = digestLetture[nodo];
    for (auto& l : v)
        if (std::fabs(l.timbro - timbro) <= digestParams.tolTimbro && l.impronta == impronta)
            return;   // gia' raccolta: piu' messaggi nati dalla stessa lettura
    // ATTENZIONE: se il timbro c'e' gia' ma l'impronta e' DIVERSA, la seconda
    // non va scartata, va conservata. Due dichiarazioni discordi nate dalla
    // stessa lettura sono esattamente la prova dell'equivocazione, ed e' quello
    // che la GCS deve far sapere ai droni: pubblicandone una sola, e per giunta
    // la prima arrivata (di solito quella del BANT, cioe' la bugia), la GCS
    // finirebbe per confermare ai droni proprio il valore falso.
    // Se il timbro c'era gia' con un'impronta diversa, questa e' una lettura
    // CONTESA: il nodo ha dichiarato due cose diverse. Le due righe devono
    // viaggiare insieme nello stesso bollettino, altrimenti chi legge ne vede
    // una sola e non puo' accorgersi di niente. Vanno quindi in una lista a
    // parte, che viene pubblicata per prima e non e' soggetta alla rotazione.
    for (auto& l : v) {
        if (std::fabs(l.timbro - timbro) > digestParams.tolTimbro)
            continue;
        bool gia = false;
        for (auto& c : digestContese)
            if (c.nodo == nodo && std::fabs(c.timbro - timbro) <= digestParams.tolTimbro)
                gia = true;
        if (!gia) {
            ant2digest::wire::RecordImpronta a, b;
            a.nodo = nodo; a.timbro = l.timbro; a.impronta = l.impronta; a.fonte = (uint8_t)l.fonte;
            b.nodo = nodo; b.timbro = timbro;   b.impronta = impronta;   b.fonte = (uint8_t)fonte;
            digestContese.push_back(a);
            digestContese.push_back(b);
            while (digestContese.size() > 16)
                digestContese.erase(digestContese.begin());
            // La prova non aspetta la chiusura del giro: parte subito, in un
            // pacchetto piccolo che ha molte piu' probabilita' di arrivare.
            sendDigestAlert();
        }
        break;
    }

    LetturaNota l;
    l.timbro = timbro;
    l.impronta = impronta;
    l.fonte = fonte;
    v.push_back(l);
    // Si tiene qualche lettura in piu' di quante se ne pubblicano, cosi' che la
    // ripubblicazione copra piu' bollettini consecutivi.
    // Il margine e' doppio perche' una lettura contesa occupa due posti.
    while ((int)v.size() > digestMeasuresPerNode * 2 + 2)
        v.erase(v.begin());
}

void Ant2::digestRaccogliReq(const Ipv4Address& mittente, const Ipv4Address& destinatario,
                             const Coord& posRichiedente, unsigned int seq)
{
    if (!digestPublish || !digestIncludeReq)
        return;
    for (auto& r : digestReqNoti)
        if (r.mittente == mittente.getInt() && r.seq == seq)
            return;   // il REQ viaggia per inondazione e arriva piu' volte
    ant2digest::wire::RecordReq r;
    r.mittente = mittente.getInt();
    r.destinatario = destinatario.getInt();
    r.x = posRichiedente.x; r.y = posRichiedente.y; r.z = posRichiedente.z;
    r.seq = seq;
    r.istante = simTime().dbl();
    digestReqNoti.push_back(r);
    while (digestReqNoti.size() > 16)
        digestReqNoti.erase(digestReqNoti.begin());
}

// ---------------------------------------------------------------------------
// Lato GCS: pubblicazione del bollettino
// ---------------------------------------------------------------------------

/**
 * Cluster di un nodo, per quanto la GCS ne sa dalle tracce. Vale -1 se il nodo
 * non e' ancora comparso in nessuna traccia.
 */
int Ant2::clusterDiNodo(uint32_t nodo) const
{
    auto it = traceNodeInfo.find(nodo);
    if (it != traceNodeInfo.end())
        return (int)it->second.cluster;
    // Ogni nodo ha piu' di un indirizzo (radio del cluster, radio di dorsale,
    // collegamento X2), e le letture arrivano con l'indirizzo del messaggio
    // mentre le voci di traccia portano quello della radio wlan0: cercare per
    // indirizzo fallisce quasi sempre, e il cluster risulterebbe ignoto per
    // tutti. E' lo stesso inganno che aveva prodotto i falsi positivi nella
    // regola 6 sugli hop, e si risolve allo stesso modo, confrontando i NOMI.
    const std::string nome = scenNomeDi(Ipv4Address(nodo));
    if (nome.empty())
        return -1;
    for (auto& kv : traceNodeInfo)
        if (scenNomeDi(Ipv4Address(kv.first)) == nome)
            return (int)kv.second.cluster;
    return -1;
}

/**
 * Pubblicazione del bollettino, a due velocita'.
 *
 * IL PROBLEMA. Il bollettino parte alla chiusura di ogni giro di tracce, cioe'
 * ogni uno-cinque secondi: la frequenza di invio non e' mai stata il limite. Il
 * limite era il contenuto. In un bollettino entravano le ultime letture di TUTTI
 * i nodi conosciuti, che con diciannove nodi e tre letture a testa fanno
 * cinquantasette righe candidate contro un tetto di dodici, e le righe uscivano
 * a rotazione: ogni singola lettura veniva pubblicata una volta ogni cinque
 * bollettini, cioe' ogni quindici secondi. Di qui i quattro controlli per coppia
 * osservatore-drone misurati sulla regola 0, contro i trentasette dell'energia.
 *
 * Il tetto non si puo' alzare a piacere: oltre l'MTU il pacchetto viene
 * frammentato dal livello IP e un frammento perso fa perdere tutto, e su un
 * canale in broadcast senza riscontri succede spesso (nelle misure si sono persi
 * 138 bollettini su 253).
 *
 * LA SOLUZIONE. Il bollettino viaggia dentro il canale del cluster e i suoi
 * destinatari sono i droni di QUEL cluster, che ricevono i BANT soprattutto dai
 * propri vicini di cluster. Le righe degli altri cluster servono quindi poco a
 * chi legge, e occupavano i quattro quinti dello spazio. Si separano percio' due
 * pubblicazioni:
 *
 *   - a ogni giro, TUTTE le letture dei nodi del proprio cluster, senza
 *     rotazione: cinque droni per tre letture fanno quindici righe, che stanno
 *     dentro il tetto. Ogni lettura viene pubblicata subito, non dopo quindici
 *     secondi;
 *   - ogni digestFullEveryRounds giri, in aggiunta, le letture degli altri
 *     cluster, queste sì a rotazione, per chi ha ricevuto BANT da fuori.
 *
 * Il risultato e' che la pubblicazione delle letture del proprio cluster passa
 * da una volta ogni quindici secondi a una volta per giro, senza far crescere il
 * pacchetto.
 */
void Ant2::sendDigestBulletin()
{
    if (!digestPublish || !digestCheckEnabled || legacyEnergy)
        return;
    if (digestEveryRounds > 1 && (traceRound % digestEveryRounds) != 0)
        return;

    // Sezione delle impronte: le ultime N letture di ogni nodo conosciuto,
    // separate fra nodi del proprio cluster e nodi degli altri.
    std::vector<ant2digest::wire::RecordImpronta> proprie, altrui;
    for (auto& kv : digestLetture) {
        auto& v = kv.second;
        const int cl = clusterDiNodo(kv.first);
        // Un nodo di cluster ancora ignoto si tratta come proprio: e' quasi
        // sempre un vicino di cui non e' ancora arrivata una traccia, e lasciarlo
        // fuori significherebbe non pubblicarlo mai.
        // Con digestClusterFirst spento tutte le righe finiscono in un'unica
        // riserva a rotazione, che e' il comportamento precedente: serve a
        // confrontare le due pubblicazioni nella stessa campagna di misure.
        const bool mio = digestClusterFirst && (cl < 0 || cl == cluster_id);
        std::vector<ant2digest::wire::RecordImpronta>& dove = mio ? proprie : altrui;
        size_t da = v.size() > (size_t)digestMeasuresPerNode ? v.size() - digestMeasuresPerNode : 0;
        for (size_t i = da; i < v.size(); i++) {
            ant2digest::wire::RecordImpronta r;
            r.nodo = kv.first;
            r.timbro = v[i].timbro;
            r.impronta = v[i].impronta;
            r.fonte = (uint8_t)v[i].fonte;
            dove.push_back(r);
        }
    }

    std::vector<ant2digest::wire::RecordImpronta> righe;

    // Le letture contese escono per prime e in ogni bollettino, fuori da
    // qualunque tetto: sono la prova dell'equivocazione e devono arrivare a
    // tutti.
    righe.insert(righe.end(), digestContese.begin(), digestContese.end());

    // Le letture del proprio cluster: tutte, senza rotazione, fino al tetto
    // dedicato. Se il cluster fosse piu' grande del previsto il tetto torna a
    // mordere, e in quel caso si ruota anche su queste.
    if ((int)proprie.size() > digestMaxRowsCluster) {
        std::vector<ant2digest::wire::RecordImpronta> finestra;
        size_t da = digestRowOffsetCluster % proprie.size();
        for (int i = 0; i < digestMaxRowsCluster; i++)
            finestra.push_back(proprie[(da + i) % proprie.size()]);
        digestRowOffsetCluster = (da + digestMaxRowsCluster) % proprie.size();
        proprie.swap(finestra);
    }
    righe.insert(righe.end(), proprie.begin(), proprie.end());
    digestRowsCluster += (long)proprie.size();

    // Le letture degli altri cluster: solo nel bollettino completo, e a
    // rotazione, nello spazio che resta sotto il tetto complessivo.
    const bool completo = !digestClusterFirst || (digestFullEveryRounds <= 1)
                          || (traceRound % digestFullEveryRounds) == 0;
    if (completo && !altrui.empty()) {
        int spazio = digestMaxRows - (int)righe.size();
        if (spazio > 0) {
            if ((int)altrui.size() > spazio) {
                std::vector<ant2digest::wire::RecordImpronta> finestra;
                size_t da = digestRowOffset % altrui.size();
                for (int i = 0; i < spazio; i++)
                    finestra.push_back(altrui[(da + i) % altrui.size()]);
                digestRowOffset = (da + spazio) % altrui.size();
                altrui.swap(finestra);
            }
            righe.insert(righe.end(), altrui.begin(), altrui.end());
            digestRowsAltrui += (long)altrui.size();
            digestFullSent++;
        }
    }

    if (righe.empty() && digestReqNoti.empty())
        return;

    std::vector<uint8_t> pt;
    ant2digest::wire::scriviSezioneImpronte(pt, righe);
    if (digestIncludeReq) {
        // Anche i REQ hanno un tetto: 44 byte a riga pesano piu' delle impronte.
        std::vector<ant2digest::wire::RecordReq> reqDaMandare = digestReqNoti;
        while ((int)reqDaMandare.size() > digestMaxReqRows)
            reqDaMandare.erase(reqDaMandare.begin());
        ant2digest::wire::scriviSezioneReq(pt, reqDaMandare);
        digestReqRowsSent += (long)reqDaMandare.size();
    }

    digestSent++;
    digestRowsSent += (long)righe.size();
    digestSpedisci(pt, digestCopies);
}

/**
 * Allerta: un bollettino minuscolo che contiene SOLO le letture contese.
 *
 * Serve perche' il bollettino ordinario e' dieci volte piu' grande di
 * qualunque altro messaggio del protocollo e, viaggiando in broadcast sul
 * canale del cluster (dove non ci sono riscontri ne' ritrasmissioni), si perde
 * quasi sempre: nelle misure arrivava a un nodo e mezzo per volta. La prova
 * dell'equivocazione sono invece due righe da 21 byte, quindi un pacchetto di
 * poche centinaia di byte che ha probabilita' di arrivare molto piu' alta.
 * Viene mandato appena la GCS si accorge della contraddizione, senza aspettare
 * la chiusura del giro di tracce.
 */
void Ant2::sendDigestAlert()
{
    if (!digestPublish || !digestCheckEnabled || legacyEnergy || digestContese.empty())
        return;
    std::vector<uint8_t> pt;
    ant2digest::wire::scriviSezioneImpronte(pt, digestContese);
    digestAlerts++;
    digestSpedisci(pt, digestCopies + 1);   // una copia in piu': e' il messaggio che conta
}

void Ant2::digestSpedisci(const std::vector<uint8_t>& pt, int copie)
{
    if (wirelessInterfaces.empty())
        return;
    uint32_t me = wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress().getInt();
    uint32_t contatore = ++digestCounter;
    std::vector<uint8_t> aad = ant2digest::wire::bollettinoAad(me, traceRound, contatore,
                                                               (uint32_t)pt.size());
    std::vector<uint8_t> ct;
    uint8_t tag[Ant2Crypto::MAX_TAG_LEN] = {0};
    uint8_t sig[Ant2Crypto::SIG_LEN] = {0};
    if (securityEnabled) {
        uint8_t nonce[Ant2Crypto::NONCE_LEN];
        crypto.deriveNonce(me, 0, contatore, Ant2Crypto::MSG_DIGEST, nonce);
        crypto.encrypt(pt, aad, nonce, ct, tag);
        std::vector<uint8_t> firmato = aad;
        firmato.insert(firmato.end(), ct.begin(), ct.end());
        firmato.insert(firmato.end(), tag, tag + crypto.tagLen());
        crypto.sign(firmato, sig);
    }
    else
        ct = pt;

    auto d = makeShared<DigestM2>();
    d->setOrigin(Ipv4Address(me));
    d->setGiro(traceRound);
    d->setContatore(contatore);
    d->setIstante(simTime().dbl());
    d->setCluster(cluster_id);
    d->setNumByte((int)pt.size());
    d->setPayloadArraySize(ct.size());
    for (size_t i = 0; i < ct.size(); i++)
        d->setPayload(i, ct[i]);
    d->setAuthTagArraySize(crypto.tagLen());
    for (int i = 0; i < crypto.tagLen(); i++)
        d->setAuthTag(i, tag[i]);
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        d->setSignature(i, sig[i]);

    sendDigestPacket(d, copie);
}

void Ant2::sendDigestPacket(const Ptr<DigestM2>& d, int copie, int ifaceId)
{
    // A differenza dello snapshot fra GCS, il bollettino va DENTRO il canale del
    // cluster, cioe' sulla prima interfaccia, perche' i destinatari sono i droni.
    // E' il canale congestionato: e' il motivo per cui si mandano impronte da 8
    // byte invece dei valori, e per cui conviene misurare la perdita di BANT
    // prima e dopo aver acceso questa regola.
    size_t lunghezza = 4 + 4 + 4 + 8 + 4 + 4 + d->getPayloadArraySize()
                     + d->getAuthTagArraySize() + Ant2Crypto::SIG_LEN;
    if (wirelessInterfaces.empty())
        return;
    // Si trasmette sull'interfaccia da cui il bollettino e' arrivato, quando la
    // si conosce: e' quella del canale del cluster, ed e' l'unica su cui ha
    // senso ritrasmetterlo. In mancanza si usa la prima, che per una GCS e' il
    // canale del proprio cluster.
    NetworkInterface *ie = wirelessInterfaces[0];
    if (ifaceId >= 0)
        for (auto x : wirelessInterfaces)
            if (x->getInterfaceId() == ifaceId)
                ie = x;

    // TRASMISSIONE IN UNICAST AI VICINI DEL CLUSTER.
    //
    // Il bollettino viaggiava solo in broadcast, e in 802.11 un frame broadcast
    // non ha riscontro ne' ritrasmissione: se si perde, e' perso. Le misure lo
    // hanno mostrato senza equivoci, perche' passando da due a tre copie le
    // ricezioni sono piu' che raddoppiate (da 107 a 257) e con esse i controlli
    // concludenti. Ma ripetere un pacchetto e' un rimedio cieco: si spende
    // banda anche quando la prima copia era arrivata, e non si sa mai se e'
    // bastato.
    //
    // Un frame UNICAST, invece, ha il riscontro del livello MAC e fino a sette
    // ritentativi automatici: la consegna a un vicino in portata diventa quasi
    // certa, e costa una trasmissione sola quando il canale e' libero. E' la
    // stessa scelta che il progetto fa gia' per le tracce (si veda
    // sendTracePacket e il parametro traceUnicastMaxDistance), quindi qui non si
    // introduce un meccanismo nuovo: si estende al bollettino uno che esiste.
    //
    // Resta una copia in broadcast per i nodi del cluster che non sono vicini
    // diretti o di cui non si conosce la distanza; a loro il bollettino arriva
    // come prima, per broadcast e per inoltro.
    int inviatiUnicast = 0;
    if (digestUnicast && ifaceId < 0 && interface80211ptr != nullptr) {
        const double ora = simTime().dbl();
        for (auto& kv : traceNeighborSeen) {
            if (ora - kv.second > traceNeighborTimeout)
                continue;   // vicino non piu' sentito di recente
            Ipv4Address vicino(kv.first);
            double distanza = neighborDistance(vicino);
            if (distanza < 0 || distanza > traceUnicastMaxDistance)
                continue;   // posizione non nota o fuori portata: resta al broadcast
            auto c = staticPtrCast<DigestM2>(d->dupShared());
            c->setChunkLength(B(lunghezza));
            auto packet = new Packet("Bollettino", c);
            auto addressReq = packet->addTag<L3AddressReq>();
            addressReq->setDestAddress(vicino);
            addressReq->setSrcAddress(interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
            packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
            packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
            packet->setKind(DIGEST_PACKET_KIND);
            contaTrafficoControllo("DIGEST", (int)lunghezza);
            sendDelayed(packet, inviatiUnicast * 0.003, "ipOut");
            inviatiUnicast++;
        }
        digestUnicastSent += inviatiUnicast;
        // Con l'unicast attivo basta una copia in broadcast di complemento: la
        // ridondanza serviva a supplire alla mancanza di riscontri, che qui non
        // manca piu'.
        if (inviatiUnicast > 0)
            copie = 1;
    }

    for (int copia = 0; copia < copie; copia++) {
        auto c = staticPtrCast<DigestM2>(d->dupShared());
        c->setChunkLength(B(lunghezza));
        auto packet = new Packet("Bollettino", c);
        auto addressReq = packet->addTag<L3AddressReq>();
        addressReq->setDestAddress(Ipv4Address(255, 255, 255, 255));
        addressReq->setSrcAddress(ie->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
        packet->addTag<InterfaceReq>()->setInterfaceId(ie->getInterfaceId());
        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
        packet->setKind(DIGEST_PACKET_KIND);
        contaTrafficoControllo("DIGEST", (int)lunghezza);
        sendDelayed(packet, copia * 0.003, "ipOut");
    }
}

// ---------------------------------------------------------------------------
// Lato drone: ricezione del bollettino
// ---------------------------------------------------------------------------

void Ant2::handleDigest(Packet *packet)
{
    auto d = staticPtrCast<DigestM2>(packet->peekData<DigestM2>()->dupShared());
    // Interfaccia di arrivo: serve per ritrasmettere il bollettino sullo stesso
    // canale da cui e' venuto, invece di indovinare.
    int ifaceArrivo = -1;
    if (auto ind = packet->findTag<InterfaceInd>())
        ifaceArrivo = ind->getInterfaceId();
    delete packet;
    if (!digestCheckEnabled || legacyEnergy)
        return;
    uint32_t origin = d->getOrigin().getInt();
    if (isOwnAddress(d->getOrigin()))
        return;   // la GCS non controlla il proprio bollettino

    // Un drone fuori portata radio dalla GCS non riceverebbe mai il bollettino,
    // quindi ogni nodo lo ritrasmette una volta sola. La chiave (origine,
    // contatore) impedisce che le copie e gli inoltri altrui si moltiplichino.
    std::ostringstream chiave;
    chiave << origin << "/" << d->getContatore();
    bool giaVisto = digestSeen.count(chiave.str()) > 0;
    if (digestSeen.size() > 5000)
        digestSeen.clear();
    digestSeen.insert(chiave.str());
    if (giaVisto)
        return;

    // Contatore monotono: scarta i doppioni e le ripetizioni, e permette di
    // accorgersi dei bollettini persi, che e' una misura della congestione del
    // canale del cluster.
    // Il contatore serve SOLO a contare i buchi, non a scartare. Scartare i
    // bollettini con contatore non crescente era un errore: con l'inoltro un
    // nodo riceve spesso il bollettino N+1 ritrasmesso da un vicino prima del
    // bollettino N arrivato direttamente dalla GCS, e il filtro buttava via
    // quello piu' vecchio anche se portava righe ancora utili. A impedire che
    // lo stesso bollettino venga elaborato due volte basta gia' la chiave
    // (origine, contatore) qui sopra.
    auto itUltimo = digestLastSeen.find(origin);
    if (itUltimo != digestLastSeen.end() && d->getContatore() > itUltimo->second + 1)
        digestGaps += (long)(d->getContatore() - itUltimo->second - 1);

    std::vector<uint8_t> ct(d->getPayloadArraySize());
    for (size_t i = 0; i < ct.size(); i++)
        ct[i] = d->getPayload(i);
    std::vector<uint8_t> aad = ant2digest::wire::bollettinoAad(origin, d->getGiro(),
                                                               d->getContatore(),
                                                               (uint32_t)d->getNumByte());
    std::vector<uint8_t> pt;
    bool valido = true;
    if (securityEnabled) {
        uint8_t tag[Ant2Crypto::MAX_TAG_LEN] = {0};
        uint8_t sig[Ant2Crypto::SIG_LEN];
        if ((int)d->getAuthTagArraySize() != crypto.tagLen())
            valido = false;
        else {
            for (int i = 0; i < crypto.tagLen(); i++)
                tag[i] = d->getAuthTag(i);
            for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
                sig[i] = d->getSignature(i);
            std::vector<uint8_t> firmato = aad;
            firmato.insert(firmato.end(), ct.begin(), ct.end());
            firmato.insert(firmato.end(), tag, tag + crypto.tagLen());
            uint8_t nonce[Ant2Crypto::NONCE_LEN];
            crypto.deriveNonce(origin, 0, d->getContatore(), Ant2Crypto::MSG_DIGEST, nonce);
            valido = crypto.isKnownNode(origin) && crypto.verify(firmato, sig, origin)
                     && crypto.decrypt(ct, tag, aad, nonce, pt);
        }
    }
    else
        pt = ct;

    std::vector<ant2digest::wire::RecordImpronta> impronte;
    std::vector<ant2digest::wire::RecordReq> req;
    bool sezioneReq = false;
    if (!valido || (int)pt.size() != d->getNumByte()
        || !ant2digest::wire::leggiBollettino(pt, impronte, req, &sezioneReq)) {
        digestRejected++;
        logScarto("BOLLETTINO", d->getOrigin(), "firma, cifratura o formato non validi", digestRejected);
        return;
    }
    if (itUltimo == digestLastSeen.end() || d->getContatore() > itUltimo->second)
        digestLastSeen[origin] = d->getContatore();
    digestReceived++;

    // L'inoltro avviene SOLO dopo che firma, cifratura e formato sono risultati
    // validi: ritrasmettere un bollettino falsificato lo diffonderebbe a tutto
    // il cluster a spese di chi lo inoltra.
    // Una copia sola: le copie multiple servono a chi pubblica, mentre qui ogni
    // nodo del cluster ritrasmette gia' una volta per conto suo, e moltiplicarle
    // intaserebbe il canale.
    if (digestRelay) {
        digestRelayed++;
        sendDigestPacket(d, 1, ifaceArrivo);
    }

    // Prima di tutto: due righe con lo stesso nodo e lo stesso timbro ma
    // impronte diverse sono la prova che quel drone ha dichiarato due cose
    // diverse della stessa lettura. Qui non serve nemmeno che chi legge abbia
    // la propria copia: la prova e' gia' completa dentro il bollettino.
    for (size_t i = 0; i < impronte.size(); i++) {
        for (size_t j = i + 1; j < impronte.size(); j++) {
            if (impronte[i].nodo != impronte[j].nodo)
                continue;
            if (std::fabs(impronte[i].timbro - impronte[j].timbro) > digestParams.tolTimbro)
                continue;
            if (impronte[i].impronta == impronte[j].impronta)
                continue;
            Ipv4Address nodo(impronte[i].nodo);
            if (isOwnAddress(nodo))
                continue;
            DigestObserved& o = digestObserved[impronte[i].nodo];
            digestResolveNome(nodo, o);
            if (!o.valido)
                continue;
            auto esiti = segnalaContesa(o.st, impronte[i].timbro,
                                        impronte[i].impronta, impronte[j].impronta,
                                        (Fonte)impronte[i].fonte, (Fonte)impronte[j].fonte,
                                        digestParams);
            digestApplicaEsiti(nodo, o, esiti);
        }
    }

    // Sezione delle impronte: il confronto vero e proprio.
    for (auto& r : impronte) {
        Ipv4Address nodo(r.nodo);
        if (isOwnAddress(nodo))
            continue;   // le proprie dichiarazioni non si controllano
        DigestObserved& o = digestObserved[r.nodo];
        digestResolveNome(nodo, o);
        if (!o.valido)
            continue;
        // Le righe di una lettura gia' accertata falsa non vanno ricontrollate:
        // l'allerta che le porta viene ripetuta per farla arrivare a tutti, e
        // contarle come "non applicabili" falserebbe la misura della copertura.
        if (ant2digest::giaContesa(o.st, r.timbro, digestParams))
            continue;
        auto esiti = checkDigest(o.st, r.timbro, r.impronta, (Fonte)r.fonte, digestParams);
        digestApplicaEsiti(nodo, o, esiti);
    }

    // Sezione dei REQ: sono fatti che questo nodo non puo' procurarsi da solo,
    // perche' un REQ raggiunge solo una parte degli osservatori. Entrano nello
    // stesso registro che le regole 2 e 4 gia' leggono, cosi' i loro dubbi
    // diventano certezze senza toccare la logica di quelle regole.
    for (auto& r : req)
        noteMoveEvent(Ipv4Address(r.mittente), Ipv4Address(r.destinatario),
                      Coord(r.x, r.y, r.z), r.seq, r.istante, true);

    // La sezione dei REQ e' arrivata: da questo momento il registro di questo
    // nodo e' allineato a quello della GCS fino all'istante in cui il bollettino
    // e' stato costruito. Gli spostamenti rimasti in dubbio prima di quell'istante
    // non hanno nessun REQ che li giustifichi nemmeno per la GCS, quindi
    // diventano violazioni certe.
    //
    // Si aggiorna solo se la SEZIONE era presente: una sezione vuota prova che la
    // GCS non conosceva nessun REQ, una sezione assente non prova niente.
    if (sezioneReq) {
        const double emesso = d->getIstante();
        if (emesso > ultimoBollettinoReq) {
            ultimoBollettinoReq = emesso;
            // Fin dove il registro pubblicato risale: una sezione vuota copre
            // tutto, altrimenti copre dal REQ piu' vecchio che contiene, perche'
            // i precedenti possono essere stati tagliati dal tetto alle righe.
            double piuVecchio = -1e300;
            for (auto& r : req)
                if (piuVecchio == -1e300 || r.istante < piuVecchio)
                    piuVecchio = r.istante;
            bollettinoReqCopreDa = piuVecchio;
        }
        risolviDubbiPosizioneTutti();
    }
}

// ---------------------------------------------------------------------------
// Punizione: effetto della metrica di trust sul reclutamento
// ---------------------------------------------------------------------------

long Ant2::violazioniCerte(uint32_t nodo) const
{
    // Solo le violazioni CERTE, non i dubbi: un dubbio ha sempre una
    // spiegazione innocente possibile, tipicamente un REQ che chi controlla non
    // ha ricevuto, e punire su un dubbio significherebbe punire la perdita di
    // pacchetti invece della malafede.
    long n = 0;
    auto e = energyObserved.find(nodo);       if (e != energyObserved.end())       n += e->second.violati;
    auto po = positionObserved.find(nodo);    if (po != positionObserved.end())    n += po->second.violati;
    auto a = availabilityObserved.find(nodo); if (a != availabilityObserved.end()) n += a->second.violati;
    auto h = helpObserved.find(nodo);         if (h != helpObserved.end())         n += h->second.violati;
    auto b = bandObserved.find(nodo);         if (b != bandObserved.end())         n += b->second.violati;
    auto d = digestObserved.find(nodo);       if (d != digestObserved.end())       n += d->second.st.violati;
    auto hp = hopObserved.find(scenNomeDi(Ipv4Address(nodo)));
    if (hp != hopObserved.end()) n += hp->second.st.violati;
    return n;
}

// ---------------------------------------------------------------------------
// File di registrazione e riepilogo
// ---------------------------------------------------------------------------

std::ofstream& Ant2::digestCheckLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_impronta", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Regola 0 della metrica di trust: coerenza fra canali (equivocazione)\n";
        log << "# formato: <tempo> <nodo che controlla> <drone osservato> <controllo> <ESITO> <dettaglio>\n";
        log << "# controlli: 'coerenza fra canali'   impronta del nodo contro quella pubblicata dalla GCS\n";
        log << "#            'coerenza fra messaggi' due messaggi arrivati a questo stesso nodo, stesso\n";
        log << "#                                    timbro e valori diversi (non serve la GCS)\n";
        log << "# esiti: SUPERATO        le due impronte della stessa lettura coincidono\n";
        log << "#        VIOLATO         non coincidono: il drone ha dichiarato due cose diverse (certo)\n";
        log << "#        NON_APPLICABILE la GCS ha pubblicato una lettura che questo nodo non ha\n";
        log << "# Quando una lettura risulta falsificata, gli esiti che le regole 1-5 ne avevano tratto\n";
        log << "# vengono annullati e la riga lo riporta: giudicare il contenuto di una dichiarazione\n";
        log << "# che sappiamo falsa non ha senso, e al loro posto resta questa violazione certa.\n";
        log << "# Esempi:  grep VIOLATO ant2_impronta*.log\n";
        log << "#\n";
    }
    return log;
}

void Ant2::digestCheckFinish()
{
    recordScalar("controlliImprontaSuperati", digestCheckSuperati);
    recordScalar("controlliImprontaViolati", digestCheckViolati);
    recordScalar("controlliImprontaNonApplicabili", digestCheckNonApplicabili);
    recordScalar("controlliImprontaViolatiLocali", digestCheckViolatiLocali);
    recordScalar("esitiAnnullatiSuperati", digestAnnullatiSuperati);
    recordScalar("esitiAnnullatiViolati", digestAnnullatiViolati);
    recordScalar("esitiAnnullatiDubbi", digestAnnullatiDubbi);
    recordScalar("bollettiniInviati", digestSent);
    recordScalar("bollettiniRicevuti", digestReceived);
    recordScalar("bollettiniRifiutati", digestRejected);
    recordScalar("bollettiniPersi", digestGaps);
    recordScalar("bollettiniInoltrati", digestRelayed);
    recordScalar("allerteInviate", digestAlerts);
    recordScalar("righeImprontaInviate", digestRowsSent);
    // Bollettino a due velocita': quante righe del proprio cluster (pubblicate a
    // ogni giro) e quante degli altri (solo nel bollettino completo).
    recordScalar("righeImprontaProprioCluster", digestRowsCluster);
    recordScalar("bollettiniUnicast", digestUnicastSent);
    recordScalar("righeImprontaAltriCluster", digestRowsAltrui);
    recordScalar("bollettiniCompleti", digestFullSent);
    recordScalar("righeReqInviate", digestReqRowsSent);
    // Letture ancora in attesa di una conferma dalla GCS: e' la misura della
    // copertura del meccanismo, cioe' quanta parte della metrica poggia su dati
    // non verificati in modo indipendente.
    long attesa = 0;
    for (auto& kv : digestObserved)
        attesa += ant2digest::nonVerificate(kv.second.st);
    recordScalar("lettureNonVerificate", attesa);
    recordScalar("reclutamentiNegatiPerSfiducia", reclutamentiNegati);

    if (!digestCheckEnabled || legacyEnergy)
        return;

    digestCheckLogFile();   // vedi la nota in positionCheckFinish()

    struct Tot { long superati = 0, violati = 0, nonApplicabili = 0, violatiGcs = 0, locali = 0;
                 long confermate = 0, contraddette = 0, nonVerificate = 0;
                 std::set<std::string> controllori; };
    static std::map<std::string, Tot> totali;
    static int runTotali = -1;
    int runCorr = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runTotali != runCorr) {
        runTotali = runCorr;
        totali.clear();
    }
    std::string io = getContainingNode(this)->getFullName();
    for (auto& kv : digestObserved) {
        const DigestObserved& o = kv.second;
        if (!o.valido)
            continue;
        Tot& t = totali[o.nome];
        t.superati += o.st.superati;
        t.violati += o.st.violati;
        t.nonApplicabili += o.st.nonApplicabili;
        t.locali += o.st.violatiLocali;
        t.confermate += o.st.confermate;
        t.contraddette += o.st.contraddette;
        t.nonVerificate += ant2digest::nonVerificate(o.st);
        if (io.rfind("gat", 0) == 0)
            t.violatiGcs += o.st.violati;
        if (o.st.superati + o.st.violati > 0)
            t.controllori.insert(io);
    }
    std::ofstream r(nomeFileRun("ant2_impronta_riepilogo", ".txt"), std::ios::trunc);
    r << "# Regola 0 (coerenza fra canali): totali di rete per drone osservato\n";
    r << "# superati = letture confermate dalla GCS; violati = equivocazioni certe\n";
    r << "# (di cui locali) = colte da due messaggi arrivati allo stesso osservatore, senza la GCS\n";
    r << "# non_verificate = letture per cui non e' mai arrivata un'impronta: misura la copertura\n";
    r << "# drone  superati  violati  (di cui dalla GCS)  (di cui locali)  non_applicabili  non_verificate  nodi\n";
    for (auto& kv : totali)
        r << kv.first << "  " << kv.second.superati << "  " << kv.second.violati << "  ("
          << kv.second.violatiGcs << ")  (" << kv.second.locali << ")  "
          << kv.second.nonApplicabili << "  " << kv.second.nonVerificate
          << "  " << kv.second.controllori.size() << "\n";
}

}   // namespace ant2
}   // namespace inet
