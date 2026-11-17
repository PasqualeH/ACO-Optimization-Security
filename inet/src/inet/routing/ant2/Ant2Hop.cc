//
// Ant2Hop.cc
//
// Regola 6 della metrica di trust: il numero di hop dichiarato.
// La logica pura sta in Ant2HopCheck.h, verificata dai test automatici in
// test_controllo_hop.cc. Qui c'e' il collegamento con il protocollo:
//
//   - checkHopRule()      controllo locale su ogni FANT e BANT ricevuto;
//   - checkCatenaTraccia() controllo sulla catena, eseguito dalla sola GCS
//                          quando una traccia rientra;
//   - hopCheckFinish()    verdetto finale sull'accumulo e riepilogo.
//
#include "inet/routing/ant2/Ant2.h"

#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/common/L3AddressTag_m.h"

#include <sstream>

namespace inet {
namespace ant2 {

using namespace ant2hop;

void Ant2::applicaEsitiHop(HopObserved& o, const std::vector<HopOutcome>& esiti)
{
    if (esiti.empty())
        return;
    std::string io = getContainingNode(this)->getFullName();
    for (auto& e : esiti) {
        switch (e.esito) {
            case Esito::SUPERATO: hopCheckSuperati++; break;
            case Esito::VIOLATO:  hopCheckViolati++; break;
            case Esito::DUBBIO:   hopCheckDubbi++; break;
            default: break;
        }
        if (e.esito == Esito::SUPERATO && !hopCheckLogAll)
            continue;
        hopCheckLogFile() << simTime() << "  " << io << "  " << o.nome << "  "
                          << e.controllo << "  " << esitoStr(e.esito) << "  "
                          << e.dettaglio << "\n";
        hopCheckLogFile().flush();
    }
}

// ---------------------------------------------------------------------------
// Controllo locale su ogni FANT e BANT ricevuto
// ---------------------------------------------------------------------------

void Ant2::checkHopRule(Packet *packet, const Ptr<const Chunk>& contenuto)
{
    if (!hopCheckEnabled || legacyEnergy)
        return;

    // I due tipi di messaggio portano gli stessi tre campi che servono qui.
    Ipv4Address creatore, dichiaratoDa;
    int dichiarato = 0;
    unsigned int seq = 0;
    if (auto f = dynamicPtrCast<const FantM2>(contenuto)) {
        creatore = f->getSrcAddress();
        dichiaratoDa = f->getNextAddress();
        dichiarato = f->getHopdistance();
        seq = f->getSequencenumber();
    }
    else if (auto b = dynamicPtrCast<const BantM2>(contenuto)) {
        creatore = b->getSrcAddress();
        dichiaratoDa = b->getNextAddress();
        dichiarato = b->getHopdistance();
        seq = b->getSequencenumber();
    }
    else
        return;

    // Chi ha trasmesso davvero il messaggio su questo salto. L'indirizzo di
    // livello 3 e' piu' attendibile del campo nextAddress, che e' scritto da chi
    // inoltra e quindi e' sotto il controllo di un eventuale attaccante. Se il
    // dato non c'e' si ripiega sul campo, notando che un attaccante che lo
    // falsifichi per sembrare il creatore perde proprio il vantaggio che
    // cercava: il feromone andrebbe al creatore e non a lui.
    Ipv4Address trasmittente = dichiaratoDa;
    if (auto l3 = packet->findTag<L3AddressInd>())
        trasmittente = l3->getSrcAddress().toIpv4();
    if (trasmittente.isUnspecified() || creatore.isUnspecified())
        return;
    if (isOwnAddress(trasmittente))
        return;   // i propri messaggi non si controllano

    // ATTENZIONE: qui si confrontano NODI, non indirizzi. Ogni nodo ne ha piu'
    // d'uno, l'interfaccia radio e quella X2, e il campo firmato ne porta uno
    // mentre il pacchetto puo' arrivare dall'altro. Confrontare gli indirizzi
    // faceva sembrare un inoltro ogni messaggio che un nodo trasmetteva da
    // un'interfaccia diversa da quella scritta nel messaggio, e produceva una
    // violazione per ogni messaggio originale di ogni nodo onesto.
    std::string nomeTrasmittente = scenNomeDi(trasmittente);
    std::string nomeCreatore = scenNomeDi(creatore);
    // Un nome non risolto e' l'indirizzo stesso: significa che quel nodo non e'
    // registrato, e senza sapere di chi si tratta non si puo' attribuire nulla.
    if (nomeTrasmittente == trasmittente.str() || nomeCreatore == creatore.str())
        return;

    // Lo stesso messaggio arriva piu' volte, per le copie e per l'inondazione:
    // si conta una volta sola per ciascun trasmittente.
    std::ostringstream chiave;
    chiave << nomeTrasmittente << "/" << nomeCreatore << "/" << seq;
    if (hopVisti.count(chiave.str()) > 0)
        return;
    if (hopVisti.size() > 20000)
        hopVisti.clear();
    hopVisti.insert(chiave.str());

    HopObserved& o = hopObserved[nomeTrasmittente];
    o.nome = nomeTrasmittente;
    o.valido = true;

    // La colpa e' di chi trasmette, non di chi ha creato il messaggio: il
    // contatore degli hop va incrementato da chi inoltra, quindi un valore
    // sbagliato in un messaggio inoltrato e' responsabilita' dell'ultimo che lo
    // ha toccato.
    auto esiti = checkHopLocale(o.st, dichiarato, nomeTrasmittente == nomeCreatore, hopParams);
    applicaEsitiHop(o, esiti);
}

// ---------------------------------------------------------------------------
// Controllo sulla catena, eseguito dalla sola GCS
// ---------------------------------------------------------------------------

void Ant2::checkCatenaTraccia(const std::vector<ant2trace::EntryData>& voci)
{
    if (!hopCheckEnabled || legacyEnergy || voci.size() < 2)
        return;

    std::vector<VoceCatena> catena;
    for (auto& e : voci) {
        VoceCatena v;
        v.nodo = e.node;
        v.hopRicevuto = e.hopRecv;
        catena.push_back(v);
    }

    // Ogni nodo attraversato ha partecipato a una catena in piu'.
    for (auto& v : catena) {
        Ipv4Address nodo(v.nodo);
        if (isOwnAddress(nodo))
            continue;
        std::string nome = scenNomeDi(nodo);
        if (nome == nodo.str())
            continue;
        HopObserved& o = hopObserved[nome];
        o.nome = nome;
        o.valido = true;
        o.st.catene++;
    }

    // Dove la numerazione si rompe, entrambi i nodi della coppia diventano
    // sospetti: da una catena sola non si puo' dire quale dei due abbia
    // sbagliato. Sara' l'accumulo su molti giri a distinguerli.
    for (auto& c : analizzaCatena(catena)) {
        hopCoppieSospette++;
        // Il ruolo dentro la coppia e' l'informazione che permette di
        // attribuire la colpa: chi non incrementa compare come precedente con
        // molti successori diversi, mentre la sua vittima compare come
        // successiva sempre accanto a lui.
        std::string nomePrec = scenNomeDi(Ipv4Address(c.precedente));
        std::string nomeSucc = scenNomeDi(Ipv4Address(c.successivo));
        if (nomePrec == Ipv4Address(c.precedente).str() || nomeSucc == Ipv4Address(c.successivo).str())
            continue;
        if (!isOwnAddress(Ipv4Address(c.precedente))) {
            HopObserved& o = hopObserved[nomePrec];
            o.nome = nomePrec;
            o.valido = true;
            annotaCoppiaSospetta(o.st, ant2hop::Ruolo::PRECEDENTE, nomeSucc);
        }
        if (!isOwnAddress(Ipv4Address(c.successivo))) {
            HopObserved& o = hopObserved[nomeSucc];
            o.nome = nomeSucc;
            o.valido = true;
            annotaCoppiaSospetta(o.st, ant2hop::Ruolo::SUCCESSIVO, nomePrec);
        }
        if (hopCheckLogAll) {
            hopCheckLogFile() << simTime() << "  " << getContainingNode(this)->getFullName()
                              << "  coppia (" << scenNomeDi(Ipv4Address(c.precedente)) << ", "
                              << scenNomeDi(Ipv4Address(c.successivo)) << ")  hop nelle tracce  SOSPETTA"
                              << "  alla posizione " << c.posizione << " era atteso " << c.atteso
                              << " e si legge " << c.trovato << "\n";
            hopCheckLogFile().flush();
        }
    }
}

// ---------------------------------------------------------------------------
// File di registrazione e riepilogo
// ---------------------------------------------------------------------------

std::ofstream& Ant2::hopCheckLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_hop", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Regola 6 della metrica di trust: il numero di hop dichiarato\n";
        log << "# formato: <tempo> <nodo che controlla> <nodo osservato> <controllo> <ESITO> <dettaglio>\n";
        log << "# controlli:\n";
        log << "#   'hop dichiarati'    controllo locale, certo: chi trasmette un messaggio creato da un\n";
        log << "#                       altro deve dichiarare almeno 2 hop; chi trasmette un messaggio\n";
        log << "#                       suo deve dichiararne 1. La colpa e' di chi trasmette.\n";
        log << "#   'hop nelle tracce'  catena delle voci di traccia: la voce in posizione i deve\n";
        log << "#                       riportare i+1. La rottura e' certa, la colpa no: la coppia e'\n";
        log << "#                       sospetta e il colpevole si isola accumulando su piu' giri.\n";
        log << "# Perche' conta: gli hop dichiarati entrano nel punteggio di reclutamento come 1/H, ma\n";
        log << "# soprattutto nel feromone dell'instradamento come 100/hop. Dichiararne meno del vero\n";
        log << "# significa diventare il prossimo salto preferito per il traffico altrui, cioe'\n";
        log << "# costruire un sinkhole.\n";
        log << "# Esempi:  grep VIOLATO ant2_hop*.log\n";
        log << "#\n";
    }
    return log;
}

void Ant2::hopCheckFinish()
{
    // Verdetto finale sull'accumulo delle coppie sospette.
    if (hopCheckEnabled && !legacyEnergy) {
        for (auto& kv : hopObserved) {
            if (!kv.second.valido)
                continue;
            auto esiti = verdettoCatena(kv.second.st, hopParams);
            applicaEsitiHop(kv.second, esiti);
        }
    }

    recordScalar("controlliHopSuperati", hopCheckSuperati);
    recordScalar("controlliHopViolati", hopCheckViolati);
    recordScalar("controlliHopDubbi", hopCheckDubbi);
    recordScalar("coppieSospetteHop", hopCoppieSospette);

    if (!hopCheckEnabled || legacyEnergy)
        return;

    hopCheckLogFile();   // vedi la nota in positionCheckFinish()

    struct Tot { long superati = 0, violati = 0, dubbi = 0, violatiGcs = 0;
                 long coppie = 0, catene = 0; std::set<std::string> controllori; };
    static std::map<std::string, Tot> totali;
    static int runTotali = -1;
    int runCorr = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runTotali != runCorr) {
        runTotali = runCorr;
        totali.clear();
    }
    std::string io = getContainingNode(this)->getFullName();
    for (auto& kv : hopObserved) {
        const HopObserved& o = kv.second;
        if (!o.valido)
            continue;
        Tot& t = totali[o.nome];
        t.superati += o.st.superati;
        t.violati += o.st.violati;
        t.coppie += o.st.coppieSospette;
        t.catene += o.st.catene;
        if (io.rfind("gat", 0) == 0)
            t.violatiGcs += o.st.violati;
        if (o.st.superati + o.st.violati > 0)
            t.controllori.insert(io);
    }
    std::ofstream r(nomeFileRun("ant2_hop_riepilogo", ".txt"), std::ios::trunc);
    r << "# Regola 6 (hop dichiarati): totali di rete per nodo osservato\n";
    r << "# superati/violati = controllo locale certo su FANT e BANT trasmessi da quel nodo\n";
    r << "# coppie/catene = controllo sulle tracce: in quante coppie sospette compare,\n";
    r << "#                 su quante catene ha attraversato. Il colpevole ha un rapporto alto.\n";
    r << "# nodo  superati  violati  (di cui dalla GCS)  coppie_sospette  catene  nodi\n";
    for (auto& kv : totali)
        r << kv.first << "  " << kv.second.superati << "  " << kv.second.violati << "  ("
          << kv.second.violatiGcs << ")  " << kv.second.coppie << "  " << kv.second.catene
          << "  " << kv.second.controllori.size() << "\n";
}

}   // namespace ant2
}   // namespace inet
