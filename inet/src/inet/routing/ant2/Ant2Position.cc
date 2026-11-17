//
// Ant2Position.cc
//
// Regola 2 della metrica di trust: collegamento del controllo sulla posizione
// (la logica pura sta in Ant2PositionCheck.h, verificata dai test automatici in
// test_controllo_posizione.cc).
//
// Il file contiene tre cose:
//   - noteMoveEvent(): annota nel registro degli eventi i REQ ricevuti, da cui
//     si capisce quali spostamenti sono giustificati;
//   - checkPositionRule(): esegue il controllo su ogni misura di posizione
//     dichiarata in un BANT;
//   - il file di registrazione e il riepilogo di fine simulazione.
//
#include "inet/routing/ant2/Ant2.h"

#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/common/ModuleAccess.h"

namespace inet {
namespace ant2 {

// ---------------------------------------------------------------------------
// File di registrazione (uno per run, condiviso da tutti i nodi)
// ---------------------------------------------------------------------------

std::ofstream& Ant2::positionCheckLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_posizione", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Regola 2 della metrica di trust: controllo sulla posizione dichiarata nei BANT\n";
        log << "# formato: <tempo> <nodo che controlla> <drone osservato> <controllo> <ESITO> <dettaglio>\n";
        log << "# esiti: SUPERATO        spostamento giustificato da un evento e coerente con esso\n";
        log << "#        VIOLATO         c'e' l'evento ma la destinazione non corrisponde (certo)\n";
        log << "#        DUBBIO          nessun evento compatibile: puo' essere un attacco, ma anche\n";
        log << "#                        un REQ che chi controlla non ha ricevuto\n";
        log << "#        NON_APPLICABILE misura ripetuta o in disordine, oppure partenza non nota\n";
        log << "# Un drone fermo non produce nessun esito: contarlo riempirebbe i contatori.\n";
        log << "# Le violazioni e i dubbi sono sempre registrati; i superati e i non applicabili\n";
        log << "# solo con positionCheckLogAll = true.\n";
        log << "# Esempi:  grep VIOLATO ant2_posizione*.log      grep DUBBIO ant2_posizione*.log\n";
        log << "#\n";
    }
    return log;
}

// ---------------------------------------------------------------------------
// Registro degli eventi: i REQ ricevuti
// ---------------------------------------------------------------------------

void Ant2::noteMoveEvent(const Ipv4Address& mittente, const Ipv4Address& destinatario,
                         const Coord& posRichiedente, unsigned int seq,
                         double istanteReale, bool daGcs)
{
    if (!positionCheckEnabled || legacyEnergy)
        return;

    // Istante in cui il REQ e' stato emesso. Per un REQ osservato di persona e'
    // adesso; per uno riferito dalla GCS e' quello che il bollettino riporta.
    const double tReq = (istanteReale >= 0) ? istanteReale : simTime().dbl();

    // Il tipo di evento si riconosce dai campi firmati del REQ: se mittente e
    // destinatario coincidono e' l'avviso di batteria scarica che il drone
    // manda a se stesso e che gli altri inoltrano, altrimenti e' un
    // reclutamento e il destinatario e' il drone scelto per prestare aiuto.
    bool avviso = (mittente == destinatario);
    uint32_t drone = destinatario.getInt();

    // Il REQ viaggia per inondazione e arriva piu' volte: lo stesso evento non
    // va annotato due volte, altrimenti una sola richiesta giustificherebbe
    // piu' spostamenti.
    for (auto& e : moveEvents)
        if (e.drone == drone && e.seq == seq
            && e.tipo == (avviso ? ant2position::TipoEvento::AVVISO : ant2position::TipoEvento::RECLUTAMENTO)) {
            // L'evento c'era gia'. Se adesso lo stiamo vedendo di persona e
            // prima ce l'aveva riferito la GCS, la prova diventa di prima mano
            // e l'attesa corrispondente torna a poter accusare.
            if (!daGcs)
                for (auto& a : helpPending)
                    if (a.drone == drone && a.seq == seq)
                        a.daSecondaMano = false;
            return;
        }

    ant2position::MoveEvent e;
    e.tipo = avviso ? ant2position::TipoEvento::AVVISO : ant2position::TipoEvento::RECLUTAMENTO;
    e.drone = drone;
    e.richiedente = mittente.getInt();
    e.posRichiedente = ant2position::Vec3(posRichiedente.x, posRichiedente.y, posRichiedente.z);
    e.istante = tReq;
    e.seq = seq;
    moveEvents.push_back(e);
    if (avviso)
        moveEventsAvviso++;
    else
        moveEventsReclutamento++;

    EV_DETAIL << "Ant2/posizione: annotato evento " << (avviso ? "avviso batteria scarica" : "reclutamento")
              << " per " << destinatario << " (seq " << seq << ")" << endl;

    // Regola 4 (falso aiuto): un reclutamento apre una verifica. Si annota in
    // quale stato risultava il vincitore nell'istante del REQ, perche' se non
    // era disponibile un drone onesto ignora la richiesta e non c'e' niente da
    // verificare.
    if (!avviso && helpCheckEnabled) {
        helpParams.maxNetworkDelay = maxNetworkDelay;
        helpParams.recruitMoveDelay = recruitMoveDelay;
        bool disponibile = false;
        auto itDisp = availabilityObserved.find(drone);
        if (itDisp != availabilityObserved.end())
            disponibile = itDisp->second.st.atteso == ant2availability::Stato::DISPONIBILE;
        helpPending.push_back(ant2help::nuovaAttesa(drone, mittente.getInt(), tReq,
                                                    seq, disponibile, helpParams, daGcs));
    }

    // Si tengono solo gli eventi abbastanza recenti per poter giustificare uno
    // spostamento ancora da osservare.
    ant2position::ripuliscoRegistro(moveEvents, simTime().dbl(), positionEventMaxAge);
    helpCheckAbbandonate += ant2help::ripulisciAttese(helpPending, simTime().dbl(), helpParams);

    // Un evento nuovo puo' giustificare uno spostamento che era rimasto in
    // dubbio: se il REQ arriva dopo il BANT che mostrava lo spostamento, il
    // dubbio si scioglie adesso.
    risolviDubbiPosizioneTutti();
}

// ---------------------------------------------------------------------------
// Parametri del drone osservato
// ---------------------------------------------------------------------------

void Ant2::resolvePositionObserved(const Ipv4Address& src, PositionObserved& o)
{
    o.risolto = true;
    cModule *h = L3AddressResolver().findHostWithAddress(L3Address(src));
    if (h == nullptr || strcmp(h->getName(), "adh") != 0)
        return;   // si controllano solo i droni: GCS e satellite non si spostano
    o.nome = h->getFullName();
    o.valido = true;
}

// ---------------------------------------------------------------------------
// Il controllo, a ogni misura di posizione dichiarata in un BANT
// ---------------------------------------------------------------------------

void Ant2::checkPositionRule(const Ipv4Address& src, const Coord& pos, double timbro, double energia,
                             const char *fonte)
{
    if (!positionCheckEnabled || legacyEnergy)
        return;
    if (timbro < 0)
        return;   // misura mai eseguita: la segnala la regola 1
    // i propri messaggi non si controllano
    for (auto& wifi : wirelessInterfaces)
        if (wifi->getProtocolData<Ipv4InterfaceData>()->getIPAddress() == src)
            return;
    if (src == x2ppp_address)
        return;

    PositionObserved& o = positionObserved[src.getInt()];
    if (!o.risolto)
        resolvePositionObserved(src, o);
    if (!o.valido)
        return;

    preparaPositionParams();

    ant2position::PositionSample s;
    s.t = timbro;
    s.pos = ant2position::Vec3(pos.x, pos.y, pos.z);
    s.energia = energia;
    s.fonte = fonte;

    // Lo spostamento di reclutamento viene annullato se, allo scadere del
    // timer, il drone era andato a ricaricarsi: moveUav() in quel caso esce
    // senza spostare. Il reclutamento non eseguito viene quindi consumato, cosi'
    // non resta nel registro a giustificare uno spostamento successivo.
    bool allaStazione = o.st.has && o.st.ancoraAllaStazione;
    ant2position::consumaReclutamentiAnnullati(moveEvents, src.getInt(), allaStazione);

    for (auto& esito : ant2position::checkPosition(o.st, s, positionParams, moveEvents, src.getInt()))
        applicaEsitoPosizione(src, o, esito);
}

// ---------------------------------------------------------------------------
// Parametri del controllo: gli stessi valori che usa il codice che sposta i
// droni, cosi' controllo e spostamento restano coerenti.
// ---------------------------------------------------------------------------

void Ant2::preparaPositionParams()
{
    positionParams.maxNetworkDelay = maxNetworkDelay;
    positionParams.recruitOffset = recruitOffset;
    positionParams.recruitRadius = recruitRadius;
    positionParams.recruitAltitude = recruitAltitude;
    positionParams.recruitMoveDelay = recruitMoveDelay;
    positionParams.chargeDepartureDelay = chargeDepartureDelay;
    positionParams.stazione = ant2position::Vec3(chargingStation.x, chargingStation.y, chargingStation.z);
    positionParams.margineBollettino = maxNetworkDelay;
}

// ---------------------------------------------------------------------------
// Registrazione di un esito, da qualunque strada arrivi: dal controllo su una
// misura nuova o dalla risoluzione di un dubbio sospeso.
// ---------------------------------------------------------------------------

void Ant2::applicaEsitoPosizione(const Ipv4Address& src, PositionObserved& o,
                                 const ant2position::PositionOutcome& esito)
{
    std::string io = getContainingNode(this)->getFullName();
    bool daRegistrare = positionCheckLogAll;
    if (esito.esito == ant2position::Esito::SUPERATO) { o.superati++; positionCheckSuperati++; }
    else if (esito.esito == ant2position::Esito::VIOLATO) {
        o.violati++; positionCheckViolati++; daRegistrare = true;
    }
    else if (esito.esito == ant2position::Esito::DUBBIO) {
        o.dubbi++; positionCheckDubbi++; daRegistrare = true;
    }
    else
        o.nonApplicabili++;

    if (daRegistrare)
        positionCheckLogFile() << simTime() << "  " << io << "  " << o.nome << "  " << esito.controllo
                               << "  " << ant2position::esitoStr(esito.esito) << "  " << esito.dettaglio << "\n";
    // Regola 3: uno spostamento confermato e' la prova che il drone ha
    // ricevuto il REQ e lo ha accettato, oppure che e' alla stazione.
    // Da quel momento la disponibilita' che dichiara deve essere coerente.
    if (esito.mossa != ant2position::Mossa::NESSUNA) {
        ant2availability::Mossa m = ant2availability::Mossa::NESSUNA;
        if (esito.mossa == ant2position::Mossa::RECLUTAMENTO)
            m = ant2availability::Mossa::RECLUTAMENTO;
        else if (esito.mossa == ant2position::Mossa::ANDATA_STAZIONE)
            m = ant2availability::Mossa::ANDATA_STAZIONE;
        else if (esito.mossa == ant2position::Mossa::RITORNO_STAZIONE)
            m = ant2availability::Mossa::RITORNO_STAZIONE;
        availabilityStato(src, m, esito.timbro);
        // Regola 4: lo spostamento di reclutamento confermato e' la prova
        // che l'aiuto e' partito, e dice anche verso chi.
        if (esito.mossa == ant2position::Mossa::RECLUTAMENTO)
            ant2help::segnalaSpostamento(helpPending, src.getInt(), esito.richiedente, true, false);
    }
    // Uno spostamento segnalato dalla regola 2 non viene punito anche dalla
    // regola 4: sarebbe punire due volte lo stesso fatto.
    if (esito.esito == ant2position::Esito::VIOLATO || esito.esito == ant2position::Esito::DUBBIO)
        ant2help::segnalaSpostamento(helpPending, src.getInt(), 0, false, true);
    if (esito.esito == ant2position::Esito::VIOLATO)
        EV_WARN << "Ant2/posizione: " << io << " rileva una violazione di " << o.nome
                << ": " << esito.dettaglio << endl;
    else if (esito.esito == ant2position::Esito::DUBBIO)
        EV_INFO << "Ant2/posizione: " << io << " rileva uno spostamento non giustificato di " << o.nome
                << ": " << esito.dettaglio << endl;
}

// ---------------------------------------------------------------------------
// Risoluzione dei dubbi sospesi
//
// Uno spostamento senza evento osservato resta in attesa: puo' essere un
// attacco, ma anche un REQ che questo nodo non ha ricevuto. Il bollettino dei
// REQ pubblicato e firmato dalla GCS lo decide, perche' il registro della GCS e'
// considerato completo. Va ripassato a ogni arrivo di REQ, di persona o dal
// bollettino, perche' un REQ nuovo puo' sciogliere un dubbio vecchio.
// ---------------------------------------------------------------------------

void Ant2::risolviDubbiPosizioneTutti()
{
    if (!positionCheckEnabled || legacyEnergy)
        return;
    preparaPositionParams();
    for (auto& kv : positionObserved) {
        PositionObserved& o = kv.second;
        if (!o.valido || o.st.sospesi.empty())
            continue;
        Ipv4Address src(kv.first);
        for (auto& esito : ant2position::risolviDubbiPosizione(o.st, positionParams, moveEvents,
                                                               kv.first, ultimoBollettinoReq,
                                                               bollettinoReqCopreDa)) {
            if (esito.esito == ant2position::Esito::SUPERATO)
                positionDubbiSciolti++;
            else if (esito.esito == ant2position::Esito::VIOLATO)
                positionDubbiCondannati++;
            applicaEsitoPosizione(src, o, esito);
        }
    }
}

// ---------------------------------------------------------------------------
// Scalari e riepilogo di rete, a fine simulazione
// ---------------------------------------------------------------------------

void Ant2::positionCheckFinish()
{
    recordScalar("controlliPosizioneSuperati", positionCheckSuperati);
    recordScalar("controlliPosizioneViolati", positionCheckViolati);
    recordScalar("controlliPosizioneDubbi", positionCheckDubbi);
    recordScalar("eventiReclutamentoOsservati", moveEventsReclutamento);
    recordScalar("eventiAvvisoOsservati", moveEventsAvviso);
    // Quanti dubbi il bollettino dei REQ della GCS ha deciso, nei due versi.
    recordScalar("dubbiPosizioneSciolti", positionDubbiSciolti);
    recordScalar("dubbiPosizioneCondannati", positionDubbiCondannati);
    // Dubbi ancora in attesa a fine simulazione: nessun bollettino li ha decisi.
    long inAttesa = 0, abbandonati = 0;
    for (auto& kv : positionObserved) {
        inAttesa += (long)kv.second.st.sospesi.size();
        abbandonati += kv.second.st.dubbiAbbandonati;
    }
    recordScalar("dubbiPosizioneInAttesa", inAttesa);
    recordScalar("dubbiPosizioneAbbandonati", abbandonati);
    if (!positionCheckEnabled || legacyEnergy)
        return;

    // I file di registrazione vengono aperti alla prima scrittura. Se in questo
    // run non c'e' stato niente da registrare (nessuna violazione e il registro
    // completo disattivato), senza questa riga resterebbe sul disco il file del
    // run precedente, che sembrerebbe attuale e trarrebbe in inganno chi legge i
    // risultati. Toccarlo qui lo tronca e gli lascia la sola intestazione.
    positionCheckLogFile();

    struct Tot { long superati = 0, violati = 0, dubbi = 0, nonApplicabili = 0, violatiGcs = 0;
                 std::set<std::string> controllori; };
    static std::map<std::string, Tot> totali;
    static int runTotali = -1;
    int runCorr = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runTotali != runCorr) {
        runTotali = runCorr;
        totali.clear();
    }
    std::string io = getContainingNode(this)->getFullName();
    for (auto& kv : positionObserved) {
        const PositionObserved& o = kv.second;
        if (!o.valido)
            continue;
        Tot& t = totali[o.nome];
        t.superati += o.superati;
        t.violati += o.violati;
        t.dubbi += o.dubbi;
        t.nonApplicabili += o.nonApplicabili;
        if (io.rfind("gat", 0) == 0)
            t.violatiGcs += o.violati;
        if (o.superati + o.violati + o.dubbi > 0)
            t.controllori.insert(io);
    }
    std::ofstream r(nomeFileRun("ant2_posizione_riepilogo", ".txt"), std::ios::trunc);
    r << "# Regola 2 (controllo sulla posizione): totali di rete per drone osservato\n";
    r << "# drone  superati  violati  (di cui dalla GCS)  dubbi  non_applicabili  nodi_che_lo_hanno_controllato\n";
    for (auto& kv : totali)
        r << kv.first << "  " << kv.second.superati << "  " << kv.second.violati << "  ("
          << kv.second.violatiGcs << ")  " << kv.second.dubbi << "  " << kv.second.nonApplicabili
          << "  " << kv.second.controllori.size() << "\n";
}

// ===========================================================================
// Regola 3 della metrica di trust: la disponibilita' (Ant2AvailabilityCheck.h)
// ===========================================================================

std::ofstream& Ant2::availabilityCheckLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_disponibilita", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Regola 3 della metrica di trust: controllo sulla disponibilita' dichiarata nei BANT\n";
        log << "# formato: <tempo> <nodo che controlla> <drone osservato> <controllo> <ESITO> <dettaglio>\n";
        log << "# Lo stato atteso (disponibile, impegnato, in ricarica) non viene stabilito\n";
        log << "# dall'arrivo del REQ, che puo' non essere giunto al drone, ma dallo spostamento\n";
        log << "# confermato dalla regola 2 sulla posizione: e' quello a provare che il drone ha\n";
        log << "# ricevuto la richiesta e l'ha accettata.\n";
        log << "# esiti: SUPERATO        la disponibilita' dichiarata coincide con quella attesa\n";
        log << "#        VIOLATO         si dichiara disponibile quando non puo' esserlo (certo)\n";
        log << "#        NON_APPLICABILE si dichiara non disponibile mentre chi controlla lo crede\n";
        log << "#                        disponibile: puo' essere un REQ non osservato\n";
        log << "# Si contano solo il primo esito dopo ogni cambiamento di stato e quelli in cui il\n";
        log << "# valore dichiarato cambia: altrimenti i contatori si gonfierebbero di esiti positivi.\n";
        log << "# Esempi:  grep VIOLATO ant2_disponibilita*.log\n";
        log << "#\n";
    }
    return log;
}

void Ant2::availabilityStato(const Ipv4Address& src, ant2availability::Mossa mossa, double timbro)
{
    if (!availabilityCheckEnabled || legacyEnergy || mossa == ant2availability::Mossa::NESSUNA)
        return;
    AvailabilityObserved& o = availabilityObserved[src.getInt()];
    ant2availability::aggiornaStato(o.st, mossa, timbro);
}

void Ant2::checkAvailabilityRule(const Ipv4Address& src, bool disponibile, double timbro)
{
    if (!availabilityCheckEnabled || legacyEnergy)
        return;
    if (timbro < 0)
        return;
    for (auto& wifi : wirelessInterfaces)
        if (wifi->getProtocolData<Ipv4InterfaceData>()->getIPAddress() == src)
            return;
    if (src == x2ppp_address)
        return;

    AvailabilityObserved& o = availabilityObserved[src.getInt()];
    if (!o.risolto) {
        o.risolto = true;
        cModule *h = L3AddressResolver().findHostWithAddress(L3Address(src));
        if (h != nullptr && strcmp(h->getName(), "adh") == 0) {
            o.nome = h->getFullName();
            o.valido = true;
        }
    }
    if (!o.valido)
        return;

    ant2availability::AvailabilitySample s;
    s.t = timbro;
    s.disponibile = disponibile;

    std::string io = getContainingNode(this)->getFullName();
    for (auto& esito : ant2availability::checkAvailability(o.st, s)) {
        bool daRegistrare = availabilityCheckLogAll;
        if (esito.esito == ant2availability::Esito::SUPERATO) { o.superati++; availabilityCheckSuperati++; }
        else if (esito.esito == ant2availability::Esito::VIOLATO) {
            o.violati++; availabilityCheckViolati++; daRegistrare = true;
        }
        else if (esito.esito == ant2availability::Esito::DUBBIO) {
            o.dubbi++; availabilityCheckDubbi++; daRegistrare = true;
        }
        else
            o.nonApplicabili++;

        if (daRegistrare)
            availabilityCheckLogFile() << simTime() << "  " << io << "  " << o.nome << "  " << esito.controllo
                                       << "  " << ant2availability::esitoStr(esito.esito) << "  " << esito.dettaglio << "\n";
        if (esito.esito == ant2availability::Esito::VIOLATO)
            EV_WARN << "Ant2/disponibilita': " << io << " rileva una violazione di " << o.nome
                    << ": " << esito.dettaglio << endl;
    }
}

void Ant2::availabilityCheckFinish()
{
    recordScalar("controlliDisponibilitaSuperati", availabilityCheckSuperati);
    recordScalar("controlliDisponibilitaViolati", availabilityCheckViolati);
    recordScalar("controlliDisponibilitaDubbi", availabilityCheckDubbi);
    if (!availabilityCheckEnabled || legacyEnergy)
        return;

    // vedi la nota in positionCheckFinish()
    availabilityCheckLogFile();

    struct Tot { long superati = 0, violati = 0, dubbi = 0, nonApplicabili = 0, violatiGcs = 0;
                 std::set<std::string> controllori; };
    static std::map<std::string, Tot> totali;
    static int runTotali = -1;
    int runCorr = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runTotali != runCorr) {
        runTotali = runCorr;
        totali.clear();
    }
    std::string io = getContainingNode(this)->getFullName();
    for (auto& kv : availabilityObserved) {
        const AvailabilityObserved& o = kv.second;
        if (!o.valido)
            continue;
        Tot& t = totali[o.nome];
        t.superati += o.superati;
        t.violati += o.violati;
        t.dubbi += o.dubbi;
        t.nonApplicabili += o.nonApplicabili;
        if (io.rfind("gat", 0) == 0)
            t.violatiGcs += o.violati;
        if (o.superati + o.violati + o.dubbi > 0)
            t.controllori.insert(io);
    }
    std::ofstream r(nomeFileRun("ant2_disponibilita_riepilogo", ".txt"), std::ios::trunc);
    r << "# Regola 3 (controllo sulla disponibilita'): totali di rete per drone osservato\n";
    r << "# drone  superati  violati  (di cui dalla GCS)  dubbi  non_applicabili  nodi_che_lo_hanno_controllato\n";
    for (auto& kv : totali)
        r << kv.first << "  " << kv.second.superati << "  " << kv.second.violati << "  ("
          << kv.second.violatiGcs << ")  " << kv.second.dubbi << "  " << kv.second.nonApplicabili
          << "  " << kv.second.controllori.size() << "\n";
}

// ===========================================================================
// Regola 4 della metrica di trust: il falso aiuto (Ant2HelpCheck.h)
// ===========================================================================

std::ofstream& Ant2::helpCheckLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_falso_aiuto", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Regola 4 della metrica di trust: controllo sul falso aiuto\n";
        log << "# formato: <tempo> <nodo che controlla> <drone osservato> <controllo> <ESITO> <dettaglio>\n";
        log << "# Verifica un comportamento, non un valore: il drone che ha vinto il reclutamento e'\n";
        log << "# andato davvero a prestare aiuto? Si appoggia al registro dei REQ della regola 2 e\n";
        log << "# alla conferma dello spostamento della regola 2 stessa, senza aggiungere dati alla rete.\n";
        log << "# L'istante limite e' t_R + D + ritardo dello spostamento: prima di quello un BANT non\n";
        log << "# dice niente, perche' il drone potrebbe non avere ancora ricevuto il REQ.\n";
        log << "# esiti: SUPERATO        spostamento verso chi ha chiesto aiuto confermato\n";
        log << "#        VIOLATO         si dichiara non disponibile ma non si e' spostato (certo)\n";
        log << "#        DUBBIO          non si e' spostato e si dichiara ancora disponibile: puo' avere\n";
        log << "#                        ignorato la richiesta, oppure non averla mai ricevuta\n";
        log << "#        NON_APPLICABILE non poteva accettare, e' in ricarica, e' impegnato altrove,\n";
        log << "#                        oppure il suo spostamento e' gia' segnalato dalla regola 2\n";
        log << "# Esempi:  grep VIOLATO ant2_falso_aiuto*.log      grep DUBBIO ant2_falso_aiuto*.log\n";
        log << "#\n";
    }
    return log;
}

void Ant2::helpResolveNome(const Ipv4Address& src, HelpObserved& o)
{
    o.risolto = true;
    cModule *h = L3AddressResolver().findHostWithAddress(L3Address(src));
    if (h == nullptr || strcmp(h->getName(), "adh") != 0)
        return;
    o.nome = h->getFullName();
    o.valido = true;
}

void Ant2::checkHelpRule(const Ipv4Address& src, bool disponibile, const Coord& pos, double timbro)
{
    if (!helpCheckEnabled || legacyEnergy)
        return;
    if (timbro < 0)
        return;
    for (auto& wifi : wirelessInterfaces)
        if (wifi->getProtocolData<Ipv4InterfaceData>()->getIPAddress() == src)
            return;
    if (src == x2ppp_address)
        return;

    HelpObserved& o = helpObserved[src.getInt()];
    if (!o.risolto)
        helpResolveNome(src, o);
    if (!o.valido)
        return;

    helpParams.maxNetworkDelay = maxNetworkDelay;
    helpParams.recruitMoveDelay = recruitMoveDelay;

    ant2help::Contesto c;
    c.disponibileDichiarata = disponibile;
    c.allaStazione = calculateEuclideanDistance(pos, chargingStation) <= positionParams.tolPosM;

    std::string io = getContainingNode(this)->getFullName();
    for (auto& esito : ant2help::checkHelp(helpPending, src.getInt(), timbro, c, helpParams)) {
        bool daRegistrare = helpCheckLogAll;
        if (esito.esito == ant2help::Esito::SUPERATO) { o.superati++; helpCheckSuperati++; }
        else if (esito.esito == ant2help::Esito::VIOLATO) {
            o.violati++; helpCheckViolati++; daRegistrare = true;
        }
        else if (esito.esito == ant2help::Esito::DUBBIO) {
            o.dubbi++; helpCheckDubbi++; daRegistrare = true;
        }
        else
            o.nonApplicabili++;

        if (daRegistrare)
            helpCheckLogFile() << simTime() << "  " << io << "  " << o.nome << "  " << esito.controllo
                               << "  " << ant2help::esitoStr(esito.esito) << "  " << esito.dettaglio << "\n";
        if (esito.esito == ant2help::Esito::VIOLATO)
            EV_WARN << "Ant2/falso aiuto: " << io << " rileva una violazione di " << o.nome
                    << ": " << esito.dettaglio << endl;
    }
}

void Ant2::helpCheckFinish()
{
    recordScalar("controlliFalsoAiutoSuperati", helpCheckSuperati);
    recordScalar("controlliFalsoAiutoViolati", helpCheckViolati);
    recordScalar("controlliFalsoAiutoDubbi", helpCheckDubbi);
    recordScalar("verificheFalsoAiutoAbbandonate", helpCheckAbbandonate);
    if (!helpCheckEnabled || legacyEnergy)
        return;

    // vedi la nota in positionCheckFinish()
    helpCheckLogFile();

    struct Tot { long superati = 0, violati = 0, dubbi = 0, nonApplicabili = 0, violatiGcs = 0;
                 std::set<std::string> controllori; };
    static std::map<std::string, Tot> totali;
    static int runTotali = -1;
    int runCorr = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runTotali != runCorr) {
        runTotali = runCorr;
        totali.clear();
    }
    std::string io = getContainingNode(this)->getFullName();
    for (auto& kv : helpObserved) {
        const HelpObserved& o = kv.second;
        if (!o.valido)
            continue;
        Tot& t = totali[o.nome];
        t.superati += o.superati;
        t.violati += o.violati;
        t.dubbi += o.dubbi;
        t.nonApplicabili += o.nonApplicabili;
        if (io.rfind("gat", 0) == 0)
            t.violatiGcs += o.violati;
        if (o.superati + o.violati + o.dubbi > 0)
            t.controllori.insert(io);
    }
    std::ofstream r(nomeFileRun("ant2_falso_aiuto_riepilogo", ".txt"), std::ios::trunc);
    r << "# Regola 4 (controllo sul falso aiuto): totali di rete per drone osservato\n";
    r << "# drone  superati  violati  (di cui dalla GCS)  dubbi  non_applicabili  nodi_che_lo_hanno_controllato\n";
    for (auto& kv : totali)
        r << kv.first << "  " << kv.second.superati << "  " << kv.second.violati << "  ("
          << kv.second.violatiGcs << ")  " << kv.second.dubbi << "  " << kv.second.nonApplicabili
          << "  " << kv.second.controllori.size() << "\n";
}

// ===========================================================================
// Regola 5 della metrica di trust: la banda massima (Ant2BandCheck.h)
// ===========================================================================

std::ofstream& Ant2::bandCheckLogFile()
{
    static std::ofstream log;
    static int runAperta = -1;
    int runCorrente = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runAperta != runCorrente) {
        if (log.is_open())
            log.close();
        log.open(nomeFileRun("ant2_banda", ".log"), std::ios::trunc);
        runAperta = runCorrente;
        log << "# Regola 5 della metrica di trust: controllo sulla banda massima dichiarata nei BANT\n";
        log << "# formato: <tempo> <nodo che controlla> <drone osservato> <controllo> <ESITO> <dettaglio>\n";
        log << "# La banda massima dichiarata non deve mai cambiare, perche' nel codice viene letta\n";
        log << "# all'avvio e non cambia piu'. Si conta solo la prima dichiarazione, che diventa il\n";
        log << "# riferimento, e ogni cambiamento successivo, che e' una violazione certa.\n";
        log << "# Il controllo non coglie chi dichiara un valore falso sempre uguale dal primo BANT:\n";
        log << "# vedi la documentazione per il controllo sulla richiesta d'aiuto, provato e scartato.\n";
        log << "# Esempi:  grep VIOLATO ant2_banda*.log\n";
        log << "#\n";
    }
    return log;
}

void Ant2::checkBandRule(const Ipv4Address& src, double maxBand, double throughput,
                         double energia, double timbro)
{
    if (!bandCheckEnabled || legacyEnergy)
        return;
    if (timbro < 0)
        return;
    for (auto& wifi : wirelessInterfaces)
        if (wifi->getProtocolData<Ipv4InterfaceData>()->getIPAddress() == src)
            return;
    if (src == x2ppp_address)
        return;

    BandObserved& o = bandObserved[src.getInt()];
    if (!o.risolto) {
        o.risolto = true;
        cModule *h = L3AddressResolver().findHostWithAddress(L3Address(src));
        if (h != nullptr && strcmp(h->getName(), "adh") == 0) {
            o.nome = h->getFullName();
            o.valido = true;
        }
    }
    if (!o.valido)
        return;

    ant2band::BandSample s;
    s.t = timbro;
    s.maxBand = maxBand;
    s.throughput = throughput;
    s.energia = energia;

    std::string io = getContainingNode(this)->getFullName();
    for (auto& esito : ant2band::checkBand(o.st, s, bandParams)) {
        bool daRegistrare = bandCheckLogAll;
        if (esito.esito == ant2band::Esito::SUPERATO) { o.superati++; bandCheckSuperati++; }
        else if (esito.esito == ant2band::Esito::VIOLATO) {
            o.violati++; bandCheckViolati++; daRegistrare = true;
        }
        else
            o.nonApplicabili++;
        if (daRegistrare)
            bandCheckLogFile() << simTime() << "  " << io << "  " << o.nome << "  " << esito.controllo
                               << "  " << ant2band::esitoStr(esito.esito) << "  " << esito.dettaglio << "\n";
        if (esito.esito == ant2band::Esito::VIOLATO)
            EV_WARN << "Ant2/banda: " << io << " rileva una violazione di " << o.nome
                    << ": " << esito.dettaglio << endl;
    }
}

void Ant2::bandCheckFinish()
{
    recordScalar("controlliBandaSuperati", bandCheckSuperati);
    recordScalar("controlliBandaViolati", bandCheckViolati);
    if (!bandCheckEnabled || legacyEnergy)
        return;

    // vedi la nota in positionCheckFinish()
    bandCheckLogFile();

    struct Tot { long superati = 0, violati = 0, nonApplicabili = 0, violatiGcs = 0;
                 std::set<std::string> controllori; };
    static std::map<std::string, Tot> totali;
    static int runTotali = -1;
    int runCorr = getEnvir()->getConfigEx()->getActiveRunNumber();
    if (runTotali != runCorr) {
        runTotali = runCorr;
        totali.clear();
    }
    std::string io = getContainingNode(this)->getFullName();
    for (auto& kv : bandObserved) {
        const BandObserved& o = kv.second;
        if (!o.valido)
            continue;
        Tot& t = totali[o.nome];
        t.superati += o.superati;
        t.violati += o.violati;
        t.nonApplicabili += o.nonApplicabili;
        if (io.rfind("gat", 0) == 0)
            t.violatiGcs += o.violati;
        if (o.superati + o.violati > 0)
            t.controllori.insert(io);
    }
    std::ofstream r(nomeFileRun("ant2_banda_riepilogo", ".txt"), std::ios::trunc);
    r << "# Regola 5 (controllo sulla banda massima): totali di rete per drone osservato\n";
    r << "# drone  superati  violati  (di cui dalla GCS)  non_applicabili  nodi_che_lo_hanno_controllato\n";
    for (auto& kv : totali)
        r << kv.first << "  " << kv.second.superati << "  " << kv.second.violati << "  ("
          << kv.second.violatiGcs << ")  " << kv.second.nonApplicabili
          << "  " << kv.second.controllori.size() << "\n";
}

}  // namespace ant2
}  // namespace inet
