//
// Copyright (C) 2008
//
// DSDV simple example for INET (add-on)
// Version 2.0
// Diogo Antio & Pedro Menezes
// Instituto Superior Tecnico
// Lisboa - Portugal
// This version and newer version can be found at http://dsdv.8rf.com
// This code was written while assisting the course "Redes moveis e sem fios" http://comp.ist.utl.pt/ec-cm
// Autorization to use and modify this code not needed :P
// The authors hope it will be useful to help understand how
// INET and OMNET++ works(more specifically INET 20061020 and omnet++ 3.3).
// Also we hope it will help in the developing of routing protocols using INET.
//

#ifndef __INET_Ant2_H
#define __INET_Ant2_H

#include <stdio.h>
#include <string.h>

#include <list>
#include <map>
#include <set>
#include <vector>

#include "inet/common/packet/Packet.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
#include "inet/networklayer/ipv4/IIpv4RoutingTable.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/ipv4/Ipv4RoutingTable.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "inet/routing/ant2/FantM2_m.h"
#include "inet/routing/ant2/BantM2_m.h"
#include "inet/routing/ant2/ReqM2_m.h"
#include "inet/routing/ant2/TraceM2_m.h"
#include "inet/routing/ant2/SnapM2_m.h"
#include "inet/routing/ant2/DigestM2_m.h"
#include "inet/routing/ant2/Ant2Trace.h"
#include "inet/routing/ant2/Ant2DigestCheck.h"
#include "inet/routing/ant2/Ant2HopCheck.h"

#include <fstream>   // per il log su file del livello di sicurezza

// Aggiunto per il livello di sicurezza (Ascon-AEAD128 + Ed25519)
#include "inet/routing/ant2/Ant2Crypto.h"
#include "inet/routing/ant2/Ant2KeyAuthority.h"

// Added for energy monitoring
#include "inet/power/management/SimpleEpEnergyManagement.h"

// Correzioni sull'energia: logica pura (percentuale, ricarica) e generatore
// della stazione di ricarica.
#include "inet/routing/ant2/Ant2Energy.h"
// Regola 1 della metrica di trust: controllo sull'energia dichiarata.
#include "inet/routing/ant2/Ant2EnergyCheck.h"
#include "inet/routing/ant2/Ant2PositionCheck.h"
#include "inet/routing/ant2/Ant2AvailabilityCheck.h"
#include "inet/routing/ant2/Ant2HelpCheck.h"
#include "inet/routing/ant2/Ant2BandCheck.h"
#include "inet/routing/ant2/ChargingStationEpEnergyGenerator.h"

// Added to save dictionaries
#include <unordered_map>
#include <utility>


// Added to get coordiates of a UAV
#include "inet/mobility/contract/IMobility.h"
#include "inet/mobility/single/LinearMobility.h"

// Added to monitor the messages in network layer
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/common/ModuleRefByPar.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/contract/IL3AddressType.h"
#include "inet/networklayer/contract/INetfilter.h"
#include "inet/networklayer/contract/IRoutingTable.h"
#include "inet/routing/base/RoutingProtocolBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"


namespace inet {
namespace ant2 {

/**
 * ANT protocol implementation.
 */
class INET_API Ant2 : public RoutingProtocolBase, public cListener, public NetfilterBase::HookBase
{
  private:
    struct ForwardEntry {
        cMessage *event = nullptr;
        Packet *hello = nullptr;

        ForwardEntry() {}
        ~ForwardEntry();
    };

    struct RoutingTableEntry {
        std::string destinationAddress;
        std::string nextHop;
        double pheromone;
    };

    struct RoutingTableAntEntry {
        std::string destinationAddress;
        std::string gateway;
        unsigned int sequenceNumber;
    };

    struct StatusEntry {
        std::string destinationAddress;
        double energy;
        double throughput;
        double distance;
        double hops;
        double max_throughput;
        int cluster_id;
        bool allowed_accept_request;
        // Correzioni sull'energia: timbro di misura dichiarato nell'ultimo
        // BANT (istante in cui il mittente ha letto energia e posizione).
        // Vale -1 con legacyEnergy = true (BANT senza timbro).
        double measure_time = -1;
    };

    cMessage *event = nullptr;
    cPar *broadcastDelay = nullptr;
    std::list<ForwardEntry *> *forwardList = nullptr;
    std::vector<RoutingTableEntry> routingTable;
    std::vector<StatusEntry> statusTable;

    // Added for node status monitoring
    std::vector<RoutingTableAntEntry> routingTableAnt;

    // Added to store the reference to the physical interface
    NetworkInterface *interface80211ptr = nullptr;
    int interfaceId = -1;

    // Added to store sequence numbers
    unsigned int sequencenumber = 0;
    unsigned int sequencenumber_bant = 0;

    // Added to store the life time of each entry in routing table
    simtime_t routeLifetime;
    cModule *host = nullptr;

    // Added to store the physical interface connected to access the 5G CN
    Ipv4Address x2ppp_address =  Ipv4Address::UNSPECIFIED_ADDRESS;

    // Added for energy measurement
    inet::power::SimpleEpEnergyManagement *energyManagement;
    double nominalCapacity;

    // ---- Correzioni sull'energia (vedi Ant2Energy.h) ----
    bool legacyEnergy = false;          // true = comportamento originale
    double batteryCapacityJ = 0;        // capacita' reale letta da energyStorage
    ant2energy::ChargingLogic chargingLogic{15, 100};
    power::ChargingStationEpEnergyGenerator *chargingGenerator = nullptr; // nullptr = nessuna ricarica
    Coord chargingStation;              // posizione della stazione di ricarica
    Coord preChargePosition;            // posizione prima di andare a ricaricarsi
    bool preChargeAccept = false;       // disponibilita' prima della ricarica
    bool preChargeSend = false;         // permesso di chiedere aiuto prima della ricarica
    simtime_t node_measure_time = -1;   // timbro di misura dell'ultima lettura
    long ricaricheIniziate = 0, ricaricheCompletate = 0;

    // Legge l'energia residua e la converte in percentuale (legacy o corretta).
    double readChargePercent(double& residualJ);
    // Avviso di batteria scarica: REQ broadcast con mittente = destinatario.
    void sendLowEnergyNotice(double chargePercent);
    // ---- Regola 1: controllo sull'energia dichiarata nei BANT ----
    struct EnergyObserved {
        ant2energy::EnergyObservedState st;   // ultima misura e riferimento
        ant2energy::EnergyCheckParams p;      // parametri del drone osservato
        bool risolto = false;                 // parametri gia' cercati
        bool valido = false;                  // drone osservato (adh) con parametri letti
        std::string nome;                     // es. "adh[7]"
        long superati = 0, violati = 0, nonApplicabili = 0;
    };
    std::map<uint32_t, EnergyObserved> energyObserved;  // chiave: indirizzo del mittente (firmato)

    // --- Regola 2 della metrica di trust: posizione (Ant2PositionCheck.h) ---
    struct PositionObserved {
        ant2position::PositionObservedState st;  // ultima misura e stato della stazione
        bool risolto = false;
        bool valido = false;
        std::string nome;                        // es. "adh[7]"
        long superati = 0, violati = 0, dubbi = 0, nonApplicabili = 0;
    };
    std::map<uint32_t, PositionObserved> positionObserved;
    // Registro degli eventi osservati: i REQ che questo nodo ha ricevuto, da
    // cui si capisce quali spostamenti sono giustificati.
    std::vector<ant2position::MoveEvent> moveEvents;
    ant2position::PositionCheckParams positionParams;
    bool positionCheckEnabled = true;
    bool positionCheckLogAll = false;
    double positionEventMaxAge = 30;   // s: oltre questa eta' un evento viene scartato
    long positionCheckSuperati = 0, positionCheckViolati = 0, positionCheckDubbi = 0;
    long moveEventsReclutamento = 0, moveEventsAvviso = 0;
    // Spostamento di reclutamento: gli stessi valori che usa moveUav(), letti
    // dai parametri cosi' controllo e spostamento restano coerenti.
    double recruitOffset = 100, recruitRadius = 100, recruitAltitude = 50, recruitMoveDelay = 1;
    // istanteReale: quando il REQ e' stato EMESSO. Vale -1 per un REQ osservato
    // di persona, dove l'istante e' adesso. Per un REQ riferito dalla GCS nel
    // bollettino va passato quello vero, altrimenti la scadenza della regola 4
    // viene calcolata dall'istante in cui e' arrivato il bollettino, che puo'
    // essere decine di secondi dopo i fatti.
    void noteMoveEvent(const Ipv4Address& mittente, const Ipv4Address& destinatario,
                       const Coord& posRichiedente, unsigned int seq,
                       double istanteReale = -1, bool daGcs = false);
    void checkPositionRule(const Ipv4Address& src, const Coord& pos, double timbro, double energia,
                           const char *fonte = "BANT");
    // Attacchi per provare la regola 2.
    // attackWrongRecruitMove: il drone accetta il reclutamento ma si sposta
    //   nella direzione opposta a quella prevista (distanza plausibile,
    //   direzione sbagliata): e' il caso che l'intervallo di distanza non
    //   coglierebbe e la sfera invece coglie.
    // attackFakePosition: dal secondo attackFakePositionStart il drone dichiara
    //   la propria posizione spostata di attackFakePositionOffset su x.
    bool attackWrongRecruitMove = false;
    // attackFakePositionOnlyBant: la posizione falsa viene dichiarata solo nei
    //   BANT, che sono quelli che decidono il reclutamento, mentre nelle voci
    //   di traccia il drone dichiara quella vera. E' un attaccante che non sa
    //   che le GCS raccolgono anche le tracce, e lo coglie il controllo sulla
    //   coerenza della posizione a parita' di timbro.
    bool attackFakePosition = false;
    bool attackFakePositionOnlyBant = false;
    double attackFakePositionOffset = 300;
    double attackFakePositionStart = 40;
    Coord posizioneDichiarata(bool perBant = true) const;
    void resolvePositionObserved(const Ipv4Address& src, PositionObserved& o);
    // Istante del piu' recente bollettino dei REQ ricevuto dalla GCS, -1 se
    // nessuno. Un dubbio sulla posizione diventa violazione certa solo quando
    // esiste un bollettino emesso dopo lo spostamento che non lo giustifica.
    double ultimoBollettinoReq = -1;
    // Istante del REQ piu' vecchio contenuto nell'ultima sezione ricevuta: il
    // bollettino ha un tetto alle righe, quindi i REQ anteriori possono essere
    // stati tagliati e un dubbio piu' vecchio di questo istante non si condanna.
    // Vuol dire "copre tutto" quando la sezione era vuota.
    double bollettinoReqCopreDa = -1e300;
    long positionDubbiSciolti = 0, positionDubbiCondannati = 0;
    void preparaPositionParams();
    void applicaEsitoPosizione(const Ipv4Address& src, PositionObserved& o,
                               const ant2position::PositionOutcome& esito);
    // Ripassa i dubbi sospesi di tutti i droni osservati: va chiamata dopo ogni
    // arrivo di REQ, osservato di persona o pubblicato dalla GCS.
    void risolviDubbiPosizioneTutti();
    void positionCheckFinish();
    static std::ofstream& positionCheckLogFile();

    // --- Regola 3 della metrica di trust: disponibilita' (Ant2AvailabilityCheck.h) ---
    struct AvailabilityObserved {
        ant2availability::AvailabilityObservedState st;
        bool risolto = false;
        bool valido = false;
        std::string nome;
        long superati = 0, violati = 0, dubbi = 0, nonApplicabili = 0;
    };
    std::map<uint32_t, AvailabilityObserved> availabilityObserved;
    bool availabilityCheckEnabled = true;
    bool availabilityCheckLogAll = false;
    long availabilityCheckSuperati = 0, availabilityCheckViolati = 0, availabilityCheckDubbi = 0;
    // attackFalseAvailability: il drone dichiara sempre disponibilita' vera,
    // anche dopo essere stato reclutato, cosi' partecipa a tutti i reclutamenti.
    bool attackFalseAvailability = false;
    void checkAvailabilityRule(const Ipv4Address& src, bool disponibile, double timbro);
    void availabilityStato(const Ipv4Address& src, ant2availability::Mossa mossa, double timbro);
    void availabilityCheckFinish();
    static std::ofstream& availabilityCheckLogFile();

    // --- Regola 4 della metrica di trust: falso aiuto (Ant2HelpCheck.h) ---
    struct HelpObserved {
        bool risolto = false;
        bool valido = false;
        std::string nome;
        long superati = 0, violati = 0, dubbi = 0, nonApplicabili = 0;
    };
    std::map<uint32_t, HelpObserved> helpObserved;
    // Verifiche aperte: un reclutamento annotato attende il primo BANT del
    // vincitore con timbro oltre l'istante limite.
    std::vector<ant2help::Pending> helpPending;
    ant2help::HelpCheckParams helpParams;
    bool helpCheckEnabled = true;
    bool helpCheckLogAll = false;
    long helpCheckSuperati = 0, helpCheckViolati = 0, helpCheckDubbi = 0, helpCheckAbbandonate = 0;
    // attackFalseHelp: il drone accetta il reclutamento, quindi si dichiara non
    //   disponibile, ma non si sposta: chi ha chiesto aiuto resta senza aiuto.
    // attackIgnoreRecruit: il drone ignora del tutto i REQ a lui destinati, non
    //   accetta, non cambia disponibilita' e non si sposta.
    bool attackFalseHelp = false;
    bool attackIgnoreRecruit = false;
    // Istante da cui attackFalseMetrics comincia a mentire: prima di quello il
    // drone dichiara i valori veri. Serve a provare i controlli che confrontano
    // una dichiarazione con quelle precedenti.
    double attackStart = 0;
    void checkHelpRule(const Ipv4Address& src, bool disponibile, const Coord& pos, double timbro);
    void helpResolveNome(const Ipv4Address& src, HelpObserved& o);
    void helpCheckFinish();
    static std::ofstream& helpCheckLogFile();

    // --- Regola 5 della metrica di trust: banda massima (Ant2BandCheck.h) ---
    struct BandObserved {
        ant2band::BandObservedState st;
        bool risolto = false;
        bool valido = false;
        std::string nome;
        long superati = 0, violati = 0, nonApplicabili = 0;
    };
    std::map<uint32_t, BandObserved> bandObserved;
    ant2band::BandCheckParams bandParams;
    bool bandCheckEnabled = true;
    bool bandCheckLogAll = false;
    long bandCheckSuperati = 0, bandCheckViolati = 0;
    // Soglia di energia sotto la quale il drone chiede aiuto comunque: la legge
    // sia il controllo periodico che decide di chiedere aiuto sia il controllo 2
    // di questa regola, cosi' i due non possono divergere.
    double helpRequestEnergyThreshold = 15;
    void checkBandRule(const Ipv4Address& src, double maxBand, double throughput,
                       double energia, double timbro);
    void bandCheckFinish();
    static std::ofstream& bandCheckLogFile();

    // --- Regola 6 della metrica di trust: hop dichiarati (Ant2HopCheck.h) ---
    // Due controlli. Il primo e' locale e certo: chi trasmette un messaggio
    // creato da un altro deve dichiarare almeno 2 hop, chi trasmette un
    // messaggio suo deve dichiararne 1. Il secondo lo fa la sola GCS sulla
    // catena delle voci di traccia, dove la voce in posizione i deve riportare
    // i+1: la rottura e' certa, la colpa si attribuisce per accumulo.
    // Conta piu' di quanto sembri perche' gli hop dichiarati entrano nel
    // feromone dell'instradamento come 100/hop: dichiararne meno del vero
    // significa diventare il prossimo salto preferito, cioe' un sinkhole.
    struct HopObserved {
        ant2hop::HopObservedState st;
        bool valido = false;
        std::string nome;
    };
    // La chiave e' il NOME del nodo, non un indirizzo: ogni nodo ne ha piu'
    // d'uno (l'interfaccia radio e quella X2), e confrontare indirizzi invece
    // di nodi faceva sembrare un inoltro ogni messaggio che un nodo trasmetteva
    // da un'interfaccia diversa da quella scritta nel campo firmato.
    std::map<std::string, HopObserved> hopObserved;
    ant2hop::HopCheckParams hopParams;
    bool hopCheckEnabled = true;
    // Traccia anche i nodi degli altri cluster: le catene diventano lunghe e il
    // controllo sulla catena degli hop ha materiale su cui lavorare.
    bool traceAllClusters = false;
    bool hopCheckLogAll = false;
    long hopCheckSuperati = 0, hopCheckViolati = 0, hopCheckDubbi = 0;
    long hopCoppieSospette = 0;
    std::set<std::string> hopVisti;   // per non contare due volte lo stesso messaggio
    void checkHopRule(Packet *packet, const Ptr<const Chunk>& contenuto);
    void checkCatenaTraccia(const std::vector<ant2trace::EntryData>& voci);
    void applicaEsitiHop(HopObserved& o, const std::vector<ant2hop::HopOutcome>& esiti);
    void hopCheckFinish();
    static std::ofstream& hopCheckLogFile();

    // --- Regola 0 della metrica di trust: coerenza fra canali (Ant2DigestCheck.h) ---
    // Confronta l'impronta delle letture che questo nodo ha ricevuto con quella
    // delle stesse letture arrivate alla GCS, che le pubblica nel bollettino.
    // E' l'unica regola che coglie l'equivocazione, cioe' il drone che dichiara
    // una cosa ai vicini e un'altra alla GCS.
    struct DigestObserved {
        ant2digest::DigestObservedState st;
        bool valido = false;
        std::string nome;
    };
    std::map<uint32_t, DigestObserved> digestObserved;
    ant2digest::DigestCheckParams digestParams;
    bool digestCheckEnabled = true;
    bool digestCheckLogAll = false;
    long digestCheckSuperati = 0, digestCheckViolati = 0, digestCheckNonApplicabili = 0;
    long digestCheckViolatiLocali = 0;
    // Esiti delle regole 1-5 annullati perche' derivavano da letture falsificate
    long digestAnnullatiSuperati = 0, digestAnnullatiViolati = 0, digestAnnullatiDubbi = 0;
    // Impronta delle letture che questo nodo ha ricevuto, calcolata sui soli
    // campi legati alla lettura (vedi la nota in Ant2DigestCheck.h).
    static uint64_t improntaLettura(uint32_t nodo, double timbro, double throughput,
                                    double energia, const Coord& pos, double maxBand);
    void digestNotaMisura(const Ipv4Address& src, double timbro, double throughput,
                          double energia, const Coord& pos, double maxBand,
                          ant2digest::Fonte fonte);
    // Totali delle cinque regole prima/dopo, per attribuire gli esiti alla
    // lettura su cui sono stati prodotti e poterli annullare se risulta falsa.
    struct TotaliRegole { long superati = 0, violati = 0, dubbi = 0; };
    TotaliRegole totaliRegole() const;
    void digestAttribuisciEsiti(const Ipv4Address& src, double timbro, const TotaliRegole& prima);
    void digestApplicaEsiti(const Ipv4Address& src, DigestObserved& o,
                            const std::vector<ant2digest::DigestOutcome>& esiti);
    void digestResolveNome(const Ipv4Address& src, DigestObserved& o);
    void digestCheckFinish();
    static std::ofstream& digestCheckLogFile();

    // --- Bollettino pubblicato dalla GCS nel proprio cluster ---
    bool digestPublish = false;          // true solo per le GCS
    int digestEveryRounds = 1;           // pubblica ogni N giri di traccia
    int digestMeasuresPerNode = 3;       // letture per nodo in ogni bollettino
    int digestCopies = 2;                // copie di ogni invio
    // Tetto alle righe di un bollettino: oltre l'MTU il pacchetto viene
    // frammentato da IP e basta perdere un frammento per perdere tutto.
    int digestMaxRows = 24;              // tetto complessivo nel bollettino completo
    size_t digestRowOffset = 0;          // rotazione della finestra di righe
    // Bollettino a due velocita': a ogni giro tutte le letture dei nodi del
    // proprio cluster, ogni digestFullEveryRounds giri anche quelle degli altri.
    bool digestClusterFirst = true;      // spento: tutte le righe a rotazione, come prima
    // Unicast ai vicini del cluster: il livello MAC riscontra e ritrasmette, il
    // broadcast no. Resta una copia in broadcast per chi non e' vicino diretto.
    bool digestUnicast = true;
    long digestUnicastSent = 0;
    int digestMaxRowsCluster = 18;       // tetto alle righe del proprio cluster
    int digestFullEveryRounds = 5;       // ogni quanti giri esce il bollettino completo
    size_t digestRowOffsetCluster = 0;   // rotazione, se il cluster sfonda il tetto
    long digestRowsCluster = 0, digestRowsAltrui = 0, digestFullSent = 0;
    int clusterDiNodo(uint32_t nodo) const;
    bool digestIncludeReq = true;        // includi il registro dei REQ
    // Inoltro: un drone fuori portata radio dalla GCS non riceverebbe mai il
    // bollettino, quindi ogni nodo lo ritrasmette una volta sola. Si puo'
    // spegnere per misurare quanta copertura si perde e quanto traffico si
    // risparmia sul canale del cluster, che e' quello congestionato.
    bool digestRelay = true;
    std::set<std::string> digestSeen;
    long digestRelayed = 0;
    uint32_t digestCounter = 0;
    std::map<uint32_t, unsigned int> digestLastSeen;   // ultimo contatore per GCS di origine
    long digestSent = 0, digestReceived = 0, digestRejected = 0, digestGaps = 0;
    long digestRowsSent = 0, digestReqRowsSent = 0;
    // Letture raccolte dalla GCS, da pubblicare: per nodo, le ultime N
    struct LetturaNota {
        double timbro = -1;
        uint64_t impronta = 0;
        ant2digest::Fonte fonte = ant2digest::Fonte::IGNOTA;
    };
    std::map<uint32_t, std::vector<LetturaNota>> digestLetture;
    std::vector<ant2digest::wire::RecordReq> digestReqNoti;
    // Letture per cui la GCS ha ricevuto due dichiarazioni discordi: sono la
    // prova dell'equivocazione, escono per prime in ogni bollettino e non
    // entrano nella rotazione, perche' le due righe devono viaggiare insieme.
    std::vector<ant2digest::wire::RecordImpronta> digestContese;
    void digestRaccogliLettura(uint32_t nodo, double timbro, uint64_t impronta,
                               ant2digest::Fonte fonte);
    void digestRaccogliReq(const Ipv4Address& mittente, const Ipv4Address& destinatario,
                           const Coord& posRichiedente, unsigned int seq);
    // --- Punizione: effetto della metrica di trust sul reclutamento ---
    // Oggi, di default, SPENTA. Tutti i risultati raccolti finora sono stati
    // ottenuti con i controlli che osservano e basta, e l'interruttore serve a
    // poter misurare la rete con e senza punizione a parita' di tutto il resto.
    // La forma definitiva del quinto termine del punteggio e' ancora da
    // decidere; questa e' la forma piu' semplice difendibile: un drone su cui
    // questo nodo ha osservato almeno una violazione CERTA non entra fra i
    // candidati al reclutamento. I dubbi non puniscono, perche' hanno sempre una
    // spiegazione innocente possibile.
    bool trustPunishEnabled = false;
    long violazioniCerte(uint32_t nodo) const;
    long reclutamentiNegati = 0;
    void sendDigestBulletin();
    void sendDigestAlert();                     // bollettino minuscolo con le sole contese
    void digestSpedisci(const std::vector<uint8_t>& pt, int copie);
    long digestAlerts = 0;
    int digestMaxReqRows = 4;                   // tetto alle righe di REQ per bollettino
    void sendDigestPacket(const Ptr<DigestM2>& d, int copie, int ifaceId = -1);
    void handleDigest(Packet *packet);

    bool energyCheckEnabled = true;
    bool energyCheckUseInitial = false;   // true per la GCS: confronto con l'energia iniziale
    bool energyCheckLogAll = false;       // true: registra anche i controlli superati
    double energyCheckWindow = 30;        // finestra W (s)
    double maxNetworkDelay = 1;           // ritardo massimo di rete D (s)
    double measureMaxInterval = 3;        // intervallo massimo tra due misure (s)
    double energyCheckTolerance = 0.01;   // tolleranza (punti percentuali)
    // Calo minimo ricavato dal traffico di protocollo (vedi Ant2EnergyCheck.h).
    double energyMinTrafficMargin = 0.5; // coefficiente di prudenza k (0 = solo ascolto)
    double energyTraceMaxAge = 3.5;      // eta' massima del timbro in una voce di traccia (s)
    double fantFrameBytes = 80;          // dimensione reale dell'ultimo FANT visto (byte)
    double bantFrameBytes = 161;         // dimensione reale dell'ultimo BANT visto (byte)
    int knownNodeCount() const;          // nodi della rete noti a chi controlla
    long energyCheckSuperati = 0, energyCheckViolati = 0;
    // misure esaminate, divise per messaggio di provenienza
    long energyCheckDaBant = 0, energyCheckDaTracce = 0;
    // fonte: "BANT" oppure "una voce di traccia"; arrival e maxAge negativi
    // significano "istante attuale" ed "eta' massima dei BANT".
    // diretto: true se il messaggio arriva dal nodo che lo ha firmato, false se
    // e' stato inoltrato da un terzo. Su un messaggio inoltrato l'eta' del
    // timbro misura il ritardo delle code della rete e non la vecchiaia della
    // lettura, quindi quel solo controllo non si applica.
    void checkEnergyRule(const Ipv4Address& src, double energy, const Coord& pos, double timbro,
                         const char *fonte = "BANT", double arrival = -1, double maxAge = -1,
                         bool diretto = true);
    // Vero se il messaggio in lavorazione e' stato messo sul canale dallo stesso
    // nodo che lo ha firmato. Calcolato una volta allo smistamento.
    bool msgDiretto = false;
    bool messaggioDalCreatore(Packet *pacchetto, const Ptr<const Chunk>& contenuto) const;
    void resolveEnergyObserved(const Ipv4Address& src, EnergyObserved& o);
    static std::ofstream& energyCheckLogFile();

    // Gestione della ricarica (solo con legacyEnergy = false).
    // acceptBefore/sendBefore: disponibilita' e permesso di chiedere aiuto
    // prima della misura, ripristinati al ritorno dalla ricarica.
    void manageCharging(bool acceptBefore, bool sendBefore);
    // Partenza ritardata verso la stazione: l'avviso parte dalla posizione
    // del drone e lo spostamento avviene chargeDepartureDelay secondi dopo.
    cMessage *chargeDepartTimer = nullptr;
    double chargeDepartureDelay = 1;      // s
    void departToChargingStation();

    // ---- Registrazione traffico/consumo (solo misura, parametro trafficEnergyLog) ----
    // Per ogni misura: energia realmente consumata (dalla batteria di INET),
    // frame e byte trasmessi e ricevuti dalla radio, tempo passato dalla radio
    // in trasmissione, ricezione e canale occupato. Serve a stimare quanto il
    // consumo si possa ricostruire dal traffico; il protocollo non usa questi dati.
    bool trafficEnergyLogEnabled = false;
    struct RadioTrack {
        cModule *radio = nullptr;
        int txState = -1, rxState = -1;   // ultimo stato di trasmissione/ricezione
        simtime_t last = 0;               // istante dell'ultimo cambio di stato
    };
    std::vector<RadioTrack> radioTracks;
    double te_Ttx = 0, te_Trx = 0, te_Tbusy = 0;          // s nell'intervallo
    long te_txFrames = 0, te_rxFrames = 0;
    double te_txBytes = 0, te_rxBytes = 0;
    double te_prevJ = -1;
    simtime_t te_prevT = -1;
    bool te_prevCharging = false;
    void trafficEnergyInit();
    void trafficEnergyAccumulate(RadioTrack& r);
    void trafficEnergyRecord(double residualJ);
    static std::ofstream& trafficEnergyLogFile();
  public:
    using cListener::receiveSignal;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, intval_t value, cObject *details) override;
    virtual void receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details) override;
  private:

    // Added for Ant tacking packet and loop avoidance
    // It record the received packets
    std::unordered_map<std::string, std::set<unsigned int>> receivedPackets;

    // Ant pheromone update
    cMessage *pheromoneUpdateTimer = nullptr;

    // Added to get current coordinates of the UAV
    opp_component_ptr<IMobility> mobility;
    cMessage *throughputUpdateTimer = nullptr;

    // Added to track data rate of lower layers
    cModule *li = nullptr;
    cModule *ipv4_module = nullptr;
    cModule *arp = nullptr;
    double old_data_amount = 0.0;
    double new_data_amount = 0.0;
    simtime_t old_time;
    simtime_t new_time;

    // Added for recruiting logic
    bool allowed_accept_request;
    bool allowed_send_request;

    // Added for bandwidth
    double max_band;


    // Added for test (delete)
    int condition = 0;

    // Add to save statistics
    simsignal_t arrivalSignal;
    simsignal_t arrivalSignal1;
    simsignal_t arrivalSignal2;
    int total_manet_packets = 0;
    int total_req_packets = 0;

    simsignal_t arrivalSignal3;
    std::string coordenates_to_be_recruited;

    // Aggiunto per il livello di sicurezza (Ascon-AEAD128 + Ed25519).
    // Un'unica istanza per nodo, caricata una volta in initialize().
    Ant2Crypto crypto;

    // Costruisce un BANT gia' cifrato e firmato, pronto per essere inviato.
    // Centralizza qui la logica di sicurezza cosi' non va ripetuta nei
    // (due) punti del codice in cui oggi viene creato un BantM2.
    Packet *buildSecureBant(Ipv4Address dstAddress, Ipv4Address gateway,
                             unsigned int seq, Ipv4Address source);

    // Verifica firma + decifra un BANT ricevuto. Ritorna false se il pacchetto
    // va scartato (firma non valida, mittente sconosciuto, o tag AEAD non valido).
    // Se ritorna true, i parametri di output contengono i dati in chiaro.
    // NOTA: "hops" non e' tra i valori decifrati: e' un dato che deve poter
    // essere aggiornato ad ogni hop (come hopdistance), quindi va preso dal
    // campo in chiaro hopdistance, non da dentro il payload cifrato.
    bool verifyAndDecryptBant(const Ptr<const BantM2>& recHello,
                               double& energyOut, double& throughputOut,
                               Coord& positionOut,
                               double& maxThroughputOut, int& clusterIdOut,
                               bool& allowedAcceptOut, double& measureTimeOut);

    // Stesso schema di buildSecureBant/verifyAndDecryptBant, applicato al REQ:
    // qui i dati sensibili sono coordinate (posizione del drone in difficolta')
    // e allowed_accept_request.
    Packet *buildSecureReq(Ipv4Address dstAddress, unsigned int seq, Ipv4Address source,
                            const Coord& coordToSend, bool allowedAccept);

    bool verifyAndDecryptReq(const Ptr<const ReqM2>& recHello,
                              Coord& coordOut, bool& allowedAcceptOut, int *clusterOut = nullptr);
    int lastReqCluster = -1;   // cluster dichiarato nell'ultimo REQ ricevuto (snapshot per cluster)

    // FANT: non trasporta dati sensibili (e' solo scoperta di rotta), quindi
    // non viene cifrato: basta la firma Ed25519 su srcAddress||dstAddress||
    // sequencenumber, che impedisce a un nodo non autorizzato di iniettarlo.
    // I campi hopdistance/hopAddresses[] restano fuori dalla firma perche'
    // cambiano ad ogni hop (limite noto, gia' documentato nel design).
    void signFant(const Ptr<FantM2>& fant);
    bool verifyFant(const Ptr<const FantM2>& fant);

    // Descrizione testuale della configurazione di sicurezza in uso, es.
    // "AES-256-GCM (confidenzialita' + integrita') + Ed25519 (autenticazione)".
    // E' STATICA perche' serve anche a securityEventLog(), che e' una funzione
    // statica; viene valorizzata una sola volta dal primo nodo che si avvia, e
    // tutti i nodi della rete usano per forza la stessa configurazione (lo
    // garantisce Ant2KeyAuthority, che rifiuta lunghezze di chiave incoerenti).
    static std::string secDescrizione;
    static const std::string& descrizioneSicurezza();

    // Etichetta breve, adatta a un nome di file, della configurazione di
    // sicurezza: "ascon128", "aes256gcm", "nosec", ... Viene inserita nei nomi
    // dei file di riepilogo, cosi' che una campagna con piu' algoritmi produca
    // file distinguibili a colpo d'occhio senza dover risalire al numero di run.
    static std::string secTagFile;

    // Logging del livello di sicurezza: il DETTAGLIO completo va sempre su file
    // (ant2_security_events.log), mentre la console riceve solo l'essenziale,
    // a meno che consoleVerbose non sia attivo.
    static std::ofstream& securityEventLog();

    // Compone un nome di file che include l'identificativo della run, cosi' che
    // esecuzioni successive (ripetizioni, valori diversi dei parametri) non si
    // sovrascrivano a vicenda. Es. "ant2_security_totals_r3.txt".
    static std::string nomeFileRun(const char *base, const char *estensione);
    void logScarto(const char *tipo, Ipv4Address mittente, const char *motivo, long n);
    void logAccettato(const char *tipo, Ipv4Address mittente, long n);
    bool consoleVerbose = false;

    // Se false, il livello di sicurezza e' completamente disattivato: nessuna
    // firma, nessuna cifratura, messaggi delle dimensioni originali. Usato per
    // ottenere il baseline nelle misure di overhead.
    bool securityEnabled = true;

  protected:
    simtime_t helloInterval;
    ModuleRefByPar<IInterfaceTable> ift;
    ModuleRefByPar<IIpv4RoutingTable> rt;

    /////////////////// added for Ant ///////////////////////////


    // Ant-related variables
    std::map<Ipv4Address, std::map<Ipv4Address, double >> pheromoneTable;
    double alpha;  // Influence of pheromone
    double betaa;   // Influence of heuristic
    double pheromoneDecayRate;  // Rate at which pheromone evaporates

    // Other Ant-specific variables
    double initialPheromoneValue;  // Initial pheromone value for a new route
    double pheromoneIncrement;     // Increment for pheromone after successful route discovery

    // Added for pheromone updae
    simtime_t update_pheromone_Interval;
    void updatePheromoneValues();
    void computeBestNextHops();

    // Added for throughput monitoring
    simtime_t update_throughput_Interval;
    void updateThroughput();

    // Added to update coordinates
    void updateCoordenates();

    // Added to update energy
    void updateEnergy();

    // Added to save coordinates, throughput, energy level
    Coord node_position;
    double node_throughput;
    double node_energy;

    // Added to remove low entries (pheromone values) in routing table
    void removeLowPheromoneEntries();

    // Added to calculate distance from node to neighbors
    double calculateEuclideanDistance(const Coord& coord1, const Coord& coord2);

    // Added to monitor network layer
    ModuleRefByPar<INetfilter> networkProtocol;

    // Added to send recruiting requests and move the UAV
    void handlePheromone(std::string src, std::string gw);
    void sendRecruiting();
    void moveUav();
    void moveUav_charge();
    cMessage *moveTimer = nullptr;

    // Added to store the name of each UAV
    int name;

    // Added to store the cluster_id of each UAV
    int cluster_id;

    // Added to support two wireless interfaces
    int num_80211 = 0;
    std::vector<NetworkInterface*> wirelessInterfaces;

    // Added roadcast addess
    Ipv4Address broadcast_addr =  Ipv4Address(255,255,255,255);
    bool allow_ip_recruit;
    //////////////////////////////////////////////////////////////////

  public:
    Ant2();
    virtual ~Ant2();
    Ipv4Route *lookupRoute(const std::string &destination);

    // Added to monitor the Ipv4 module
    virtual void initialize(int stage) override;

    virtual void handleMessageWhenUp(cMessage *msg) override;

    /* Netfilter hooks */
    // Used to support the layer monitoring
    Result ensureRouteForDatagram(Packet *datagram);
    virtual Result datagramPreRoutingHook(Packet *datagram) override { Enter_Method("datagramPreRoutingHook"); return ensureRouteForDatagram(datagram); }
    virtual Result datagramForwardHook(Packet *datagram) override;
    virtual Result datagramPostRoutingHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalInHook(Packet *datagram) override { return ACCEPT; }
    virtual Result datagramLocalOutHook(Packet *datagram) override { Enter_Method("datagramLocalOutHook"); return ensureRouteForDatagram(datagram); }

  protected:

    // Contatori del livello di sicurezza. Stampati in finish() con std::cout
    // (non con EV_*) di proposito: le stampe EV_* NON compaiono quando Cmdenv
    // gira in "express mode", mentre std::cout e' sempre visibile.
    long sec_bant_ok = 0;
    long sec_bant_fail = 0;
    long sec_req_ok = 0;
    long sec_req_fail = 0;
    long sec_fant_ok = 0;
    long sec_fant_fail = 0;

    // Contatori per MOTIVO dello scarto: utile per capire a colpo d'occhio
    // che tipo di attacco/anomalia si sta osservando.
    long sec_fail_unknown = 0;    // mittente non presente nel registro delle identita'
    long sec_fail_signature = 0;  // identita' nota, ma firma Ed25519 non valida
    long sec_fail_aead = 0;       // firma valida, ma payload manomesso (tag Ascon errato)

    // Contatori del traffico di CONTROLLO effettivamente immesso sul canale da
    // questo nodo: sia i messaggi che origina, sia quelli che si limita a
    // inoltrare. A differenza di MOS/ritardo, questa misura e' deterministica
    // e non dipende dalla traiettoria casuale della simulazione: e' la
    // quantificazione diretta dell'overhead introdotto dalla sicurezza.
    long ctrl_fant_pkt = 0,  ctrl_bant_pkt = 0,  ctrl_req_pkt = 0;
    long ctrl_fant_byte = 0, ctrl_bant_byte = 0, ctrl_req_byte = 0;

    // --- Attacchi interni (solo per i test): un nodo legittimo, con chiavi
    // valide, che dichiara dati falsi. Non rilevabili dalla crittografia.
    bool attackFalseMetrics = false;   // mente su energia/banda nel payload cifrato
    bool attackHopDistance = false;    // non incrementa hopdistance inoltrando

    // Esito delle selezioni di recruiting effettuate da questo nodo: serve a
    // misurare se l'attaccante viene scelto in modo sproporzionato.
    long recruiting_totali = 0;

    // Registra un messaggio di controllo trasmesso. 'tipo' e' FANT/BANT/REQ/TRACE.
    void contaTrafficoControllo(const char *tipo, int byte);
    long ctrl_trace_pkt = 0, ctrl_trace_byte = 0;

    // --- TRACEROUTE DELLE GCS (snapshot della rete, vedi Ant2Trace.h) ---
    // Parametri
    bool traceEnabled = false;          // true solo per le GCS: lanciano le tracce
    double traceStartTime = 3;          // s, primo giro di tracce
    double traceIntervalMin = 1;        // s, intervallo casuale tra due giri
    double traceIntervalMax = 5;
    double traceTimeout = 2;            // s, attesa delle risposte di un giro
    double traceStagger = 0.02;         // s, distanza tra due tracce dello stesso giro
    double traceRetryDelay = 1;         // s, attesa prima del secondo tentativo
    double traceUnicastMaxDistance = 2000;  // m, oltre si trasmette in broadcast (ACK troppo lento)
    int traceBroadcastCopies = 2;       // copie di ogni passaggio trasmesso in broadcast
    long traceHopUnicast = 0, traceHopBroadcast = 0;
    // Istante in cui il nodo ha sentito per l'ultima volta ogni vicino
    std::map<uint32_t, double> traceNeighborSeen;
    double traceNeighborTimeout = 10;   // s, vicini riportati nelle voci
    // Snapshot per cluster scambiati tra le GCS
    bool snapshotRelay = false;         // GCS e satellite: inoltrano gli snapshot
    int snapshotCopies = 2;             // copie di ogni invio di snapshot
    uint32_t snapshotCounter = 0;
    std::set<std::string> snapSeen;
    struct RemoteSnap { int cluster = 0; unsigned int giro = 0; double istante = 0, ricevuto = 0; std::vector<ant2trace::SnapRecord> record; };
    std::map<uint32_t, RemoteSnap> remoteSnapshots;   // per GCS di origine
    long snapSent = 0, snapReceived = 0, snapRejected = 0;
    void sendClusterSnapshot();
    void sendSnapPacket(const Ptr<SnapM2>& s);
    void handleSnapshot(Packet *packet);
    void writeTopology();
    static std::ofstream& topologyLogFile();
    // Cambio di cluster con il reclutamento
    int clusterIdOriginale = 0;
    int pendingRecruitCluster = -1;
    double neighborDistance(const Ipv4Address& a) const;
    int traceMaxHops = 10;
    // Stato di ogni nodo
    uint32_t traceEntryCounter = 0;     // contatore delle voci aggiunte (nonce)
    std::set<std::string> traceSeen;    // tracce gia' elaborate (doppioni)
    // Stato della GCS
    cMessage *traceRoundTimer = nullptr;
    cMessage *traceCloseTimer = nullptr;
    cMessage *traceRetryTimer = nullptr;
    // Interfaccia su cui il nodo ha sentito per l'ultima volta ogni vicino
    // (indirizzo IP del vicino -> id dell'interfaccia locale): serve a
    // trasmettere la traccia in unicast sull'interfaccia giusta.
    std::map<uint32_t, int> traceNeighborIf;
    // Per ogni traccia inoltrata: da chi e' arrivata all'andata (indirizzo e
    // interfaccia), per rimandarla indietro allo stesso nodo al ritorno.
    struct TraceUpstream { Ipv4Address addr; int ifaceId = -1; double t = 0; };
    std::map<std::string, TraceUpstream> traceUpstream;
    unsigned int traceNextId = 0;
    int traceRound = 0;
    double traceRoundStart = 0;
    bool traceRoundOpen = false;
    struct TraceResult {
        uint32_t target = 0;
        double sent = 0, received = -1;  // invio e arrivo della risposta (s)
        bool risposta = false;           // risposta arrivata
        bool manomessa = false;          // firma o cifratura non verificata
        int voceManomessa = -1;
        uint8_t esito = 0;
        std::vector<ant2trace::EntryData> voci;
        std::string note;
        bool sostituita = false;         // senza risposta, sostituita dal secondo tentativo
        bool secondoTentativo = false;   // e' il secondo tentativo verso questo nodo
    };
    std::map<unsigned int, TraceResult> traceCurrent;          // giro in corso, per traceId
    std::map<uint32_t, ant2trace::EntryData> traceNodeInfo;    // ultimo dato noto per nodo
    long traceSent = 0, traceComplete = 0, traceNoRoute = 0, traceMissing = 0, traceTampered = 0, traceLate = 0;
    long traceRetried = 0, traceRetryOk = 0;

    void startTraceRound();
    void closeTraceRound(bool rischedula = true);
    unsigned int sendTraceTo(Ipv4Address target, double delay, bool secondoTentativo = false);
    void retryMissingTraces();
    void noteNeighborInterface(Packet *packet);
    void handleTrace(Packet *packet);
    void appendTraceEntry(const Ptr<TraceM2>& t, Ipv4Address prev);
    void sendTracePacket(const Ptr<TraceM2>& t, Ipv4Address receiver, double delay, int ifaceId = -1);
    void traceTurnAround(const Ptr<TraceM2>& t, uint8_t esito);
    void handleTraceResult(const Ptr<const TraceM2>& t);
    bool isOwnAddress(const Ipv4Address& a) const;
    Ipv4Address ownIdentity() const;
    static std::ofstream& snapshotLogFile();

    // --- DIARIO DELLO SCENARIO (vedi Ant2Scenario.cc) ---
    // Solo osservazione: nessuna di queste funzioni modifica lo stato del
    // protocollo, programma eventi o usa numeri casuali.
    bool scenarioLogEnabled = false;
    static std::ofstream& scenarioLogFile();
    static std::map<uint32_t, std::string>& scenRegistroNomi();
    std::string scenNome() const;
    static std::string scenNomeDi(const Ipv4Address& a);
    static std::string scenNomeDi(const std::string& ipTestuale);
    void scen(const char *evento, const std::string& testo);
    void scenAvvio();
    void scenFant(double chargeStatus, double residualJ);
    void scenBant(const std::string& srcIp, double energiaMittente, bool mittenteDisponibile);
    void scenAiuto(const std::vector<std::pair<std::string, double>>& candidati,
                   const std::string& scelto, double punteggio);
    void scenAiutoNonPossibile();
    void scenSos(double chargeStatus);
    void scenRichiestaRicevuta(const Ipv4Address& src, const Ipv4Address& dst, bool rivoltaAMe,
                               bool disponibile, const Coord& coordRichiedente);
    void scenSpostamento(const Coord& da, const Coord& a);
    void scenEnergia(double chargeStatus);
    void scenRicarica();
    void scenFineRicarica();
    void scenStop();
    void scenFine();
    // stato osservato, usato solo per il diario
    int scen_avvii = 0;
    long scen_fant_round = 0;
    simtime_t scen_first_fant = -1, scen_last_fant = -1;
    std::map<std::string, int> scen_bant_da;   // BANT ricevuti dal FANT precedente, per mittente
    long scen_bant_tot = 0;
    int scen_reclutato = 0, scen_rifiuti = 0, scen_richieste = 0, scen_sos = 0;
    std::set<uint32_t> scen_sos_visti;
    long scen_ricariche = 0;
    simtime_t scen_t_ricarica = -1, scen_t15 = -1;
    int scen_spegnimenti = 0;
    double scen_last_charge = -1, scen_min_charge = 1e9, scen_max_charge = -1e9;
    bool scen_sotto15 = false, scen_sotto10 = false, scen_risalita = false;
    bool scen_finito = false;

    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void finish() override;

    void handleSelfMessage(cMessage *msg);
    void handleStartOperation(LifecycleOperation *operation) override { start(); }
    void handleStopOperation(LifecycleOperation *operation) override { stop(); }
    void handleCrashOperation(LifecycleOperation *operation) override { stop(); }

    void start();
    void stop();
};

/**
 * IPv4 route used by the Ant protocol.
 */
class INET_API AntIpv4Route : public Ipv4Route
{
  protected:
    simtime_t expiryTime; // time the routing entry is valid until

  public:
    virtual bool isValid() const override { return expiryTime == 0 || expiryTime > simTime(); }

    simtime_t getExpiryTime() const { return expiryTime; }
    void setExpiryTime(simtime_t time) { expiryTime = time; }
};

} // namespace inet
}

#endif
