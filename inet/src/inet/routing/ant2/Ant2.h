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

#include <fstream>   // per il log su file del livello di sicurezza

// Aggiunto per il livello di sicurezza (Ascon-AEAD128 + Ed25519)
#include "inet/routing/ant2/Ant2Crypto.h"
#include "inet/routing/ant2/Ant2KeyAuthority.h"

// Added for energy monitoring
#include "inet/power/management/SimpleEpEnergyManagement.h"

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
                               bool& allowedAcceptOut);

    // Stesso schema di buildSecureBant/verifyAndDecryptBant, applicato al REQ:
    // qui i dati sensibili sono coordinate (posizione del drone in difficolta')
    // e allowed_accept_request.
    Packet *buildSecureReq(Ipv4Address dstAddress, unsigned int seq, Ipv4Address source,
                            const Coord& coordToSend, bool allowedAccept);

    bool verifyAndDecryptReq(const Ptr<const ReqM2>& recHello,
                              Coord& coordOut, bool& allowedAcceptOut);

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

    // Registra un messaggio di controllo trasmesso. 'tipo' e' FANT/BANT/REQ.
    void contaTrafficoControllo(const char *tipo, int byte);

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
