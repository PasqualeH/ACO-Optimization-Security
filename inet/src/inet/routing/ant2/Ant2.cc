// General libraries
#include "inet/routing/ant2/Ant2.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3Tools.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/stlutils.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/HopLimitTag_m.h"
#include "inet/networklayer/ipv4/IcmpHeader.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/networklayer/ipv4/Ipv4Route.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo.h"

// Libraries added for energy measurement
#include "inet/power/management/SimpleEpEnergyManagement.h"
#include "inet/common/StringFormat.h"
#include "inet/common/lifecycle/ModuleOperations.h"

// Libraries added to store vectors and process mathematical operations
#include <unordered_map>
#include <utility>
#include <numeric>


// Libraries added to monitor packets incoming to ipv4 module
#include "inet/networklayer/ipv4/Ipv4.h"
#include "inet/common/packet/Packet.h"


// Libraries added to track the packet passing through a node in order to increase the pheromone values
#include "inet/networklayer/arp/ipv4/GlobalArp.h"
#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/common/L3Address.h"
#include <iostream>
#include <fstream>   // aggiunto per il riepilogo di sicurezza scritto su file in finish()


// Libraries added to enable dynamic moblity of UAVs while simulation is running
#include <cstdlib>
#include <ctime>
#include <cmath>
#include <chrono>
#include <thread>


namespace inet {
namespace ant2 {

Define_Module(Ant2);

enum PacketType {
    FANT_PACKET,
    BANT_PACKET,
    REQ_PACKET
};

Ant2::ForwardEntry::~ForwardEntry()
{
    if (this->event != nullptr) delete this->event;
    if (this->hello != nullptr) delete this->hello;
}

Ant2::Ant2()
{
}

Ant2::~Ant2()
{
    stop();
    // Dispose of dynamically allocated the objects
    delete event;
    delete forwardList;

//    delete Hello;
}

void Ant2::initialize(int stage)
{
    RoutingProtocolBase::initialize(stage);

    // added for energy monitoring
    arrivalSignal = registerSignal("arrival");
    arrivalSignal1 = registerSignal("arrival1");
    arrivalSignal2 = registerSignal("arrival2");
    arrivalSignal3 = registerSignal("arrival3");

    // reads from omnetpp.ini
    if (stage == INITSTAGE_LOCAL) {
        sequencenumber = 0;
        sequencenumber_bant = 0;
        host = getContainingNode(this);
        ift.reference(this, "interfaceTableModule", true);
        rt.reference(this, "routingTableModule", true);

        // added for track the data rate of lower layers
        li = host->getSubmodule("li");
        ipv4_module = host->getSubmodule("ipv4");

        //added for energy measurement
        energyManagement = check_and_cast<inet::power::SimpleEpEnergyManagement *>(getContainingNode(this)->getSubmodule("energyManagement"));

        routeLifetime = par("routeLifetime").doubleValue();
        helloInterval = par("helloInterval");

        // NOTA per il livello di sicurezza: il caricamento delle chiavi NON puo'
        // stare qui. A questo punto di initialize(), interface80211ptr e' ancora
        // nullptr (viene assegnato solo dentro Ant2::start(), eseguito dopo).
        // Vedi il blocco spostato in Ant2::start(), subito dopo l'assegnazione
        // di interface80211ptr.
        forwardList = new std::list<ForwardEntry *>();
        event = new cMessage("event");

        // added for Ant
        alpha = par("alpha").doubleValue();
        betaa = par("betaa").doubleValue();
        pheromoneDecayRate = par("pheromoneDecayRate").doubleValue();
        initialPheromoneValue = par("initialPheromoneValue").doubleValue();
        pheromoneIncrement = par("pheromoneIncrement").doubleValue();

        // added to track data rate
        update_throughput_Interval = par("update_throughput_Interval");
        throughputUpdateTimer = new cMessage("throughputUpdateTimer");
        double waitTime = uniform(0, 2);
        update_throughput_Interval = update_throughput_Interval + waitTime;

        //scheduleAfter(update_throughput_Interval, throughputUpdateTimer); // Schedule the timer to trigger every second
        scheduleAfter(waitTime, throughputUpdateTimer); // Schedule the timer to trigger every second

        // added for pheromone update
        double start_pheromone_update = 4 + uniform(0, 2);
        update_pheromone_Interval = par("update_pheromone_Interval");
        pheromoneUpdateTimer = new cMessage("pheromoneUpdateTimer");
        //scheduleAfter(update_throughput_Interval , pheromoneUpdateTimer); // Schedule the timer to trigger every second
        scheduleAfter(start_pheromone_update , pheromoneUpdateTimer); // Schedule the timer to trigger every second

        // added for ipv4 module monitoring
        networkProtocol.reference(this, "networkProtocolModule", true);

        // added for recruiting logic
        allowed_accept_request = par("allowed_accept_request");
        allowed_send_request = par("allowed_send_request");

        //  added for energy
        nominalCapacity = par("nominalCapacity");

        // added for name
        name = par("name");

        // added bandwidth
        max_band = par("max_band");

        // added cluster if
        cluster_id = par("cluster_id");
        if (cluster_id == 1 || cluster_id == 2 || cluster_id == 3){
            // added to get position
            mobility = check_and_cast<LinearMobility *>(host->getSubmodule("mobility"));
        }
        else if (cluster_id == 4){
            // added to get position
            mobility = nullptr;
        }

    }
    else if (stage == INITSTAGE_ROUTING_PROTOCOLS) {
        registerProtocol(Protocol::manet, gate("ipOut"), gate("ipIn"));
        networkProtocol->registerHook(0, this);
    }

}

void Ant2::start()
{
    /* Search the 80211 interface */
    //int num_80211 = 0;
    NetworkInterface* ie;

    broadcastDelay = &par("broadcastDelay");

    for (int i = 0; i < ift->getNumInterfaces(); i++) {
        ie = ift->getInterface(i);
        if (ie->isWireless()) {
            wirelessInterfaces.push_back(ie);
            num_80211++;
            interfaceId = i; // Save last wireless interface's ID for reference
        }
    }

    // Print the name of each wireless interface
    for (auto iface : wirelessInterfaces) {
        EV << "Found wireless interface: " << iface->getFullName() << "\n"; // OMNeT++ logging
        std::cout << "Found wireless interface: " << iface->getFullName() << std::endl; // Console output
    }

    // Handle cases based on the number of interfaces
    if (num_80211 == 1) {
        interface80211ptr = wirelessInterfaces[0];
    } else if (num_80211 == 2) {
        interface80211ptr = wirelessInterfaces[0];
    } else {
        throw cRuntimeError("DSDV has found %i 80211 interfaces", num_80211);
    }

    // Aggiunto per il livello di sicurezza: caricamento chiavi (una tantum per nodo).
    // Va fatto QUI (in start(), non in initialize()) perche' e' il primo punto in
    // cui interface80211ptr e' garantito assegnato (vedi sopra) e quindi possiamo
    // leggere il vero indirizzo IP del nodo. Due approcci alternativi, scelti col
    // parametro useCentralAuthority:
    // - false (default): provisioning OFFLINE da file, generati prima della run
    //   con gli strumenti in tools/ (vedi Ant2Crypto::loadGroupKey/loadOwnKeypair/loadFleetRoster).
    // - true: autorita' centrale "in-simulazione" (Ant2KeyAuthority), che genera
    //   le chiavi al volo la prima volta che un nodo le richiede.
    // Se un file manca, una chiave e' corrotta, o l'autorita' non si trova,
    // il nodo si ferma subito con un errore chiaro: e' preferibile a farlo
    // partire "silenziosamente insicuro".
    consoleVerbose = par("securityConsoleVerbose").boolValue();

    try {
        if (par("useCentralAuthority").boolValue()) {
            auto authorityModule = getSimulation()->getSystemModule()->getSubmodule(par("keyAuthorityName").stringValue());
            if (authorityModule == nullptr)
                throw cRuntimeError("Ant2KeyAuthority non trovata nella rete (nome cercato: %s)",
                                    par("keyAuthorityName").stringValue());
            auto authority = check_and_cast<ant2::Ant2KeyAuthority *>(authorityModule);

            Ipv4Address myAddress = interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
            crypto.useCentralAuthority(authority, myAddress.getInt());
            // Banner esplicativo, stampato una sola volta dal primo nodo che si avvia.
            static bool bannerStampato = false;
            if (!bannerStampato) {
                bannerStampato = true;
                std::cout << "\n"
                          << "============================================================\n"
                          << " LIVELLO DI SICUREZZA Ant2 attivo\n"
                          << "   - Ascon-AEAD128 : cifra e protegge il contenuto dei messaggi\n"
                          << "                     (coordinate, energia, throughput, cluster)\n"
                          << "   - Ed25519       : firma digitale individuale di ogni nodo,\n"
                          << "                     verificata prima di accettare un pacchetto\n"
                          << " Provisioning chiavi: autorita' centrale in-simulazione\n"
                          << " File prodotti a fine run (nella cartella della simulazione):\n"
                          << "   ant2_security_events.log   -> ogni singolo evento, con motivo\n"
                          << "   ant2_security_summary.txt  -> riepilogo per nodo\n"
                          << "   ant2_security_totals.txt   -> totali di rete\n"
                          << " (in console solo l'essenziale; per il dettaglio completo a\n"
                          << "  schermo: **.routing.securityConsoleVerbose = true)\n"
                          << "============================================================\n"
                          << std::endl;
            }
            securityEventLog() << simTime() << "  " << getFullPath()
                               << "  AVVIO   identita' ricevuta (chiave privata Ed25519 + chiave di gruppo Ascon), indirizzo="
                               << myAddress << "\n";
            std::cout << "[SEC][AVVIO] " << getFullPath() << " -> identita' ok, indirizzo=" << myAddress << std::endl;
            EV_INFO << "Ant2/security: chiavi ottenute dall'autorita' centrale per " << myAddress << endl;
        }
        else {
            crypto.loadGroupKey(par("groupKeyFile").stdstringValue());
            crypto.loadOwnKeypair(par("ownPubKeyFile").stdstringValue(), par("ownPrivKeyFile").stdstringValue());
            crypto.loadFleetRoster(par("fleetRosterFile").stdstringValue());
            EV_INFO << "Ant2/security: chiavi caricate da file (provisioning offline)" << endl;
        }
    } catch (const std::exception& e) {
        throw cRuntimeError("Ant2: errore nel caricamento delle chiavi di sicurezza: %s", e.what());
    }
    // UNCOMMENT AFTER
    // if (par("manetPurgeRoutingTables").boolValue()) {
    Ipv4Route *entry;
        // clean the route table wlan interface entry
    for (int i = rt->getNumRoutes() - 1; i >= 0; i--) {
        entry = rt->getRoute(i);
        x2ppp_address = entry->getDestination();
        EV << "Existing route " << x2ppp_address << endl;
    //        if (entry->getInterface()->isWireless())
    //            rt->deleteRoute(entry);
      }

    // Sicurezza: questo nodo puo' inviare FANT usando come srcAddress anche
    // x2ppp_address (l'interfaccia X2/PPP verso il proprio gNodeB) invece
    // dell'indirizzo wlan con cui si e' registrato. Lo dichiariamo come alias
    // della stessa identita', altrimenti quei pacchetti - pur autentici -
    // verrebbero scartati dagli altri nodi come "mittente sconosciuto".
    if (x2ppp_address != Ipv4Address::UNSPECIFIED_ADDRESS) {
        crypto.registerOwnAlias(x2ppp_address.getInt());
        securityEventLog() << simTime() << "  " << getFullPath()
                           << "  AVVIO   secondo indirizzo (interfaccia X2 verso il gNodeB): "
                           << x2ppp_address << " registrato come stessa identita'\n";
    }

    // TEST NEGATIVO: se configurato come attaccante, il nodo scarta la propria
    // identita' legittima e ne genera una non riconosciuta da nessuno.
    // Da qui in avanti continuera' a inviare FANT/BANT/REQ regolarmente, ma
    // ogni ricevente ne rifiutera' la firma. Si fa DOPO il provisioning proprio
    // per simulare una compromissione avvenuta dopo il rilascio in campo.
    if (par("isAttacker").boolValue()) {
        crypto.useRogueIdentity();
        std::cout << "\n[SEC][ATTACCANTE] *** " << getFullPath() << " e' stato COMPROMESSO ***\n"
                  << "                  Da ora firma i propri messaggi con una chiave NON riconosciuta.\n"
                  << "                  Conserva pero' la chiave di gruppo Ascon: con la sola cifratura\n"
                  << "                  di gruppo sarebbe indistinguibile da un nodo onesto.\n"
                  << "                  Ci aspettiamo che tutti i suoi vicini ne rifiutino i pacchetti.\n"
                  << std::endl;
    }
    //}

    //CHK(interface80211ptr->getProtocolDataForUpdate<Ipv4InterfaceData>())->joinMulticastGroup(Ipv4Address::LL_MANET_ROUTERS);
    //if (name == 0){
    //    scheduleAfter(uniform(0.0, 2.0), event);
    //}
    scheduleAfter(uniform(0.0, 2.0), event);
}

void Ant2::finish()
{
    // Riepilogo del livello di sicurezza, a fine run, per OGNI nodo.
    //
    // Scritto su file dedicati (nella working directory della simulazione) e non
    // solo con EV_*/std::cout, perche' le stampe EV_* vengono soppresse in
    // "express mode" e std::cout non finisce nel file di cmdenv-output-file.
    static bool firstCall = true;
    static long tot_bant_ok = 0, tot_bant_fail = 0;
    static long tot_req_ok = 0, tot_req_fail = 0;
    static long tot_fant_ok = 0, tot_fant_fail = 0;
    static long tot_unknown = 0, tot_signature = 0, tot_aead = 0;
    static int nodiConteggiati = 0;

    tot_bant_ok += sec_bant_ok;   tot_bant_fail += sec_bant_fail;
    tot_req_ok  += sec_req_ok;    tot_req_fail  += sec_req_fail;
    tot_fant_ok += sec_fant_ok;   tot_fant_fail += sec_fant_fail;
    tot_unknown += sec_fail_unknown;
    tot_signature += sec_fail_signature;
    tot_aead += sec_fail_aead;
    nodiConteggiati++;

    std::ofstream out;
    if (firstCall) {
        out.open("ant2_security_summary.txt", std::ios::trunc);
        out << "# ================================================================\n";
        out << "# Riepilogo livello di sicurezza Ant2 (Ascon-AEAD128 + Ed25519)\n";
        out << "# ================================================================\n";
        out << "# Una riga per nodo. Per ogni tipo di messaggio del protocollo:\n";
        out << "#   FANT = scoperta di rotta       (solo firmato)\n";
        out << "#   BANT = risposta con stato nodo (firmato + cifrato)\n";
        out << "#   REQ  = richiesta di recruiting (firmato + cifrato)\n";
        out << "#\n";
        out << "#   ok        = firma verificata e payload decifrato correttamente\n";
        out << "#   scartati  = pacchetto rifiutato PRIMA di aggiornare qualsiasi tabella\n";
        out << "# ================================================================\n";
        firstCall = false;
    }
    else
        out.open("ant2_security_summary.txt", std::ios::app);

    if (out) {
        out << getFullPath()
            << "  FANT: ok=" << sec_fant_ok << " scartati=" << sec_fant_fail
            << " | BANT: ok=" << sec_bant_ok << " scartati=" << sec_bant_fail
            << " | REQ: ok=" << sec_req_ok << " scartati=" << sec_req_fail;
        if (sec_fail_unknown || sec_fail_signature || sec_fail_aead) {
            out << "   [motivi scarti -> identita' sconosciuta: " << sec_fail_unknown
                << ", firma non valida: " << sec_fail_signature
                << ", payload manomesso: " << sec_fail_aead << "]";
        }
        out << "\n";
    }

    // File separato con i TOTALI di rete: viene riscritto ad ogni finish(),
    // quindi al termine contiene l'aggregato completo di tutti i nodi.
    std::ofstream tot("ant2_security_totals.txt", std::ios::trunc);
    if (tot) {
        long okTot = tot_fant_ok + tot_bant_ok + tot_req_ok;
        long failTot = tot_fant_fail + tot_bant_fail + tot_req_fail;
        tot << "=====================================================\n";
        tot << " TOTALI DI RETE - livello di sicurezza Ant2\n";
        tot << " (nodi conteggiati finora: " << nodiConteggiati << ")\n";
        tot << "=====================================================\n";
        tot << " FANT   verificati: " << tot_fant_ok  << "   scartati: " << tot_fant_fail << "\n";
        tot << " BANT   verificati: " << tot_bant_ok  << "   scartati: " << tot_bant_fail << "\n";
        tot << " REQ    verificati: " << tot_req_ok   << "   scartati: " << tot_req_fail << "\n";
        tot << "-----------------------------------------------------\n";
        tot << " TOTALE verificati: " << okTot << "   scartati: " << failTot << "\n";
        if (okTot + failTot > 0)
            tot << " Percentuale pacchetti rifiutati: "
                << (100.0 * failTot / (okTot + failTot)) << "%\n";
        tot << "-----------------------------------------------------\n";
        tot << " Motivi degli scarti:\n";
        tot << "   identita' sconosciuta (non nel registro): " << tot_unknown << "\n";
        tot << "   firma Ed25519 non valida:                 " << tot_signature << "\n";
        tot << "   payload manomesso (tag Ascon errato):     " << tot_aead << "\n";
        tot << "=====================================================\n";
    }

    std::cout << "[SEC][RIEPILOGO] " << getFullPath()
              << "  FANT ok=" << sec_fant_ok << "/scartati=" << sec_fant_fail
              << "  BANT ok=" << sec_bant_ok << "/scartati=" << sec_bant_fail
              << "  REQ ok=" << sec_req_ok << "/scartati=" << sec_req_fail
              << std::endl;
}

void Ant2::stop()
{
    cancelEvent(event);
    while (!forwardList->empty()) {
        ForwardEntry *fh = forwardList->front();
        if (fh->event)
            cancelAndDelete(fh->event);
        if (fh->hello)
            cancelAndDelete(fh->hello);
        fh->event = nullptr;
        fh->hello = nullptr;
        forwardList->pop_front();
        delete fh;
    }
}

void Ant2::handleSelfMessage(cMessage *msg)
{

    //////////// ADDED FOR ENERGY MEASUREMENT /////////////////////////

    J energylevel = energyManagement->getEstimatedEnergyCapacity();
    double residualEnergy = energylevel.get();
    double charge_status = (int)((residualEnergy/nominalCapacity) * 100);
    EV_DETAIL << "Energy level is: " << charge_status << "%" << endl;

    if (charge_status <= 15.0 && allowed_send_request == true) {
        allowed_accept_request = false;
        int counter = 1;
        for (auto& interface80211ptr : wirelessInterfaces) {
            // MODIFICATO per sicurezza: cifratura + firma centralizzate in buildSecureReq().
            Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            sequencenumber += 1;
            Coord selfPosition = mobility->getCurrentPosition();
            node_position = selfPosition;
            auto packet = buildSecureReq(source, sequencenumber, source, node_position, false);
            auto addressReq = packet->addTag<L3AddressReq>();
            addressReq->setDestAddress(L3Address(broadcast_addr));
            addressReq->setSrcAddress(L3Address(source));

            packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
            packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
            packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

            // Broadcast the ReqM2 to other nodes
            send(packet, "ipOut");
            total_manet_packets++;
            counter++;

            // Clean up
            packet = nullptr;

            allowed_send_request = false;
        }
    }

    if (charge_status <= 15.0) {
        return;
    }

    if (charge_status <= 10.0) {
        moveUav_charge();
        EV << "Energy is depleted, not sending Hello message" << endl;
        if (event -> isScheduled()) {
            cancelEvent(event);
        }
        if (pheromoneUpdateTimer -> isScheduled()) {
            cancelEvent(pheromoneUpdateTimer);
        }
        if (throughputUpdateTimer -> isScheduled()) {
            cancelEvent(throughputUpdateTimer);
        }
        return;
    }

    ///////////////////////////////////////////////////////////////////

    ///////////// Ant packet generation and forwarding ////////////////

    if (msg == event) {

        double random = uniform(0.0, 1.0);
        double range_limit = 0.8;

        EV_INFO << "Prueba " << random << endl;
        Ipv4Address selectedDestination;
        if (random < range_limit) {
            // If the random number is in the first range, send a broadcast message
            // Collect all valid routes in a vector
            std::vector<Ipv4Route*> validRoutes;

            for (int i = 0; i < rt->getNumRoutes(); ++i) {
                Ipv4Route* route = rt->getRoute(i);
                if (route) { // Ensure the route is valid
                    // Get the network interface associated with the route
                    NetworkInterface* interfaceEntry = route->getInterface();
                    if (interfaceEntry) {
                        // Check if the interface name contains "ppp" (or adjust the logic based on your needs)
                        std::string interfaceName = interfaceEntry->getInterfaceName();
                        if (interfaceName.find("ppp") == std::string::npos) {
                            validRoutes.push_back(route); // Add the route only if the interface is PPP
                        }
                    }
                }
            }

            // Select a random valid route and set its destination as the Fant message destination
            if (!validRoutes.empty()) {
                // Generate a random index between 0 and validRoutes.size() - 1
                int randomIndex = rand() % validRoutes.size();
                selectedDestination = validRoutes[randomIndex]->getDestination();;
            }
            else {
                selectedDestination = Ipv4Address(255,255,255,255);
            }
        } else { // Remaining range
            selectedDestination = Ipv4Address(255,255,255,255);
        }

        Ipv4Address source_a;
        Ipv4Address source_b;
        Ipv4Address source;
        source = (wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress());

        if (wirelessInterfaces.size() == 1) {
            source_a = (wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
        }
        else if (wirelessInterfaces.size() == 2) {
            source_b = (wirelessInterfaces[1]->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
        }

        auto fant_message = makeShared<FantM2>();
        fant_message->setChunkLength(b(128));
        fant_message->setSrcAddress(source);
        fant_message->setDstAddress(selectedDestination);
        sequencenumber += 1;
        fant_message->setSequencenumber(sequencenumber);
        fant_message->setNextAddress(source);
        fant_message->setHopdistance(1);
        fant_message->appendHopAddresses(source);

        // firma Ed25519 del FANT prima dell'invio
        signFant(fant_message);
        auto packet = new Packet("Fant", fant_message);
        auto addressReq = packet->addTag<L3AddressReq>();
        packet->setKind(FANT_PACKET);
        addressReq->setDestAddress(L3Address(broadcast_addr));
        addressReq->setSrcAddress(L3Address(source_a));

        packet->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

        double waitTime1 = intuniform(1, 100);
        waitTime1 = waitTime1 / 10000;
        sendDelayed(packet, waitTime1, "ipOut");
        total_manet_packets++;

        packet = nullptr;
        fant_message = nullptr;

        if (wirelessInterfaces.size() == 2) {

            auto fant_message2 = makeShared<FantM2>();

            fant_message2->setChunkLength(b(128));
            fant_message2->setSrcAddress(source);
            fant_message2->setDstAddress(selectedDestination);
            //sequencenumber += 1;
            fant_message2->setSequencenumber(sequencenumber);
            fant_message2->setNextAddress(source_b);
            fant_message2->setHopdistance(1);
            fant_message2->appendHopAddresses(source_b);

            // Creating fant packet
            // firma Ed25519 del FANT prima dell'invio
            signFant(fant_message2);
            auto packet2 = new Packet("Fant", fant_message2);
            auto addressReq2 = packet2->addTag<L3AddressReq>();
            packet2->setKind(FANT_PACKET);
            addressReq2->setDestAddress(L3Address(broadcast_addr));
            addressReq2->setSrcAddress(L3Address(source_b));

            packet2->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
            packet2->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
            packet2->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

            double waitTime2 = intuniform(1, 100);
            waitTime2 = waitTime2 / 10000;
            sendDelayed(packet2, waitTime2, "ipOut");
            total_manet_packets++;

            packet2 = nullptr;
            fant_message2 = nullptr;
        }

        /////////////////////////////// send other packet ///////////////////////
        if (x2ppp_address != Ipv4Address::UNSPECIFIED_ADDRESS) {
            auto fant_message3 = makeShared<FantM2>();
            Ipv4Address source_x2 = x2ppp_address;
            fant_message3->setChunkLength(b(128));
            fant_message3->setSrcAddress(source_x2);
            fant_message3->setDstAddress(selectedDestination);
            sequencenumber += 1;
            fant_message3->setSequencenumber(sequencenumber);
            fant_message3->setNextAddress(source);
            fant_message3->setHopdistance(1);
            fant_message3->appendHopAddresses(source);

            // Creating fant packet
            // firma Ed25519 del FANT prima dell'invio
            signFant(fant_message3);
            auto packet3 = new Packet("Fant", fant_message3);
            auto addressReq3 = packet3->addTag<L3AddressReq>();
            packet3->setKind(FANT_PACKET);
            addressReq3->setDestAddress(L3Address(broadcast_addr));
            addressReq3->setSrcAddress(source_a);

            packet3->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
            packet3->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
            packet3->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

            double waitTime3 = intuniform(1, 100);
            waitTime3 = waitTime3 / 10000;
            sendDelayed(packet3, waitTime3, "ipOut");
            total_manet_packets++;

            packet3 = nullptr;
            fant_message3 = nullptr;

            if (wirelessInterfaces.size() == 2) {
                auto fant_message4 = makeShared<FantM2>();
                fant_message4->setChunkLength(b(128));
                fant_message4->setSrcAddress(source_x2);
                fant_message4->setDstAddress(selectedDestination);
                //sequencenumber += 1;
                fant_message4->setSequencenumber(sequencenumber);
                fant_message4->setNextAddress(source_b);
                fant_message4->setHopdistance(1);
                fant_message4->appendHopAddresses(source_b);

                // Creating fant packet
                // firma Ed25519 del FANT prima dell'invio
                signFant(fant_message4);
                auto packet4 = new Packet("Fant", fant_message4);
                auto addressReq4 = packet4->addTag<L3AddressReq>();
                packet4->setKind(FANT_PACKET);
                addressReq4->setDestAddress(L3Address(broadcast_addr));
                addressReq4->setSrcAddress(source_b);

                packet4->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                packet4->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                packet4->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                double waitTime4 = intuniform(1, 100);
                waitTime4 = waitTime4 / 10000;
                sendDelayed(packet4, waitTime4, "ipOut");
                total_manet_packets++;

                packet4 = nullptr;
                fant_message4 = nullptr;
            }

        }
        scheduleAfter(helloInterval, event);
    }


    ///////////////////////////////////////////////////////////////////
}

void Ant2::handleMessageWhenUp(cMessage *msg)
{

    //////////// ADDED FOR ENERGY MEASUREMENT /////////////////////////

    J energylevel = energyManagement->getEstimatedEnergyCapacity();
    double residualEnergy = energylevel.get();
    double charge_status = (int)((residualEnergy/nominalCapacity) * 100);
    //EV_DETAIL << "Energy level is: " << charge_status << "%" << endl;



    if (msg == pheromoneUpdateTimer) {
        // Update pheromone values
        updatePheromoneValues();

        // Reschedule the timer for the next second
        scheduleAfter(update_pheromone_Interval, pheromoneUpdateTimer);
    }

    if (msg == throughputUpdateTimer) {
        // Update amount of data processed on physical interface
        updateThroughput();

        // Reschedule the timer for the next second
        scheduleAfter(update_throughput_Interval, throughputUpdateTimer);
    }

    if (msg == moveTimer) {
        // Update amount of data processed on physical interface
        moveUav();
    }

    ///////////////////////////////////////////////////////////////////

    if (charge_status <= 15.0 && allowed_send_request == true) {
        allowed_accept_request = false;
        int counter = 1;
        for (auto& interface80211ptr : wirelessInterfaces) {
            // MODIFICATO per sicurezza: cifratura + firma centralizzate in buildSecureReq().
            Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            sequencenumber += 1;
            Coord selfPosition = mobility->getCurrentPosition();
            node_position = selfPosition;
            auto packet = buildSecureReq(source, sequencenumber, source, node_position, false);
            auto addressReq = packet->addTag<L3AddressReq>();
            addressReq->setDestAddress(Ipv4Address(255,255,255,255));
            addressReq->setSrcAddress(source);

            packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
            packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
            packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

            // Broadcast the ReqM2 to other nodes
            send(packet, "ipOut");
            total_manet_packets++;

            // Clean up
            packet = nullptr;
            counter++;
            allowed_send_request = false;
        }
    }

    if (charge_status <= 15.0) {
        if (charge_status <= 10.0) {
            moveUav_charge();
            EV << "Energy is depleted, not sending Hello message" << endl;
            if (event -> isScheduled()) {
                cancelEvent(event);
            }
            if (pheromoneUpdateTimer -> isScheduled()) {
                cancelEvent(pheromoneUpdateTimer);
            }
            if (throughputUpdateTimer -> isScheduled()) {
                cancelEvent(throughputUpdateTimer);
            }
            return;
        }
        else {
            return;
        }
    }



    ///////////////////////////////////////////////////////////////////
    /////////////////// CONTROL FOR FIRST SCHEDULED MESSAGE ///////////
    if (msg->isSelfMessage()) {
        handleSelfMessage(msg);
    }

    /////////////// FORWARD FANT /////////////////////////////////////

    else if (check_and_cast<Packet *>(msg)->getTag<PacketProtocolTag>()->getProtocol() == &Protocol::manet) {
        total_manet_packets++;

        if (num_80211 == 1) {
            // Differentiating between FANT and BANT
            if (msg->getKind() == FANT_PACKET) {

                // --- Sicurezza: verifica firma del FANT come primo passo,
                // prima di allocare fhp, toccare tabelle o inoltrare.
                if (!verifyFant(check_and_cast<Packet *>(msg)->peekData<FantM2>())) {
                    delete msg;
                    return;
                }

                ForwardEntry *fhp = nullptr;
                auto recHello = staticPtrCast<FantM2>(check_and_cast<Packet *>(msg)->peekData<FantM2>()->dupShared());
                fhp = new ForwardEntry();
                fhp->hello = check_and_cast<Packet *>(msg->dup());

                if (msg->arrivedOn("ipIn")) {

                    Ipv4Address source = wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    std::string source_string = source.str();

                    // Reading Fant fields
                    Ipv4Address src;
                    Ipv4Address dst;
                    unsigned int msgsequencenumber;
                    int numHops;
                    Ipv4Address next;

                    src = recHello->getSrcAddress();
                    dst = recHello->getDstAddress();
                    msgsequencenumber = recHello->getSequencenumber();
                    next = recHello->getNextAddress();
                    numHops = recHello->getHopdistance();

                    EV_DETAIL << "========================================== new processing ====================================================" << endl;
                    EV_DETAIL << "FANT arrives, Source: " << src << " Destination: " << dst << " Sequence number: " << msgsequencenumber << " Hops number: " << numHops << endl;

                    std::string src_string = recHello->getSrcAddress().str();
                    std::string dst_string = recHello->getNextAddress().str();
                    std::string nxt_string = recHello->getNextAddress().str();

                    //////////////////////////////////////////////////////////////////////
                    // Create the key for the map

                    std::string key = src_string;

                    if ((src == source) || (src == x2ppp_address)) {
                        EV_INFO << "Fant msg dropped. This message returned to the original creator.\n";
                        delete fhp;
                        delete msg;
                        return;

                    }

                    ///////////// Check if this packet has already been received with the same sequence number
                    if (receivedPackets[key].find(msgsequencenumber) != receivedPackets[key].end()) {
                        EV_INFO << "Duplicate Fant msg detected (Source: " << src_string << ", Destination: " << dst_string << ", Sequence number: " << msgsequencenumber << "). Dropping packet.\n";
                        delete fhp;
                        delete msg;
                        return;
                    }
                    // Store the source-destination pair and sequence number
                    receivedPackets[key].insert(msgsequencenumber);

                    ///// added learn all possible routes avoiding duplicate messages that generate loops ////
                    size_t size = recHello->getHopAddressesArraySize();
                    //Ipv4Address hopAddresses[size];
                    bool repeated = false;
                    for (int i = 0; i < recHello->getHopAddressesArraySize(); ++i) {
                        Ipv4Address address = recHello->getHopAddresses(i);
                        if (address == source) {
                            repeated = true;
                            break;
                        }
                    }

                    if (repeated == false) {
                        // added to save the destination (source of Fant), its next hop, and its number of hops
                        double pheromoneValue = 100.0 / numHops;

                        // update table
                        bool entryExists = false;
                        for (auto &entry : routingTable) {
                            if (entry.destinationAddress == src_string && entry.nextHop == nxt_string) {
                                entry.pheromone += pheromoneValue; // Update pheromone value
                                EV_INFO << "Updated pheromone value for destination: " << entry.destinationAddress
                                        << ", Next Hop: " << entry.nextHop
                                        << ", New Pheromone: " << entry.pheromone << "\n";
                                entryExists = true;
                                break;
                            }
                        }
                        if (!entryExists) {
                            // Add the new entry to the table
                            RoutingTableEntry newEntry = {src_string, nxt_string, pheromoneValue};
                            routingTable.push_back(newEntry);
                            EV_INFO << "Added new entry to routing table: Destination: " << src_string << ", Next Hop: " << nxt_string << ", Pheromone: " << pheromoneValue << "\n";
                        }
                    }
                    else {
                        delete fhp;
                        delete msg;
                        return;
                    }

                    ////////////////// Add the new entry to the routing table (destination, gateway, sequence number)
                    ////////////////// Used to route the Bant when comes back to the originator

                    RoutingTableAntEntry newEntry = {src_string, dst_string, msgsequencenumber};
                    routingTableAnt.push_back(newEntry);

                    ///////////////// Processing when Unicast Fant arrives to destination ///////////////
                    if (dst == source || dst == x2ppp_address) {

                        EV_INFO << "Fant arrives to destination" << endl;
                        //////// get gateway for bant //////////////////
                        Ipv4Address gateway;
                        bool entryExists = false;
                        for (auto &entry : routingTableAnt) {
                            if (entry.destinationAddress == src_string && entry.sequenceNumber == msgsequencenumber) {
                                gateway = Ipv4Address(entry.gateway.c_str());
                                entryExists = true;
                                // entryExists = true;
                                break;
                            }
                        }
                        /////////////////////////////////////////////////

                        if (entryExists == false){
                            return;
                        }
                        else {
                            // MODIFICATO per sicurezza: cifratura + firma centralizzate in
                            // buildSecureBant() (vedi Ant2Crypto). Nessun campo sensibile
                            // (energia, throughput, coordinate, cluster_id, disponibilita')
                            // viene piu' impostato in chiaro qui.
                            auto bant_packet = buildSecureBant(src, gateway, msgsequencenumber, source);
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();
                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq->setSrcAddress(L3Address(source));
                            bant_packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
                            bant_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            // Send the Bant packet
                            double waitTime3 = intuniform(1, 100);
                            waitTime3 = waitTime3 / 10000;
                            sendDelayed(bant_packet, waitTime3, "ipOut");
                            total_manet_packets++;

                            // Clean up
                            bant_packet = nullptr;
                            //packet = nullptr;
                            fhp = nullptr;
                        }

                    }

                    else {

                        auto packet = new Packet("Fant");
                        auto addressReq = packet->addTag<L3AddressReq>();
                        addressReq->setDestAddress(L3Address(broadcast_addr));
                        //addressReq->setSrcAddress(interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
                        addressReq->setSrcAddress(L3Address(source));
                        packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
                        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        recHello->setNextAddress(source);
                        numHops++;

                        recHello->setHopdistance(numHops);
                        recHello->setSrcAddress(src);
                        recHello->setDstAddress(dst);
                        recHello->setSequencenumber(msgsequencenumber);
                        recHello->appendHopAddresses(source);
                        double waitTime = intuniform(1, 100);
                        waitTime = waitTime / 10000;
                        EV_DETAIL << "Forwarding Fant " << endl;
                        packet->insertAtBack(recHello);
                        packet->setKind(FANT_PACKET); // Set the packet type
                        sendDelayed(packet, waitTime, "ipOut");
                        total_manet_packets++;

                        //////// get gateway for bant //////////////////
                        Ipv4Address gateway;
                        bool entryExists = false;
                        for (auto &entry : routingTableAnt) {
                            if (entry.destinationAddress == src_string && entry.sequenceNumber == msgsequencenumber) {
                                gateway = Ipv4Address(entry.gateway.c_str());
                                entryExists = true;
                                // entryExists = true;
                                break;
                            }
                        }
                        /////////////////////////////////////////////////

                        if (entryExists==false){
                            return;
                        }
                        else {
                            // MODIFICATO per sicurezza: cifratura + firma centralizzate in
                            // buildSecureBant() (vedi Ant2Crypto). Stesso identico schema
                            // usato nel blocco "caso destinazione" poco sopra.
                            auto bant_packet = buildSecureBant(src, gateway, msgsequencenumber, source);
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();
                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq->setSrcAddress(L3Address(source));

                            bant_packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
                            bant_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            // Send the Bant packet
                            double waitTime1 = intuniform(1, 100);
                            waitTime1 = waitTime1 / 10000;
                            sendDelayed(bant_packet, waitTime1, "ipOut");
                            total_manet_packets++;

                            // Clean up
                            bant_packet = nullptr;

                        }
                        //////////////////////////////////////////

                        packet = nullptr;
                        fhp = nullptr;

                        //////////////////////////////////////////
                    }
                }
            }

            else if (msg->getKind() == BANT_PACKET) {

                auto recHello = check_and_cast<Packet *>(msg)->peekData<BantM2>();

                // --- Aggiunto per sicurezza: verifica firma + decifratura, come PRIMA
                // cosa in assoluto, prima di allocare fhp, prima di toccare
                // routingTableAnt/statusTable, prima di un eventuale inoltro. Un
                // pacchetto che non supera questo controllo viene scartato subito,
                // senza propagarsi oltre: e' questo a chiudere il problema
                // dell'"amplificazione" da parte dei gateway di cui avevamo parlato.
                double energy, throughput, max_throughput;
                Coord node_position_neighbor;
                int cluster_id_;
                bool allowed_accept_request_node;
                if (!verifyAndDecryptBant(recHello, energy, throughput, node_position_neighbor,
                                           max_throughput, cluster_id_, allowed_accept_request_node)) {
                    delete msg;
                    return;
                }

                ForwardEntry *fhp = nullptr;
                fhp = new ForwardEntry();
                fhp->hello = check_and_cast<Packet *>(msg->dup());

                if (msg->arrivedOn("ipIn")) {

                    Ipv4Address source = interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    std::string source_string = source.str();

                    // Reading Fant fields
                    Ipv4Address src;
                    Ipv4Address dst;
                    unsigned int msgsequencenumber;
                    int numHops;
                    Ipv4Address next;
                    Ipv4Address gateway;

                    src = recHello->getSrcAddress();
                    dst = recHello->getDstAddress();
                    msgsequencenumber = recHello->getSequencenumber();
                    next = recHello->getNextAddress();
                    numHops = recHello->getHopdistance();
                    gateway = recHello->getGateway();
                    // NOTA: allowed_accept_request_node arriva gia' decifrato qui sopra,
                    // non si rilegge piu' un campo in chiaro dal pacchetto.
                    // "hops" resta concettualmente uguale a hopdistance (il numero di
                    // salti attraversati): e' un campo in chiaro, mutabile ad ogni hop,
                    // quindi lo prendiamo da qui e non dal payload cifrato.
                    double hops = static_cast<double>(numHops);

                    std::string src_string = recHello->getSrcAddress().str();
                    std::string dst_string = recHello->getNextAddress().str();
                    std::string nxt_string = recHello->getNextAddress().str();
                    std::string gateway_string = recHello->getGateway().str();
                    std::string destination_string = recHello->getDstAddress().str();

                    EV_DETAIL << "========================================== new processing ====================================================" << endl;
                    EV_DETAIL << "BANT arrives, Source: " << src << " Destination: " << dst << "Gateway: " << gateway_string << " Sequence number: " << msgsequencenumber << " Hops number: " << numHops << endl;

                    ////////////// Ant CONTROL FOR BANT (RETURN TO ORIGINATOR ADDRESS) /////////////////
                    Ipv4Address next_gateway;
                    bool entryExists1 = false;

                    if (gateway_string == source_string) {
                        for (auto &entry : routingTableAnt) {
                            if (entry.destinationAddress == destination_string && entry.sequenceNumber == msgsequencenumber) {
                                next_gateway = Ipv4Address(entry.gateway.c_str());
                                entryExists1 = true;
                                break;
                            }
                        }
                    }

                    ///////////////////////////////////////////////////////////////////////////////////

                    //if ((entryExists1 == true && gateway == source) || (dst == source &&  gateway == source )) {
                    if ((gateway == source) || (dst == source) || (dst == x2ppp_address)) {

                        /////// Add the status of the Bant generateor address to monitor table ///////////////
                        // MODIFICATO: energy/throughput/node_position_neighbor/hops/max_throughput/
                        // cluster_id_/allowed_accept_request_node arrivano gia' decifrati da
                        // verifyAndDecryptBant() in cima al blocco: non si rileggono piu' dal pacchetto.

                        double distance = calculateEuclideanDistance(node_position_neighbor, node_position);

                        // Check if the src_string already exists in the statusTable
                        auto it = std::find_if(statusTable.begin(), statusTable.end(),
                                               [&src_string](const StatusEntry& entry) {
                                                   return entry.destinationAddress == src_string;
                                               });

                        if (it != statusTable.end()) {
                            // Update existing entry
                            it->energy = energy;
                            it->throughput = throughput;
                            it->distance = distance;
                            it->hops = hops;
                            it->max_throughput = max_throughput;
                            it->cluster_id = cluster_id_;
                            it->allowed_accept_request = allowed_accept_request_node;
                            EV_INFO << "Updated entry in monitor table: Host: " << src_string
                                    << ", Energy: " << energy << ", Throughput: " << throughput
                                    << ", Distance: " << distance << ", Hops: " << hops << "\n";
                        } else {
                            // Add new entry
                            StatusEntry newEntry = {src_string, energy, throughput, distance, hops, max_throughput, cluster_id_, allowed_accept_request_node};
                            statusTable.push_back(newEntry);
                            EV_INFO << "Added new entry to monitor table: Host: " << src_string
                                    << ", Energy: " << energy << ", Throughput: " << throughput
                                    << ", Distance: " << distance << ", Hops: " << hops << "\n";
                        }

                        /////////////////////////////////////////////////////////////////////////////////////
                        ///////// Save routing table Ant ////////////////////////////////////
                        double pheromoneValue = 100.0 / numHops;

                        /////////// routing table update /////////////
                        bool entryExists = false;

                        for (auto &entry : routingTable) {
                            if (entry.destinationAddress == src_string && entry.nextHop == nxt_string) {
                                entry.pheromone += pheromoneValue; // Update pheromone value
                                EV_INFO << " Updated pheromone value for destination: " << entry.destinationAddress
                                        << ", Next Hop: " << entry.nextHop
                                        << ", New Pheromone: " << entry.pheromone << "\n";
                                entryExists = true;
                                break;
                            }
                        }

                        if (!entryExists) {
                            // Add the new entry to the routing table
                            RoutingTableEntry newEntry = {src_string, nxt_string, pheromoneValue};
                            routingTable.push_back(newEntry);
                            EV_INFO << "Added new entry to routing table: Destination: " << src_string << ", Next Hop: " << nxt_string << ", Pheromone: " << pheromoneValue << "\n";
                        }

                        /////////////////////////////////////////////////////////

                    }

                    /////////////////////////// forward message ////////////////////

                    if (entryExists1 && gateway == source && ((dst != source) || (dst != x2ppp_address))){

                        auto packet = new Packet("Bant");
                        auto addressReq = packet->addTag<L3AddressReq>();
                        addressReq->setDestAddress(L3Address(broadcast_addr));
                        addressReq->setSrcAddress(source);
                        packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
                        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        // MODIFICATO per sicurezza: recHello e' ora un puntatore a un
                        // BantM2 IMMUTABILE (const). Per inoltrarlo serve una copia
                        // mutabile, e su quella copia si toccano SOLO i campi di
                        // routing in chiaro (nextAddress, hopdistance, gateway).
                        // srcAddress/dstAddress/sequencenumber/ciphertext/authTag/
                        // signature restano byte-per-byte identici a come li ha
                        // prodotti il mittente originale: e' proprio questo che
                        // permette a chiunque, a qualunque hop, di continuare a
                        // verificarne la firma. Non si riscrive piu' qui dentro
                        // ne' "hops" ne' "allowed_accept_request": sono dati che
                        // riguardano il mittente originale, non il nodo che inoltra,
                        // e vivono cifrati dentro il payload sigillato dalla sua firma.
                        auto forwardedBant = staticPtrCast<BantM2>(recHello->dupShared());
                        numHops++;
                        forwardedBant->setNextAddress(source);
                        forwardedBant->setHopdistance(numHops);
                        forwardedBant->setGateway(next_gateway);

                        double waitTime = intuniform(1, 100);
                        waitTime = waitTime / 10000;
                        EV_DETAIL << "Forwarding Bant " << endl;
                        packet->insertAtBack(forwardedBant);
                        packet->setKind(BANT_PACKET);  // Set the correct packet type
                        sendDelayed(packet, waitTime, "ipOut");
                        total_manet_packets++;
                        packet = nullptr;
                        fhp = nullptr;
                    }
                    else {
                        delete msg;
                        return;
                    }

                }
            }
            else if (msg->getKind() == REQ_PACKET) {
                total_req_packets++;

                auto recHelloConst = check_and_cast<Packet *>(msg)->peekData<ReqM2>();

                // --- Aggiunto per sicurezza: stesso schema del BANT. Verifica
                // firma + decifratura come primissimo passo, prima di allocare
                // fhp e prima di toccare qualunque tabella.
                Coord coordenates_to_be_recruited_coord;
                bool allowed_accept_request_sender;
                if (!verifyAndDecryptReq(recHelloConst, coordenates_to_be_recruited_coord,
                                          allowed_accept_request_sender)) {
                    delete msg;
                    return;
                }

                ForwardEntry *fhp = nullptr;
                auto recHello = staticPtrCast<ReqM2>(recHelloConst->dupShared());
                fhp = new ForwardEntry();
                fhp->hello = check_and_cast<Packet *>(msg->dup());

                if (msg->arrivedOn("ipIn")) {

                    Ipv4Address source = interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    std::string source_string = source.str();

                    // Reading Fant fields
                    Ipv4Address src;
                    Ipv4Address dst;
                    unsigned int msgsequencenumber;
                    int numHops;
                    Ipv4Address next;

                    src = recHello->getSrcAddress();
                    dst = recHello->getDstAddress();
                    msgsequencenumber = recHello->getSequencenumber();
                    next = recHello->getNextAddress();
                    numHops = recHello->getHopdistance();

                    EV_DETAIL << "========================================== new processing ====================================================" << endl;
                    EV_DETAIL << "REQ arrives, Source: " << src << " Destination: " << dst << " Sequence number: " << msgsequencenumber << " Hops number: " << numHops << endl;

                    std::string src_string = recHello->getSrcAddress().str();
                    std::string dst_string = recHello->getNextAddress().str();
                    std::string nxt_string = recHello->getNextAddress().str();
                    // NOTA: le coordinate arrivano gia' decifrate in
                    // coordenates_to_be_recruited_coord (calcolato sopra da
                    // verifyAndDecryptReq()), non si rilegge piu' un campo in
                    // chiaro dal pacchetto.

                    //////////////////////////////////////////////////////////////////////
                    // Create the key for the m/p

                    std::string key = src_string;

                    if ((src == source) || (src == x2ppp_address)) {
                        EV_INFO << "Req msg dropped. This message returned to the original creator.\n";

                        //delete packet;
                        delete fhp;
                        delete msg;
                        return;

                    }

                    ///////////// Check if this packet has already been received with the same sequence number
                    if (receivedPackets[key].find(msgsequencenumber) != receivedPackets[key].end()) {
                        EV_INFO << "Duplicate Req msg detected Source: " << src_string << ", Destination: " << dst_string << ", Sequence number: " << msgsequencenumber << "). Dropping packet.\n";
                        //delete packet;
                        delete fhp;
                        delete msg;
                        return;
                    }

                    // Store the source-destination pair and sequence number
                    receivedPackets[key].insert(msgsequencenumber);


                    ///// added learn all possible routes avoiding duplicate messages that generate loops ////
                    size_t size = recHello->getHopAddressesArraySize();
                    Ipv4Address hopAddresses[size];
                    bool repeated = false;
                    for (int i = 0; i < recHello->getHopAddressesArraySize(); ++i) {
                        Ipv4Address address = recHello->getHopAddresses(i);
                        if (address == source) {
                            repeated = true;
                            break;
                        }
                    }

                    if (repeated == false) {
                        // added to save the destination (source of Fant), its next hop, and its number of hops
                        double pheromoneValue = 0.0;

                        // update table
                        bool entryExists = false;
                        for (auto &entry : routingTable) {
                            if (entry.destinationAddress == src_string && entry.nextHop == nxt_string) {
                                entry.pheromone += pheromoneValue; // Update pheromone value
                                EV_INFO << "Updated pheromone value for destination: " << entry.destinationAddress
                                        << ", Next Hop: " << entry.nextHop
                                        << ", New Pheromone: " << entry.pheromone << "\n";
                                entryExists = true;
                                break;
                            }
                        }

                        if (!entryExists) {
                            // Add the new entry to the table
                            RoutingTableEntry newEntry = {src_string, nxt_string, pheromoneValue};
                            routingTable.push_back(newEntry);
                            EV_INFO << "Added new entry to routing table: Destination: " << src_string << ", Next Hop: " << nxt_string << ", Pheromone: " << pheromoneValue << "\n";
                        }
                    }

                    ///////////// Update the Status table to deactivate recruited UAV //////////////////

                    std::string dst_req_string = recHello->getDstAddress().str();
                    // Check if the src_string already exists in the statusTable
                    auto it = std::find_if(statusTable.begin(), statusTable.end(),
                                           [&dst_req_string](const StatusEntry& entry) {
                                               return entry.destinationAddress == dst_req_string;
                                           });

                    if (it != statusTable.end()) {
                        // Update existing entry
                        it->allowed_accept_request = false;
                        EV_INFO << "Updated entry in status table: Host: " << src_string << "\n";
                    }

                    ////////////////// Add the new entry to the routing table (destination, gateway, sequence number)
                    ////////////////// Used to route the Bant when comes back to the originator

                    RoutingTableAntEntry newEntry = {src_string, dst_string, msgsequencenumber};
                    routingTableAnt.push_back(newEntry);



                    //////////////////////////////////////////

                    if ((allowed_accept_request == true) && ((dst == source) || (dst == x2ppp_address))) {
                        EV_INFO << "PETICION" << endl;
                        double timer = 1;
                        moveTimer = new cMessage("moveTimer");
                        scheduleAfter(timer , moveTimer); // Schedule the timer to trigger every second
                        allowed_accept_request = false;
                        // MODIFICATO per sicurezza: la coordinata arriva gia' decifrata
                        // come oggetto Coord (coordenates_to_be_recruited_coord); la
                        // riconvertiamo nello stesso formato stringa "(x, y, z)" che
                        // moveUav() si aspetta gia', cosi' non serve toccare moveUav().
                        std::stringstream ssCoord;
                        ssCoord << "(" << coordenates_to_be_recruited_coord.x << ", "
                                << coordenates_to_be_recruited_coord.y << ", "
                                << coordenates_to_be_recruited_coord.z << ")";
                        coordenates_to_be_recruited = ssCoord.str();

                        //////// code to update the energy /////

                        auto it = std::find_if(statusTable.begin(), statusTable.end(),
                                               [&src_string](const StatusEntry& entry) {
                                                   return entry.destinationAddress == src_string;
                                               });

                        if (it != statusTable.end()) {
                            double D = it->distance;
                            double E = node_energy;
                            double T_eff;
                            double Energy_consumption;

                            if (E>70) {
                                T_eff = D/17;
                                Energy_consumption = 720;
                            }
                            else if (E>40) {
                                T_eff = D/10;
                                Energy_consumption = 840;
                            }
                            else {
                                T_eff = D/3;
                                Energy_consumption = 1200;
                            }

                            int total_energy = T_eff * Energy_consumption;
                            emit(arrivalSignal3, static_cast<long>(total_energy));

                        }

                        //////////


                        //////////

                    }
                    else {

                        auto packet = new Packet("Request");
                        auto addressReq = packet->addTag<L3AddressReq>();
                        addressReq->setDestAddress(L3Address(broadcast_addr));
                        addressReq->setSrcAddress(interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
                        packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
                        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        recHello->setNextAddress(source);
                        numHops++;
                        recHello->setHopdistance(numHops);
                        recHello->setSrcAddress(src);
                        recHello->setDstAddress(dst);
                        recHello->setSequencenumber(msgsequencenumber);
                        recHello->appendHopAddresses(source);
                        double waitTime = intuniform(1, 100);
                        waitTime = waitTime / 10000;
                        EV_DETAIL << "Forwarding Req " << endl;
                        packet->insertAtBack(recHello);
                        packet->setKind(REQ_PACKET); // Set the packet type
                        sendDelayed(packet, waitTime, "ipOut");
                        total_manet_packets++;
                        total_req_packets++;

                        packet = nullptr;

                    }

                    auto fant_message = makeShared<FantM2>();
                    fant_message->setChunkLength(b(128));
                    fant_message->setSrcAddress(source);
                    fant_message->setDstAddress(broadcast_addr);
                    sequencenumber += 1;
                    fant_message->setSequencenumber(sequencenumber);
                    fant_message->setNextAddress(source);
                    fant_message->setHopdistance(1);
                    fant_message->appendHopAddresses(source);

                    // firma Ed25519 del FANT prima dell'invio
                    signFant(fant_message);
                    auto packet = new Packet("Fant", fant_message);
                    auto addressReq = packet->addTag<L3AddressReq>();
                    packet->setKind(FANT_PACKET);
                    addressReq->setDestAddress(L3Address(broadcast_addr));
                    addressReq->setSrcAddress(L3Address(source));

                    packet->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                    packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                    double waitTime1 = 2;
                    sendDelayed(packet, waitTime1, "ipOut");
                    total_manet_packets++;
                    total_req_packets++;

                    fant_message = nullptr;
                    packet = nullptr;
                    fhp = nullptr;
                }

            }
            else {
            // Unknown or unexpected packet type, handle accordingly
            delete msg;
            return;
            }
        }
        else if (num_80211 == 2){
            // Differentiating between FANT and BANT
            if (msg->getKind() == FANT_PACKET) {


                ForwardEntry *fhp = nullptr;
                // --- Sicurezza: verifica firma del FANT come primo passo.
                if (!verifyFant(check_and_cast<Packet *>(msg)->peekData<FantM2>())) {
                    delete msg;
                    return;
                }

                auto recHello1 = staticPtrCast<FantM2>(check_and_cast<Packet *>(msg)->peekData<FantM2>()->dupShared());
                auto recHello2 = staticPtrCast<FantM2>(check_and_cast<Packet *>(msg)->peekData<FantM2>()->dupShared());

                fhp = new ForwardEntry();
                fhp->hello = check_and_cast<Packet *>(msg->dup());

                if (msg->arrivedOn("ipIn")) {

                    Ipv4Address source = wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    //------
                    Ipv4Address source_a = wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    Ipv4Address source_b = wirelessInterfaces[1]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    //-------
                    std::string source_string = source.str();

                    std::string source_string_a = source_a.str();
                    std::string source_string_b = source_b.str();

                    // Reading Fant fields
                    Ipv4Address src;
                    Ipv4Address dst;
                    unsigned int msgsequencenumber;
                    int numHops;
                    Ipv4Address next;

                    src = recHello1->getSrcAddress();
                    dst = recHello1->getDstAddress();
                    msgsequencenumber = recHello1->getSequencenumber();
                    next = recHello1->getNextAddress();
                    numHops = recHello1->getHopdistance();

                    EV_DETAIL << "========================================== new processing ====================================================" << endl;
                    EV_DETAIL << "FANT arrives, Source: " << src << " Destination: " << dst << " Sequence number: " << msgsequencenumber << " Hops number: " << numHops << endl;

                    std::string src_string = recHello1->getSrcAddress().str();
                    std::string dst_string = recHello1->getNextAddress().str();
                    std::string nxt_string = recHello1->getNextAddress().str();

                    //////////////////////////////////////////////////////////////////////
                    // Create the key for the map

                    std::string key = src_string;

                    if ((src == source_a) || (src == source_b) || (src == x2ppp_address)) {
                        EV_INFO << "Fant msg dropped. This message returned to the original creator.\n";

                        delete fhp;
                        delete msg;
                        return;

                    }

                    ///// added learn all possible routes avoiding duplicate messages that generate loops ////
                    size_t size = recHello1->getHopAddressesArraySize();
                    Ipv4Address hopAddresses[size];
                    bool repeated = false;
                    for (int i = 0; i < recHello1->getHopAddressesArraySize(); ++i) {
                        Ipv4Address address = recHello1->getHopAddresses(i);
                        if (address == source_a || address == source_b) {
                            repeated = true;
                            break;
                        }
                    }

                    if (repeated == false) {
                        // added to save the destination (source of Fant), its next hop, and its number of hops
                        double pheromoneValue = 100.0 / numHops;

                        // update table
                        bool entryExists = false;
                        for (auto &entry : routingTable) {
                            if (entry.destinationAddress == src_string && entry.nextHop == nxt_string) {
                                entry.pheromone += pheromoneValue; // Update pheromone value
                                EV_INFO << "Updated pheromone value for destination: " << entry.destinationAddress
                                        << ", Next Hop: " << entry.nextHop
                                        << ", New Pheromone: " << entry.pheromone << "\n";
                                entryExists = true;
                                break;
                            }
                        }
                        if (!entryExists) {
                            // Add the new entry to the table
                            RoutingTableEntry newEntry = {src_string, nxt_string, pheromoneValue};
                            routingTable.push_back(newEntry);
                            EV_INFO << "Added new entry to routing table: Destination: " << src_string << ", Next Hop: " << nxt_string << ", Pheromone: " << pheromoneValue << "\n";
                        }
                    }

                    ///////////// Check if this packet has already been received with the same sequence number
                    if (receivedPackets[key].find(msgsequencenumber) != receivedPackets[key].end()) {
                        EV_INFO << "Duplicate Fant msg detected (Source: " << src_string << ", Destination: " << dst_string << ", Sequence number: " << msgsequencenumber << "). Dropping packet.\n";
                        delete fhp;
                        delete msg;
                        return;
                    }

                    // Store the source-destination pair and sequence number
                    receivedPackets[key].insert(msgsequencenumber);

                    ////////////////// Add the new entry to the routing table (destination, gateway, sequence number)
                    ////////////////// Used to route the Bant when comes back to the originator

                    RoutingTableAntEntry newEntry = {src_string, dst_string, msgsequencenumber};
                    routingTableAnt.push_back(newEntry);

                    ///////////////// Processing when Unicast Fant arrives to destination ///////////////
                    if (dst == source_a || dst == source_b || dst == x2ppp_address) {

                        //////// get gateway for bant //////////////////
                        Ipv4Address gateway;
                        bool entryExists = false;
                        for (auto &entry : routingTableAnt) {
                            if (entry.destinationAddress == src_string && entry.sequenceNumber == msgsequencenumber) {
                                gateway = Ipv4Address(entry.gateway.c_str());
                                entryExists = true;
                                break;
                            }
                        }
                        /////////////////////////////////////////////////

                        if (entryExists==false){
                            return;
                        }
                        else {
                            //////////// sent to wlan0 /////////
                            // MODIFICATO per sicurezza: cifratura + firma centralizzate in
                            // buildSecureBant(), stesso schema usato altrove.
                            auto bant_packet = buildSecureBant(src, gateway, msgsequencenumber, source_a);
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();
                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq->setSrcAddress(source_a);

                            bant_packet->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                            bant_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            double waitTime = intuniform(1, 100);
                            waitTime = waitTime / 10000;
                            sendDelayed(bant_packet, waitTime, "ipOut");
                            total_manet_packets++;

                            //////////// sent to wlan1 /////////
                            auto bant_packet1 = buildSecureBant(src, gateway, msgsequencenumber, source_a);
                            auto bantAddressReq1 = bant_packet1->addTag<L3AddressReq>();
                            bantAddressReq1->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq1->setSrcAddress(source_b);

                            bant_packet1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                            bant_packet1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            double waitTime1 = intuniform(1, 100);
                            waitTime1 = waitTime1 / 10000;
                            sendDelayed(bant_packet1, waitTime1, "ipOut");
                            total_manet_packets++;

                            // Clean up
                            bant_packet = nullptr;
                            bant_packet1 = nullptr;


                        }
                        //////////////////////////////////////////

                        fhp = nullptr;


                    }

                    else {

                        auto packet1 = new Packet("Fant");
                        auto addressReq1 = packet1->addTag<L3AddressReq>();
                        addressReq1->setDestAddress(L3Address(broadcast_addr));
                        addressReq1->setSrcAddress(L3Address(source_a));
                        packet1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                        packet1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        auto packet2 = new Packet("Fant");
                        auto addressReq2 = packet2->addTag<L3AddressReq>();
                        addressReq2->setDestAddress(L3Address(broadcast_addr));
                        addressReq2->setSrcAddress(L3Address(source_b));
                        packet2->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                        packet2->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet2->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        ///////////// sent to wlan0 ////////////
                        recHello1->setNextAddress(source_a);
                        numHops++;
                        recHello1->setHopdistance(numHops);
                        recHello1->setSrcAddress(src);
                        recHello1->setDstAddress(dst);
                        recHello1->setSequencenumber(msgsequencenumber);
                        recHello1->appendHopAddresses(source_a);
                        double waitTime = intuniform(1, 100);
                        waitTime = waitTime / 10000;
                        EV_DETAIL << "Forwarding Fant " << endl;
                        packet1->insertAtBack(recHello1);
                        packet1->setKind(FANT_PACKET); // Set the packet type
                        sendDelayed(packet1, waitTime, "ipOut");
                        total_manet_packets++;


                        ///////////// sent to wlan1 ////////////
                        recHello2->setNextAddress(source_a);
                        recHello2->setHopdistance(numHops);
                        recHello2->setSrcAddress(src);
                        recHello2->setDstAddress(dst);
                        recHello2->setSequencenumber(msgsequencenumber);
                        recHello2->appendHopAddresses(source_a);
                        double waitTime2 = intuniform(1, 100);
                        waitTime2 = waitTime2 / 10000;
                        EV_DETAIL << "Forwarding Fant " << endl;
                        packet2->insertAtBack(recHello2);
                        packet2->setKind(FANT_PACKET); // Set the packet type
                        sendDelayed(packet2, waitTime2, "ipOut");
                        total_manet_packets++;

                        //////// get gateway for bant //////////////////
                        Ipv4Address gateway;
                        bool entryExists = false;
                        for (auto &entry : routingTableAnt) {
                            if (entry.destinationAddress == src_string && entry.sequenceNumber == msgsequencenumber) {
                                gateway = Ipv4Address(entry.gateway.c_str());
                                entryExists = true;
                                // entryExists = true;
                                break;
                            }
                        }
                        /////////////////////////////////////////////////

                        if (entryExists==false){
                            return;
                        }
                        else {
                            //////////// sent to wlan0 /////////
                            // MODIFICATO per sicurezza: cifratura + firma centralizzate in
                            // buildSecureBant(), stesso schema usato sopra.
                            auto bant_packet = buildSecureBant(src, gateway, msgsequencenumber, source_a);
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();
                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq->setSrcAddress(source_a);

                            bant_packet->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                            bant_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            double waitTime = intuniform(1, 100);
                            waitTime = waitTime / 10000;
                            sendDelayed(bant_packet, waitTime, "ipOut");
                            total_manet_packets++;

                            //////////// sent to wlan1 /////////
                            auto bant_packet1 = buildSecureBant(src, gateway, msgsequencenumber, source_a);
                            auto bantAddressReq1 = bant_packet1->addTag<L3AddressReq>();
                            bantAddressReq1->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq1->setSrcAddress(source_b);

                            bant_packet1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                            bant_packet1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            double waitTime1 = intuniform(1, 100);
                            waitTime1 = waitTime1 / 10000;
                            sendDelayed(bant_packet1, waitTime1, "ipOut");
                            total_manet_packets++;

                            // Clean up
                            bant_packet = nullptr;
                            bant_packet1 = nullptr;


                        }
                        //////////////////////////////////////////

                        packet1 = nullptr;
                        packet2 = nullptr;

                        fhp = nullptr;

                        //////////////////////////////////////////
                    }
                }
            }

            else if (msg->getKind() == BANT_PACKET) {

                auto recHelloConst = check_and_cast<Packet *>(msg)->peekData<BantM2>();

                // --- Aggiunto per sicurezza: stesso schema del ramo a interfaccia
                // singola. Verifica firma + decifratura come primissimo passo.
                double energy, throughput, max_throughput;
                Coord node_position_neighbor;
                int cluster_id_;
                bool allowed_accept_request_node;
                if (!verifyAndDecryptBant(recHelloConst, energy, throughput, node_position_neighbor,
                                           max_throughput, cluster_id_, allowed_accept_request_node)) {
                    delete msg;
                    return;
                }

                auto recHello1 = staticPtrCast<BantM2>(recHelloConst->dupShared());
                auto recHello2 = staticPtrCast<BantM2>(recHelloConst->dupShared());

                ForwardEntry *fhp = nullptr;
                fhp = new ForwardEntry();
                fhp->hello = check_and_cast<Packet *>(msg->dup());

                if (msg->arrivedOn("ipIn")) {

                    Ipv4Address source = interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    Ipv4Address source_a = wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    Ipv4Address source_b = wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();

                    std::string source_string = source.str();
                    std::string source_string_a = source_a.str();
                    std::string source_string_b = source_b.str();

                    // Reading Fant fields
                    Ipv4Address src;
                    Ipv4Address dst;
                    unsigned int msgsequencenumber;
                    int numHops;
                    Ipv4Address next;
                    Ipv4Address gateway;

                    src = recHello1->getSrcAddress();
                    dst = recHello1->getDstAddress();
                    msgsequencenumber = recHello1->getSequencenumber();
                    next = recHello1->getNextAddress();
                    numHops = recHello1->getHopdistance();
                    gateway = recHello1->getGateway();
                    // "hops" arriva dal campo hopdistance in chiaro (vedi nota nel
                    // ramo a interfaccia singola): concettualmente lo stesso dato.
                    double hops = static_cast<double>(numHops);

                    std::string src_string = recHello1->getSrcAddress().str();
                    std::string dst_string = recHello1->getNextAddress().str();
                    std::string nxt_string = recHello1->getNextAddress().str();
                    std::string gateway_string = recHello1->getGateway().str();
                    std::string destination_string = recHello1->getDstAddress().str();

                    EV_DETAIL << "========================================== new processing ====================================================" << endl;
                    EV_DETAIL << "BANT arrives, Source: " << src << " Destination: " << dst << "Gateway: " << gateway_string << " Sequence number: " << msgsequencenumber << " Hops number: " << numHops << endl;

                    ////////////// Ant CONTROL FOR BANT (RETURN TO ORIGINATOR ADDRESS) /////////////////
                    Ipv4Address next_gateway;
                    bool entryExists1 = false;

                    if (gateway_string == source_string_a || gateway_string == source_string_b){
                        for (auto &entry : routingTableAnt) {
                            if (entry.destinationAddress == destination_string && entry.sequenceNumber == msgsequencenumber) {
                                next_gateway = Ipv4Address(entry.gateway.c_str());
                                entryExists1 = true;
                                break;
                            }
                        }
                    }

                    ///////////////////////////////////////////////////////////////////////////////////

                    if ((gateway == source_a) || (gateway == source_b) || (dst == source_a) || (dst == source_b) || (dst == x2ppp_address)) {

                        /////// Add the status of the Bant generateor address to monitor table ///////////////
                        // MODIFICATO per sicurezza: energy/throughput/node_position_neighbor/
                        // max_throughput/cluster_id_/allowed_accept_request_node arrivano gia'
                        // decifrati da verifyAndDecryptBant() in cima al blocco.

                        double distance = calculateEuclideanDistance(node_position_neighbor, node_position);

                        // Check if the src_string already exists in the statusTable
                        auto it = std::find_if(statusTable.begin(), statusTable.end(),
                                               [&src_string](const StatusEntry& entry) {
                                                   return entry.destinationAddress == src_string;
                                               });

                        if (it != statusTable.end()) {
                            // Update existing entry
                            it->energy = energy;
                            it->throughput = throughput;
                            it->distance = distance;
                            it->hops = hops;
                            it->max_throughput = max_throughput;
                            it->cluster_id = cluster_id_;
                            it->allowed_accept_request = allowed_accept_request_node;
                            EV_INFO << "Updated entry in monitor table: Host: " << src_string
                                    << ", Energy: " << energy << ", Throughput: " << throughput
                                    << ", Distance: " << distance << ", Hops: " << hops << "\n";
                        } else {
                            // Add new entry
                            StatusEntry newEntry = {src_string, energy, throughput, distance, hops, max_throughput, cluster_id_, allowed_accept_request_node};
                            statusTable.push_back(newEntry);
                            EV_INFO << "Added new entry to monitor table: Host: " << src_string
                                    << ", Energy: " << energy << ", Throughput: " << throughput
                                    << ", Distance: " << distance << ", Hops: " << hops << "\n";
                        }

                        /////////////////////////////////////////////////////////////////////////////////////
                        ///////// Save routing table Ant ////////////////////////////////////
                        double pheromoneValue = 100.0 / numHops;

                        /////////// routing table update /////////////
                        bool entryExists = false;

                        for (auto &entry : routingTable) {
                            if (entry.destinationAddress == src_string && entry.nextHop == nxt_string) {
                                entry.pheromone += pheromoneValue; // Update pheromone value
                                EV_INFO << "Updated pheromone value for destination: " << entry.destinationAddress
                                        << ", Next Hop: " << entry.nextHop
                                        << ", New Pheromone: " << entry.pheromone << "\n";
                                entryExists = true;
                                break;
                            }
                        }

                        if (!entryExists) {
                            // Add the new entry to the routing table
                            RoutingTableEntry newEntry = {src_string, nxt_string, pheromoneValue};
                            routingTable.push_back(newEntry);
                            EV_INFO << "Added new entry to routing table: Destination: " << src_string << ", Next Hop: " << nxt_string << ", Pheromone: " << pheromoneValue << "\n";
                        }

                        /////////////////////////////////////////////////////////

                        /////////////////////////////////////////////////////////

                        // Print the routing table after updating
                        EV_INFO << "== Routing table:\n";
                        for (const auto& entry : routingTable) {
                            EV_INFO << "Destination: " << entry.destinationAddress
                                    << ", Next Hop: " << entry.nextHop
                                    << ", Pheromone: " << entry.pheromone << "\n";
                        }
                    }

                    /////////////////////////// forward message ////////////////////

                    if (entryExists1 && (gateway == source_a || gateway == source_b) && (dst != source_a || dst != source_b)) {

                        auto packet1 = new Packet("Bant");
                        auto addressReq1 = packet1->addTag<L3AddressReq>();
                        addressReq1->setDestAddress(L3Address(broadcast_addr));
                        addressReq1->setSrcAddress(L3Address(source_a));
                        packet1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                        packet1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        auto packet2 = new Packet("Bant");
                        auto addressReq2 = packet2->addTag<L3AddressReq>();
                        addressReq2->setDestAddress(L3Address(broadcast_addr));
                        addressReq2->setSrcAddress(L3Address(source_b));
                        packet2->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                        packet2->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet2->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        ////////// send to wlan0 ////////////////
                        recHello1->setNextAddress(source_a);
                        numHops++;
                        recHello1->setHopdistance(numHops);
                        recHello1->setGateway(next_gateway);
                        double waitTime = intuniform(1, 100);
                        waitTime = waitTime / 10000;
                        EV_DETAIL << "Forwarding Bant " << endl;
                        packet1->insertAtBack(recHello1);
                        packet1->setKind(BANT_PACKET);  // Set the correct packet type
                        sendDelayed(packet1, waitTime, "ipOut");
                        total_manet_packets++;

                        ////////// send to wlan1 ////////////////
                        recHello2->setNextAddress(source_b);
                        recHello2->setHopdistance(numHops);
                        recHello2->setGateway(next_gateway);
                        double waitTime2 = intuniform(1, 100);
                        waitTime2 = waitTime2 / 10000;
                        EV_DETAIL << "Forwarding Bant " << endl;
                        packet2->insertAtBack(recHello2);
                        packet2->setKind(BANT_PACKET);  // Set the correct packet type
                        sendDelayed(packet2, waitTime2, "ipOut");
                        total_manet_packets++;

                        packet1 = nullptr;
                        packet2 = nullptr;

                        fhp = nullptr;
                    }
                    else {
                        delete msg;
                        return;
                    }

                }
            }
            else if (msg->getKind() == REQ_PACKET) {
                total_req_packets++;

                auto recHelloConstReq = check_and_cast<Packet *>(msg)->peekData<ReqM2>();

                // --- Aggiunto per sicurezza: stesso schema usato ovunque altrove.
                // Questo era l'ultimo punto del file rimasto privo del controllo.
                Coord coordenates_to_be_recruited_coord_dual;
                bool allowed_accept_request_sender_dual;
                if (!verifyAndDecryptReq(recHelloConstReq, coordenates_to_be_recruited_coord_dual,
                                          allowed_accept_request_sender_dual)) {
                    delete msg;
                    return;
                }

                ForwardEntry *fhp = nullptr;
                auto recHello1 = staticPtrCast<ReqM2>(recHelloConstReq->dupShared());
                auto recHello2 = staticPtrCast<ReqM2>(recHelloConstReq->dupShared());

                fhp = new ForwardEntry();
                fhp->hello = check_and_cast<Packet *>(msg->dup());

                if (msg->arrivedOn("ipIn")) {

                    Ipv4Address source = interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    Ipv4Address source_a = wirelessInterfaces[0]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
                    Ipv4Address source_b = wirelessInterfaces[1]->getProtocolData<Ipv4InterfaceData>()->getIPAddress();

                    std::string source_string = source.str();
                    std::string source_string_a = source_a.str();
                    std::string source_string_b = source_b.str();

                    // Reading Fant fields
                    Ipv4Address src;
                    Ipv4Address dst;
                    unsigned int msgsequencenumber;
                    int numHops;
                    Ipv4Address next;

                    src = recHello1->getSrcAddress();
                    dst = recHello1->getDstAddress();
                    msgsequencenumber = recHello1->getSequencenumber();
                    next = recHello1->getNextAddress();
                    numHops = recHello1->getHopdistance();

                    EV_DETAIL << "========================================== new processing ====================================================" << endl;
                    EV_DETAIL << "REQ arrives, Source: " << src << " Destination: " << dst << " Sequence number: " << msgsequencenumber << " Hops number: " << numHops << endl;

                    std::string src_string = recHello1->getSrcAddress().str();
                    std::string dst_string = recHello1->getNextAddress().str();
                    std::string nxt_string = recHello1->getNextAddress().str();

                    //////////////////////////////////////////////////////////////////////
                    // Create the key for the m/p

                    std::string key = src_string;

                    if ((src == source_a) || (src == source_b) || (src == x2ppp_address)) {
                        EV_INFO << "Req msg dropped. This message returned to the original creator.\n";

                        delete fhp;
                        delete msg;
                        return;

                    }

                    ///// added learn all possible routes avoiding duplicate messages that generate loops ////
                    size_t size = recHello1->getHopAddressesArraySize();
                    Ipv4Address hopAddresses[size];
                    bool repeated = false;
                    for (int i = 0; i < recHello1->getHopAddressesArraySize(); ++i) {
                        Ipv4Address address = recHello1->getHopAddresses(i);
                        if (address == source_a || address == source_b) {
                            repeated = true;
                            break;
                        }
                    }

                    if (repeated == false) {
                        // added to save the destination (source of Fant), its next hop, and its number of hops
                        double pheromoneValue = 0.0;

                        // update table
                        bool entryExists = false;
                        for (auto &entry : routingTable) {
                            if (entry.destinationAddress == src_string && entry.nextHop == nxt_string) {
                                entry.pheromone += pheromoneValue; // Update pheromone value
                                EV_INFO << "Updated pheromone value for destination: " << entry.destinationAddress
                                        << ", Next Hop: " << entry.nextHop
                                        << ", New Pheromone: " << entry.pheromone << "\n";
                                entryExists = true;
                                break;
                            }
                        }
                        if (!entryExists) {
                            // Add the new entry to the table
                            RoutingTableEntry newEntry = {src_string, nxt_string, pheromoneValue};
                            routingTable.push_back(newEntry);
                            EV_INFO << "Added new entry to routing table: Destination: " << src_string << ", Next Hop: " << nxt_string << ", Pheromone: " << pheromoneValue << "\n";
                        }
                    }

                    ///////////// Update the Status table to deactivate recruited UAV //////////////////

                    std::string dst_req_string = recHello1->getDstAddress().str();
                    // Check if the src_string already exists in the statusTable
                    auto it = std::find_if(statusTable.begin(), statusTable.end(),
                                           [&dst_req_string](const StatusEntry& entry) {
                                               return entry.destinationAddress == dst_req_string;
                                           });

                    if (it != statusTable.end()) {
                        // Update existing entry
                        it->allowed_accept_request = false;
                        EV_INFO << "Updated entry in status table: Host: " << src_string << "\n";
                    }

                    ///////////// Check if this packet has already been received with the same sequence number
                    if (receivedPackets[key].find(msgsequencenumber) != receivedPackets[key].end()) {
                        EV_INFO << "Duplicate Req msg detected Source: " << src_string << ", Destination: " << dst_string << ", Sequence number: " << msgsequencenumber << "). Dropping packet.\n";

                        delete fhp;
                        delete msg;
                        return;
                    }

                    // Store the source-destination pair and sequence number
                    receivedPackets[key].insert(msgsequencenumber);

                    ////////////////// Add the new entry to the routing table (destination, gateway, sequence number)
                    ////////////////// Used to route the Bant when comes back to the originator

                    RoutingTableAntEntry newEntry = {src_string, dst_string, msgsequencenumber};
                    routingTableAnt.push_back(newEntry);

                    ///////////////// Processing when Unicast Fant arrives to destination ///////////////


                    if ((allowed_accept_request == true) && ((dst == source_a) || (dst == source_b) || (dst == x2ppp_address))) {
                        EV_INFO << "PETICION" << endl;
                        double timer = 1;
                        moveTimer = new cMessage("moveTimer");
                        scheduleAfter(timer , moveTimer); // Schedule the timer to trigger every second
                        allowed_accept_request = false;
                    }
                    else {
                        auto packet1 = new Packet("Request");
                        auto addressReq1 = packet1->addTag<L3AddressReq>();
                        addressReq1->setDestAddress(L3Address(broadcast_addr));
                        addressReq1->setSrcAddress(L3Address(source_a));
                        packet1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                        packet1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        auto packet2 = new Packet("Request");
                        auto addressReq2 = packet2->addTag<L3AddressReq>();
                        addressReq2->setDestAddress(L3Address(broadcast_addr));
                        addressReq2->setSrcAddress(L3Address(source_b));
                        packet2->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                        packet2->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                        packet2->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                        ////////////// sent to wlan0 ////////////
                        recHello1->setNextAddress(source_a);
                        numHops++;
                        recHello1->setHopdistance(numHops);
                        recHello1->setSrcAddress(src);
                        recHello1->setDstAddress(dst);
                        recHello1->setSequencenumber(msgsequencenumber);
                        recHello1->appendHopAddresses(source_a);
                        double waitTime = intuniform(1, 100);
                        waitTime = waitTime / 10000;
                        EV_DETAIL << "Forwarding Req " << endl;
                        packet1->insertAtBack(recHello1);
                        packet1->setKind(REQ_PACKET); // Set the packet type
                        sendDelayed(packet1, waitTime, "ipOut");
                        total_manet_packets++;
                        total_req_packets++;

                        ////////////// sent to wlan1 ////////////
                        recHello2->setNextAddress(source_a);
                        recHello2->setHopdistance(numHops);
                        recHello2->setSrcAddress(src);
                        recHello2->setDstAddress(dst);
                        recHello2->setSequencenumber(msgsequencenumber);
                        recHello2->appendHopAddresses(source_a);
                        double waitTime2 = intuniform(1, 100);
                        waitTime2 = waitTime2 / 10000;
                        EV_DETAIL << "Forwarding Req " << endl;
                        packet2->insertAtBack(recHello2);
                        packet2->setKind(REQ_PACKET); // Set the packet type
                        sendDelayed(packet2, waitTime2, "ipOut");
                        total_manet_packets++;
                        total_req_packets++;

                        packet1 = nullptr;
                        packet2 = nullptr;
                    }

                    auto fant_message_1 = makeShared<FantM2>();
                    fant_message_1->setChunkLength(b(128));
                    fant_message_1->setSrcAddress(source);
                    fant_message_1->setDstAddress(broadcast_addr);
                    sequencenumber += 1;
                    fant_message_1->setSequencenumber(sequencenumber);
                    fant_message_1->setNextAddress(source);
                    fant_message_1->setHopdistance(1);
                    fant_message_1->appendHopAddresses(source);

                    // firma Ed25519 del FANT prima dell'invio
                    signFant(fant_message_1);
                    auto packet_1 = new Packet("Fant", fant_message_1);
                    auto addressReq_1 = packet_1->addTag<L3AddressReq>();
                    packet_1->setKind(FANT_PACKET);
                    addressReq_1->setDestAddress(L3Address(broadcast_addr));
                    addressReq_1->setSrcAddress(L3Address(source_a));

                    packet_1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                    packet_1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                    packet_1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                    double waitTime_1 = 2;
                    sendDelayed(packet_1, waitTime_1, "ipOut");


                    auto fant_message_2 = makeShared<FantM2>();
                    fant_message_2->setChunkLength(b(128));
                    fant_message_2->setSrcAddress(source);
                    fant_message_2->setDstAddress(broadcast_addr);
                    sequencenumber += 1;
                    fant_message_2->setSequencenumber(sequencenumber);
                    fant_message_2->setNextAddress(source);
                    fant_message_2->setHopdistance(1);
                    fant_message_2->appendHopAddresses(source);

                    // firma Ed25519 del FANT prima dell'invio
                    signFant(fant_message_2);
                    auto packet_2 = new Packet("Fant", fant_message_2);
                    auto addressReq_2 = packet_2->addTag<L3AddressReq>();
                    packet_2->setKind(FANT_PACKET);
                    addressReq_2->setDestAddress(L3Address(broadcast_addr));
                    addressReq_2->setSrcAddress(L3Address(source_a));

                    packet_2->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                    packet_2->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                    packet_2->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                    double waitTime_2 = 2;
                    sendDelayed(packet_2, waitTime_2, "ipOut");

                    total_manet_packets++;
                    total_req_packets++;

                    fant_message_1 = nullptr;
                    packet_1 = nullptr;
                    fant_message_2 = nullptr;
                    packet_2 = nullptr;
                    fhp = nullptr;
                    fhp = nullptr;
                }

            }
            else {
            // Unknown or unexpected packet type, handle accordingly
            delete msg;
            return;
            }
        }
    }
}

void Ant2::updatePheromoneValues()
{
    J energylevel = energyManagement->getEstimatedEnergyCapacity();
    double residualEnergy = energylevel.get();
    double charge_status = (int)((residualEnergy/nominalCapacity) * 100);
    EV_DETAIL << "Energy level is: " << charge_status << "%" << endl;

    if (charge_status <= 15.0 && allowed_send_request == true) {
        allowed_accept_request = false;

        // MODIFICATO per sicurezza: cifratura + firma centralizzate in buildSecureReq().
        Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
        sequencenumber += 1;
        Coord selfPosition = mobility->getCurrentPosition();
        node_position = selfPosition;
        auto packet = buildSecureReq(source, sequencenumber, source, node_position, false);
        auto addressReq = packet->addTag<L3AddressReq>();
        addressReq->setDestAddress(L3Address(broadcast_addr));
        addressReq->setSrcAddress(L3Address(source));

        packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

        // broadcast the fant to other nodes
        send(packet, "ipOut");
        total_manet_packets++;
        packet = nullptr;

        allowed_send_request = false;
    }

    if (charge_status <= 15.0) {
        return;
    }

    if (charge_status <= 10.0) {
        moveUav_charge();
        EV << "Energy is depleted, not sending Hello message" << endl;
        if (event -> isScheduled()) {
            cancelEvent(event);
        }
        if (pheromoneUpdateTimer -> isScheduled()) {
            cancelEvent(pheromoneUpdateTimer);
        }
        if (throughputUpdateTimer -> isScheduled()) {
            cancelEvent(throughputUpdateTimer);
        }
        return;
    }

    double p = 0.2; // Pheromone decay rate

    for (auto &entry : routingTable) {
        entry.pheromone = (1 - p) * entry.pheromone; // Update the pheromone value
        EV_INFO << "Updated pheromone for Destination: " << entry.destinationAddress
                << ", Next Hop: " << entry.nextHop
                << ", New Pheromone: " << entry.pheromone << "\n";
    }

    EV_DETAIL << "====== Node status ======" << endl;

    for (const auto& entry : statusTable) {
        EV_INFO << "Host: " << entry.destinationAddress
                  << ", Energy: " << entry.energy
                  << ", Throughput: " << entry.throughput
                  << ", Distance: " << entry.distance
                  << ", Hops: " << entry.hops << "\n";
    }

    // Remove entries with pheromone value less than "x.xxx"

    EV_DETAIL << "=RAMY" << endl;
    for (const auto& entry : routingTable) {
        EV_INFO << "Host: " << entry.destinationAddress
                  << ", Destination: " << entry.nextHop
                  << ", Pheromone: " << entry.pheromone << "\n";
    }

    //removeLowPheromoneEntries();
    computeBestNextHops();

    for (const auto& entry : routingTable) {
        EV_INFO << "Destination: " << entry.destinationAddress
                << ", Next Hop: " << entry.nextHop
                << ", Pheromone: " << entry.pheromone << "\n";
    }
}

void Ant2::removeLowPheromoneEntries() {
    EV_INFO << "=UP" << endl;

    for (auto &entry : routingTable) {
        if (entry.pheromone < 1) { //10
            Ipv4Address destAddress(entry.destinationAddress.c_str());

            // Vector to store matching routes to delete
            std::vector<Ipv4Route*> routesToDelete;

            // Iterate over the routing table to find all routes to the destination
            for (int i = 0; i < rt->getNumRoutes(); ++i) {
                Ipv4Route* route_delete = rt->getRoute(i);
                if (route_delete && route_delete->getDestination() == destAddress) {
                    routesToDelete.push_back(route_delete);
                }
            }

            // Delete all matching routes
            for (Ipv4Route* route : routesToDelete) {
                rt->deleteRoute(route);
                EV_INFO  << "Deleted route to destination: " << destAddress << "\n";
            }

        }
    }

    routingTable.erase(
        std::remove_if(
            routingTable.begin(),
            routingTable.end(),
            [](const RoutingTableEntry& entry) {
                return entry.pheromone < 10; // Condition to remove entry
            }
        ),
        routingTable.end()
    );
}

// Function to compute the best next hop for each destination
void Ant2::computeBestNextHops() {
    std::map<std::string, std::vector<RoutingTableEntry>> groupedEntries;
    std::map<std::string, std::string> bestNextHops;
    double a = 1.0; // alpha
    double b = 1.0; // beta
    double heuristic = 1.0;

    // Group entries by destination address
    for (const auto& entry : routingTable) {
        groupedEntries[entry.destinationAddress].push_back(entry);
    }

    // Determine the best next hop for each destination address
    for (const auto& group : groupedEntries) {
        const std::string& destination = group.first;
        const std::vector<RoutingTableEntry>& entries = group.second;

        double sumProbabilities = 0;
        for (const auto& entry : entries) {
              // Example heuristic value, modify as needed
            double probability = std::pow(entry.pheromone, a) * std::pow(heuristic, b);
            sumProbabilities += probability;
            }

        double maxProbability = -1.0;
        std::string bestNextHop;

        // Compute probabilities and determine the best next hop
        for (const auto& entry : entries) {
            double probability = (std::pow(entry.pheromone, a) * std::pow(heuristic, b)) / sumProbabilities;

            // Find the maximum probability
            if (probability > maxProbability) {
                maxProbability = probability;
                bestNextHop = entry.nextHop;
            }
        }

        // Store the best next hop for this destination
        bestNextHops[destination] = bestNextHop;
    }

    for (const auto& entry : bestNextHops) {
        const std::string& destination = entry.first;
        const std::string& nextHop = entry.second;

        // Convert destination string to Ipv4Address
        Ipv4Address destAddress(destination.c_str());

        //////////////////////////////

        // Vector to store matching routes to delete
        std::vector<Ipv4Route*> routesToDelete;

        // Iterate over the routing table to find all routes to the destination
        for (int i = 0; i < rt->getNumRoutes(); ++i) {
            Ipv4Route* route_delete = rt->getRoute(i);
            if (route_delete && route_delete->getDestination() == destAddress) {
                routesToDelete.push_back(route_delete);
            }
        }

        // Delete all matching routes
        for (Ipv4Route* route : routesToDelete) {
            rt->deleteRoute(route);
            EV_INFO  << "Deleted route to destination: " << destAddress << "\n";
        }

        //////////////////////////////


        // Check if destination is on the routing table
        Ipv4Route* _existingRoute = rt->findBestMatchingRoute(destAddress);
        AntIpv4Route* existing_Route = dynamic_cast<AntIpv4Route*>(_existingRoute);

        if (existing_Route) {

            // Vector to store matching routes to delete
            std::vector<Ipv4Route*> routesToDelete;

            // Iterate over the routing table to find all routes to the destination
            for (int i = 0; i < rt->getNumRoutes(); ++i) {
                Ipv4Route* route_delete = rt->getRoute(i);
                if (route_delete && route_delete->getDestination() == destAddress) {
                    routesToDelete.push_back(route_delete);
                }
            }


            // Delete all matching routes
            for (Ipv4Route* route : routesToDelete) {
                rt->deleteRoute(route);
                std::cout << "Deleted route to destination: " << destination << "\n";
            }

            Ipv4Address netmask = Ipv4Address::ALLONES_ADDRESS;
            AntIpv4Route *route = new AntIpv4Route();
            route->setDestination(Ipv4Address(destination.c_str()));
            route->setNetmask(netmask);
            route->setGateway(Ipv4Address(nextHop.c_str()));
            route->setInterface(interface80211ptr);
            route->setMetric(int(1));
            route->setExpiryTime(simTime() + routeLifetime);
            rt->addRoute(route);

            EV_INFO << "Updated routing entry for destination: " << destination
                    << ", Best Next Hop: " << nextHop
                    << ", Expiry Time: " << route->getExpiryTime() << "\n";

        } else {

            Ipv4Address netmask = Ipv4Address::ALLONES_ADDRESS;
            AntIpv4Route *route = new AntIpv4Route();
            route->setDestination(Ipv4Address(destination.c_str()));
            route->setNetmask(netmask);
            route->setGateway(Ipv4Address(nextHop.c_str()));
            route->setInterface(interface80211ptr);
            route->setMetric(int(1));
            route->setExpiryTime(simTime() + routeLifetime);

            ////////////////////////////////////////////

            // Add the new route to the routing table
            rt->addRoute(route);
            EV_INFO << "Inserted new routing entry for destination: " << destination
                    << ", Best Next Hop: " << nextHop
                    << ", Expiry Time: " << route->getExpiryTime() << "\n";
        }

    }

}

void Ant2::updateThroughput()
{
    // added to get data rate

    auto *liProcessor = dynamic_cast<inet::queueing::PacketProcessorBase *>(li);
    if (liProcessor) {
        // Access the protected member using a public method
        b processedTotalLength = liProcessor->getProcessedTotalLength();
        double total_bits = processedTotalLength.get();
        new_data_amount = total_bits;
    }

    if (old_data_amount == 0){
        //EV_DETAIL << "Ignoring run" << endl;
    }
    else {
        new_time = simTime();
        double time_diff = (new_time - old_time).dbl();
        double amount_data = new_data_amount - old_data_amount;
        double data_rate = amount_data / time_diff;
        data_rate = data_rate / 1000000;
        node_throughput = data_rate;
    }

    old_data_amount = new_data_amount;
    old_time = simTime();

    updateCoordenates();
    updateEnergy();

    EV_DETAIL << "=========== INFO GENERAL =========" << endl;
    EV_DETAIL << "Current coordinates: " << node_position << endl;
    EV_DETAIL << "Current throughput: " << node_throughput << "Mbps" << endl;
    EV_DETAIL << "Current energy: " << node_energy << "%" << endl;
    double th = max_band*0.85;
    double ene = 15;
    if (node_throughput >= th || node_energy < ene) {
        if (allowed_send_request == true) {
            sendRecruiting();
            allowed_send_request = false;
        }
    }

    if (node_energy <= 15.0) {
        moveUav_charge();
    }
    // added to test (delete)
    if (condition > 5) {
        if (allowed_send_request == true) {
            sendRecruiting();
        }
    }
    //condition ++;

    ////// energy vector saving //////
    emit(arrivalSignal, static_cast<long>(node_energy));
    emit(arrivalSignal1, static_cast<long>(total_manet_packets));
    emit(arrivalSignal2, static_cast<long>(total_req_packets));
    emit(arrivalSignal3, static_cast<long>(int(600)));

}

void Ant2::sendRecruiting()
{
    EV_DETAIL << "=========== Trying to send request for help =========" << endl;
    if (allowed_send_request == true) {
        EV_DETAIL << "=========== Sending request for help =========" << endl;

        if (x2ppp_address != Ipv4Address::UNSPECIFIED_ADDRESS){
            // creating fant message
            //Ipv4Address source1 = x2ppp_address;
            Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());

            std::unordered_map<std::string, double> results;

            // weighted formula metric
            double c1 = 0.25;  // Replace with actual value
            double c2 = 0.25;  // Replace with actual value
            double c3 = 0.25;  // Replace with actual value
            double c4 = 1.25;  // Replace with actual value



            for (const auto& entry : statusTable) {

                // Extract parameters for calculation
                bool allowed_accept_request_n = entry.allowed_accept_request;
                if (allowed_accept_request_n == true) {
                    double E = entry.energy;
                    double T = entry.throughput;
                    double D = entry.distance;
                    int H = entry.hops;
                    double M_T = entry.max_throughput;
                    //int ID = entry.cluster_id;

                    // Normalize values
                    double M_T_C =  1; // 1Mbps is the maximum thrughput of all cluster
                    double energy_c = E / 100;
                    double th_c = (1-(T/M_T))*(M_T/M_T_C);
                    double T_eff;

                    if (E>70) {
                        T_eff = D/17;
                    }
                    else if (E>40) {
                        T_eff = D/10;
                    }
                    else {
                        T_eff = D/3;
                    }

                    double T_max = 3500; // seconds
                    double T_min = 10 ; // seconds

                    if (T_eff < T_max) {
                        // Calculate the result using the given formula
                        double result = (c1 * (1 / H)) + (c2 * energy_c) + (c3 * ((T_max - T_eff) / (T_max - T_min))) + (c4 * th_c);
                        results[entry.destinationAddress] = result;
                        EV_INFO << "sssss " << entry.destinationAddress << " : " << result << endl;
                    }

                }

            }

            if (results.empty()) {
                EV_INFO << "No candidates to recruit" << endl;
            } else {
                EV_INFO << "Find candidate to recruit" << endl;
                std::string bestAddress;
                double maxResult = -1;
                EV_INFO << "====== AVAILABLE ======" << endl;

                for (const auto& [address, result] : results) {
                    EV_INFO << "sss " << address << " : " << result << endl;
                    if (result > maxResult) {
                        maxResult = result;
                        bestAddress = address;
                    }
                }

                int a, b, c, d;
                char dot; // to discard the dot separator
                std::istringstream stream(bestAddress);
                stream >> a >> dot >> b >> dot >> c >> dot >> d;
                Ipv4Address bestAddr(a, b, c, d);

                sequencenumber += 1;

                if (mobility == nullptr){
                    Coord selfPosition = Coord(100000,1000,1000);
                    node_position = selfPosition;
                }
                else {
                    Coord selfPosition = mobility->getCurrentPosition();
                    node_position = selfPosition;
                }

                // MODIFICATO per sicurezza: cifratura + firma centralizzate in
                // buildSecureReq(). 'false' per allowed_accept_request: stesso
                // comportamento del codice originale, che qui non lo impostava
                // mai esplicitamente (restava al valore di default).
                auto packet = buildSecureReq(bestAddr, sequencenumber, source, node_position, false);
                auto addressReq = packet->addTag<L3AddressReq>();
                addressReq->setDestAddress(L3Address(broadcast_addr));
                addressReq->setSrcAddress(source);

                packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
                packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                // broadcast the fant to other nodes
                send(packet, "ipOut");
                total_manet_packets++;

                packet = nullptr;

                allowed_send_request = false;
            }

        }


    }
}

//void Ant2::moveUav(std::string coordenates)
void Ant2::moveUav()

{
    //EV_DETAIL << "Moving UAV to request" << endl;
    //EV_DETAIL << "Moving UAV to position" << coordenates << endl;
    double x, y, z;
    char ignore;
    std::stringstream coordStream(coordenates_to_be_recruited);
    coordStream >> ignore >> x >> ignore >> y >> ignore >> z >> ignore;
    Coord newPosition(x, y, z);

    double radius = 100;
    double angle = static_cast<double>(rand())/ RAND_MAX*2*M_PI;
    double randomRadius = static_cast<double>(rand())/ RAND_MAX*radius;
    double xx = 100 + newPosition.x + randomRadius*cos(angle);
    double yy = 100 + newPosition.y + randomRadius*sin(angle);
    double zz = 50;

    Coord newPosition1(xx, yy, zz);

/*    Coord newPosition1;  // Declare newPosition1
    if (name == 5) {
        newPosition1 = Coord(300, 250, 50);
    }
    else if (name == 6) {
        newPosition1 = Coord(300, 750, 50);
    }
    else if (name == 7) {
        newPosition1 = Coord(150, 500, 50);
    }
    else if (name == 8) {
        newPosition1 = Coord(450, 500, 50);
    }
    else if (name == 9) {
        newPosition1 = Coord(300, 350, 50);
    }
    else if (name == 10) {
        newPosition1 = Coord(300, 650, 50);
    }
    else if (name == 11) {
        newPosition1 = Coord(300, 450, 50);
    }
    else if (name == 12) {
        newPosition1 = Coord(300, 550, 50);
    }
    else if (name == 13) {
        newPosition1 = Coord(50, 500, 50);
    }
    else if (name == 14) {
        newPosition1 = Coord(550, 500, 50);
    }
    else if (name == 15) {
        newPosition1 = Coord(250, 500, 50);
    }
    else if (name == 16) {
        newPosition1 = Coord(350, 500, 50);
    }
    else if (name == 17) {
        newPosition1 = Coord(100, 300, 50);
    }
    else if (name == 18) {
        newPosition1 = Coord(500, 700, 50);
    }
    else if (name == 19) {
        newPosition1 = Coord(100, 700, 50);
    }
    else if (name == 20) {
        newPosition1 = Coord(500, 300, 50);
    }*/

    mobility->setPosition(newPosition1);  // Manually set position
    allowed_accept_request = false;
    allowed_send_request = true;
}

void Ant2::moveUav_charge()
{
    EV_DETAIL << "Moving UAV to charge" << endl;
    Coord newPosition1 = Coord(1000, 1000, 50);
    mobility->setPosition(newPosition1);  // Manually set position
    allowed_accept_request = false;
}


void Ant2::updateCoordenates()
{
    if (mobility == nullptr){
        Coord selfPosition = Coord(100000,1000,1000);
        node_position = selfPosition;
    }
    else {
        Coord selfPosition = mobility->getCurrentPosition();
        node_position = selfPosition;
    }
    //Coord selfPosition = mobility->getCurrentPosition();
    //EV_DETAIL << "Current coordenates: " << selfPosition << endl;
    //node_position = selfPosition;

}

double Ant2::calculateEuclideanDistance(const Coord& coord1, const Coord& coord2) {
    // Compute the difference between the coordinates
    double dx = coord2.x - coord1.x;
    double dy = coord2.y - coord1.y;
    double dz = coord2.z - coord1.z;

    // Calculate the Euclidean distance
    double distance = std::sqrt(dx * dx + dy * dy + dz * dz);
    return distance;
}

// ============================================================================
// Aggiunto per il livello di sicurezza (Ascon-AEAD128 + Ed25519).
//
// Le due funzioni sotto centralizzano TUTTA la logica crittografica per i
// messaggi BANT, cosi' non va ripetuta nei vari punti di Ant2.cc che oggi
// creano o ricevono un BantM2. Lo stesso schema (payload cifrato + AAD in
// chiaro + firma su AAD||ciphertext||tag) va replicato in modo identico
// per FANT (solo firma, non c'e' nulla di sensibile da cifrare) e per REQ
// (cifrando coordenates + allowed_accept_request).
// ============================================================================

Packet *Ant2::buildSecureBant(Ipv4Address dstAddress, Ipv4Address gateway,
                               unsigned int seq, Ipv4Address source)
{
    // 1) Payload in chiaro: qui vanno TUTTI i dati che nella versione originale
    //    erano campi separati del messaggio (throughput, energy, coordinate,
    //    hops, max_throughput, cluster_id, allowed_accept_request).
    std::vector<uint8_t> plaintext;
    auto append = [&plaintext](const void *data, size_t len) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
        plaintext.insert(plaintext.end(), p, p + len);
    };
    // NOTA: "hops" non viene incluso qui: e' concettualmente lo stesso dato di
    // hopdistance (il numero di salti attraversati), che deve poter essere
    // aggiornato ad ogni hop e quindi resta un campo in chiaro del pacchetto,
    // non puo' stare dentro un payload sigillato dalla firma del mittente originale.
    append(&node_throughput, sizeof(double));
    append(&node_energy, sizeof(double));
    append(&node_position.x, sizeof(double));
    append(&node_position.y, sizeof(double));
    append(&node_position.z, sizeof(double));
    append(&max_band, sizeof(double));
    append(&cluster_id, sizeof(int));
    uint8_t allowedByte = allowed_accept_request ? 1 : 0;
    append(&allowedByte, sizeof(uint8_t));

    // 2) AAD (Associated Data): i campi di routing restano in chiaro (servono
    //    ad ogni hop per l'inoltro) ma sono comunque autenticati dal tag/firma:
    //    nessuno puo' alterarli senza far fallire la verifica.
    std::vector<uint8_t> aad;
    auto appendAad = [&aad](const void *data, size_t len) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
        aad.insert(aad.end(), p, p + len);
    };
    uint32_t srcInt = source.getInt();
    uint32_t dstInt = dstAddress.getInt();
    appendAad(&srcInt, sizeof(uint32_t));
    appendAad(&dstInt, sizeof(uint32_t));
    appendAad(&seq, sizeof(uint32_t));

    // 3) Nonce derivato: mai trasmesso, unico per (nodo, sequencenumber, tipo messaggio).
    uint8_t nonce[Ant2Crypto::NONCE_LEN];
    crypto.deriveNonce(srcInt, seq, Ant2Crypto::MSG_BANT, nonce);

    // 4) Cifratura + tag di autenticita'/integrita' (Ascon-AEAD128).
    std::vector<uint8_t> ciphertext;
    uint8_t tag[Ant2Crypto::TAG_LEN];
    if (!crypto.encrypt(plaintext, aad, nonce, ciphertext, tag))
        throw cRuntimeError("Ant2: cifratura del BANT fallita");

    // 5) Firma Ed25519 su AAD||ciphertext||tag: lega il tutto all'identita' del mittente.
    std::vector<uint8_t> toSign = aad;
    toSign.insert(toSign.end(), ciphertext.begin(), ciphertext.end());
    toSign.insert(toSign.end(), tag, tag + Ant2Crypto::TAG_LEN);
    uint8_t signature[Ant2Crypto::SIG_LEN];
    crypto.sign(toSign, signature);

    // 6) Popolamento del messaggio OMNeT: solo campi di routing in chiaro + blob cifrati.
    auto bant_message = makeShared<BantM2>();
    bant_message->setChunkLength(B(20 + ciphertext.size() + Ant2Crypto::TAG_LEN + Ant2Crypto::SIG_LEN));
    bant_message->setSrcAddress(source);
    bant_message->setDstAddress(dstAddress);
    bant_message->setNextAddress(source);
    bant_message->setGateway(gateway);
    bant_message->setSequencenumber(seq);
    bant_message->setHopdistance(1);

    bant_message->setCiphertextArraySize(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); i++)
        bant_message->setCiphertext(i, ciphertext[i]);
    for (int i = 0; i < Ant2Crypto::TAG_LEN; i++)
        bant_message->setAuthTag(i, tag[i]);
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        bant_message->setSignature(i, signature[i]);

    auto bant_packet = new Packet("Bant", bant_message);
    bant_packet->setKind(BANT_PACKET);
    return bant_packet;
}

bool Ant2::verifyAndDecryptBant(const Ptr<const BantM2>& recHello,
                                 double& energyOut, double& throughputOut,
                                 Coord& positionOut,
                                 double& maxThroughputOut, int& clusterIdOut,
                                 bool& allowedAcceptOut)
{
    uint32_t srcInt = recHello->getSrcAddress().getInt();
    uint32_t dstInt = recHello->getDstAddress().getInt();
    unsigned int seq = recHello->getSequencenumber();

    // 1) Il mittente deve essere un nodo noto della flotta (nel fleet roster).
    //    Questo e' il primo controllo, prima di qualunque altra elaborazione:
    //    un mittente sconosciuto viene scartato subito, senza sprecare tempo
    //    a verificare firme che comunque non potrebbero mai risultare valide.
    if (!crypto.isKnownNode(srcInt)) {
        sec_bant_fail++;
        sec_fail_unknown++;
        logScarto("BANT", recHello->getSrcAddress(), "identita' sconosciuta: non e' nel registro della flotta", sec_bant_fail);
        EV_WARN << "Ant2/security: BANT scartato, mittente non presente nel fleet roster: "
                << recHello->getSrcAddress() << endl;
        return false;
    }

    // 2) Ricostruzione dell'AAD e del messaggio su cui verificare la firma.
    std::vector<uint8_t> aad;
    auto appendAad = [&aad](const void *data, size_t len) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
        aad.insert(aad.end(), p, p + len);
    };
    appendAad(&srcInt, sizeof(uint32_t));
    appendAad(&dstInt, sizeof(uint32_t));
    appendAad(&seq, sizeof(uint32_t));

    std::vector<uint8_t> ciphertext(recHello->getCiphertextArraySize());
    for (size_t i = 0; i < ciphertext.size(); i++)
        ciphertext[i] = recHello->getCiphertext(i);

    uint8_t tag[Ant2Crypto::TAG_LEN];
    for (int i = 0; i < Ant2Crypto::TAG_LEN; i++)
        tag[i] = recHello->getAuthTag(i);

    uint8_t signature[Ant2Crypto::SIG_LEN];
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        signature[i] = recHello->getSignature(i);

    std::vector<uint8_t> toVerify = aad;
    toVerify.insert(toVerify.end(), ciphertext.begin(), ciphertext.end());
    toVerify.insert(toVerify.end(), tag, tag + Ant2Crypto::TAG_LEN);

    // 3) Verifica della firma: solo chi possiede la chiave privata di srcAddress
    //    puo' averla prodotta. Fatta PRIMA di decifrare e PRIMA di toccare
    //    qualunque tabella (routingTable/statusTable) o di inoltrare il pacchetto.
    if (!crypto.verify(toVerify, signature, srcInt)) {
        sec_bant_fail++;
        sec_fail_signature++;
        logScarto("BANT", recHello->getSrcAddress(), "firma Ed25519 non valida: chi ha inviato non possiede la chiave privata dichiarata", sec_bant_fail);
        EV_WARN << "Ant2/security: BANT scartato, firma non valida da "
                << recHello->getSrcAddress() << endl;
        return false;
    }

    // 4) Decifratura + verifica del tag di integrita' AEAD.
    uint8_t nonce[Ant2Crypto::NONCE_LEN];
    crypto.deriveNonce(srcInt, seq, Ant2Crypto::MSG_BANT, nonce);

    std::vector<uint8_t> plaintext;
    if (!crypto.decrypt(ciphertext, tag, aad, nonce, plaintext)) {
        sec_bant_fail++;
        sec_fail_aead++;
        logScarto("BANT", recHello->getSrcAddress(), "tag Ascon errato: il payload cifrato e' stato manomesso", sec_bant_fail);
        EV_WARN << "Ant2/security: BANT scartato, tag AEAD non valido da "
                << recHello->getSrcAddress() << endl;
        return false;
    }

    const size_t expectedLen = 6 * sizeof(double) + sizeof(int) + sizeof(uint8_t);
    if (plaintext.size() != expectedLen) {
        sec_bant_fail++;
        sec_fail_aead++;
        logScarto("BANT", recHello->getSrcAddress(), "payload decifrato malformato", sec_bant_fail);
        EV_WARN << "Ant2/security: BANT scartato, payload decifrato di lunghezza inattesa" << endl;
        return false;
    }

    // 5) Spacchettamento nei valori di output, nello stesso ordine usato in buildSecureBant().
    size_t offset = 0;
    auto readDouble = [&plaintext, &offset]() {
        double v;
        memcpy(&v, plaintext.data() + offset, sizeof(double));
        offset += sizeof(double);
        return v;
    };
    throughputOut = readDouble();
    energyOut = readDouble();
    double x = readDouble(), y = readDouble(), z = readDouble();
    positionOut = Coord(x, y, z);
    maxThroughputOut = readDouble();
    memcpy(&clusterIdOut, plaintext.data() + offset, sizeof(int));
    offset += sizeof(int);
    allowedAcceptOut = plaintext[offset] != 0;

    // Aggiunto: stampa di successo, cosi' nel log si vede chiaramente sia cosa
    // viene scartato (EV_WARN sopra) sia cosa passa la verifica correttamente.
    sec_bant_ok++;
    logAccettato("BANT", recHello->getSrcAddress(), sec_bant_ok);
    EV_INFO << "Ant2/security: BANT OK da " << recHello->getSrcAddress()
            << " (seq=" << seq << ", energia=" << energyOut
            << ", throughput=" << throughputOut << ")" << endl;

    return true;
}

// Stesso schema usato per il BANT (vedi sopra), applicato al REQ: qui i dati
// sensibili sono le coordinate (la posizione del drone in difficolta', da non
// esporre in chiaro via radio) e allowed_accept_request.
Packet *Ant2::buildSecureReq(Ipv4Address dstAddress, unsigned int seq, Ipv4Address source,
                              const Coord& coordToSend, bool allowedAccept)
{
    std::vector<uint8_t> plaintext;
    auto append = [&plaintext](const void *data, size_t len) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
        plaintext.insert(plaintext.end(), p, p + len);
    };
    append(&coordToSend.x, sizeof(double));
    append(&coordToSend.y, sizeof(double));
    append(&coordToSend.z, sizeof(double));
    uint8_t allowedByte = allowedAccept ? 1 : 0;
    append(&allowedByte, sizeof(uint8_t));

    std::vector<uint8_t> aad;
    auto appendAad = [&aad](const void *data, size_t len) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
        aad.insert(aad.end(), p, p + len);
    };
    uint32_t srcInt = source.getInt();
    uint32_t dstInt = dstAddress.getInt();
    appendAad(&srcInt, sizeof(uint32_t));
    appendAad(&dstInt, sizeof(uint32_t));
    appendAad(&seq, sizeof(uint32_t));

    uint8_t nonce[Ant2Crypto::NONCE_LEN];
    crypto.deriveNonce(srcInt, seq, Ant2Crypto::MSG_REQ, nonce);

    std::vector<uint8_t> ciphertext;
    uint8_t tag[Ant2Crypto::TAG_LEN];
    if (!crypto.encrypt(plaintext, aad, nonce, ciphertext, tag))
        throw cRuntimeError("Ant2: cifratura del REQ fallita");

    std::vector<uint8_t> toSign = aad;
    toSign.insert(toSign.end(), ciphertext.begin(), ciphertext.end());
    toSign.insert(toSign.end(), tag, tag + Ant2Crypto::TAG_LEN);
    uint8_t signature[Ant2Crypto::SIG_LEN];
    crypto.sign(toSign, signature);

    auto req_message = makeShared<ReqM2>();
    req_message->setChunkLength(B(16 + ciphertext.size() + Ant2Crypto::TAG_LEN + Ant2Crypto::SIG_LEN));
    req_message->setSrcAddress(source);
    req_message->setDstAddress(dstAddress);
    req_message->setSequencenumber(seq);
    req_message->setNextAddress(source);
    req_message->setHopdistance(1);
    req_message->appendHopAddresses(source);

    req_message->setCiphertextArraySize(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); i++)
        req_message->setCiphertext(i, ciphertext[i]);
    for (int i = 0; i < Ant2Crypto::TAG_LEN; i++)
        req_message->setAuthTag(i, tag[i]);
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        req_message->setSignature(i, signature[i]);

    auto req_packet = new Packet("Request", req_message);
    req_packet->setKind(REQ_PACKET);
    return req_packet;
}

bool Ant2::verifyAndDecryptReq(const Ptr<const ReqM2>& recHello,
                                Coord& coordOut, bool& allowedAcceptOut)
{
    uint32_t srcInt = recHello->getSrcAddress().getInt();
    uint32_t dstInt = recHello->getDstAddress().getInt();
    unsigned int seq = recHello->getSequencenumber();

    if (!crypto.isKnownNode(srcInt)) {
        sec_req_fail++;
        sec_fail_unknown++;
        logScarto("REQ", recHello->getSrcAddress(), "identita' sconosciuta: non e' nel registro della flotta", sec_req_fail);
        EV_WARN << "Ant2/security: REQ scartato, mittente non presente nel fleet roster: "
                << recHello->getSrcAddress() << endl;
        return false;
    }

    std::vector<uint8_t> aad;
    auto appendAad = [&aad](const void *data, size_t len) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data);
        aad.insert(aad.end(), p, p + len);
    };
    appendAad(&srcInt, sizeof(uint32_t));
    appendAad(&dstInt, sizeof(uint32_t));
    appendAad(&seq, sizeof(uint32_t));

    std::vector<uint8_t> ciphertext(recHello->getCiphertextArraySize());
    for (size_t i = 0; i < ciphertext.size(); i++)
        ciphertext[i] = recHello->getCiphertext(i);

    uint8_t tag[Ant2Crypto::TAG_LEN];
    for (int i = 0; i < Ant2Crypto::TAG_LEN; i++)
        tag[i] = recHello->getAuthTag(i);

    uint8_t signature[Ant2Crypto::SIG_LEN];
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        signature[i] = recHello->getSignature(i);

    std::vector<uint8_t> toVerify = aad;
    toVerify.insert(toVerify.end(), ciphertext.begin(), ciphertext.end());
    toVerify.insert(toVerify.end(), tag, tag + Ant2Crypto::TAG_LEN);

    if (!crypto.verify(toVerify, signature, srcInt)) {
        sec_req_fail++;
        sec_fail_signature++;
        logScarto("REQ", recHello->getSrcAddress(), "firma Ed25519 non valida: chi ha inviato non possiede la chiave privata dichiarata", sec_req_fail);
        EV_WARN << "Ant2/security: REQ scartato, firma non valida da "
                << recHello->getSrcAddress() << endl;
        return false;
    }

    uint8_t nonce[Ant2Crypto::NONCE_LEN];
    crypto.deriveNonce(srcInt, seq, Ant2Crypto::MSG_REQ, nonce);

    std::vector<uint8_t> plaintext;
    if (!crypto.decrypt(ciphertext, tag, aad, nonce, plaintext)) {
        sec_req_fail++;
        sec_fail_aead++;
        logScarto("REQ", recHello->getSrcAddress(), "tag Ascon errato: il payload cifrato e' stato manomesso", sec_req_fail);
        EV_WARN << "Ant2/security: REQ scartato, tag AEAD non valido da "
                << recHello->getSrcAddress() << endl;
        return false;
    }

    const size_t expectedLen = 3 * sizeof(double) + sizeof(uint8_t);
    if (plaintext.size() != expectedLen) {
        sec_req_fail++;
        sec_fail_aead++;
        logScarto("REQ", recHello->getSrcAddress(), "payload decifrato malformato", sec_req_fail);
        EV_WARN << "Ant2/security: REQ scartato, payload decifrato di lunghezza inattesa" << endl;
        return false;
    }

    double x, y, z;
    memcpy(&x, plaintext.data(), sizeof(double));
    memcpy(&y, plaintext.data() + sizeof(double), sizeof(double));
    memcpy(&z, plaintext.data() + 2 * sizeof(double), sizeof(double));
    coordOut = Coord(x, y, z);
    allowedAcceptOut = plaintext[3 * sizeof(double)] != 0;

    sec_req_ok++;
    logAccettato("REQ", recHello->getSrcAddress(), sec_req_ok);
    EV_INFO << "Ant2/security: REQ OK da " << recHello->getSrcAddress()
            << " (seq=" << seq << ", coordinate=" << coordOut << ")" << endl;

    return true;
}


// Stream condiviso verso il file di dettaglio degli eventi di sicurezza.
// TUTTI gli eventi (accettazioni e scarti, di ogni nodo) finiscono qui, senza
// limiti: il file e' pensato per essere analizzato con grep/contatori a fine run.
// La console riceve invece solo l'essenziale, per non essere intasata
// (il buffer dell'IDE tronca gli output lunghi, perdendo le righe iniziali).
std::ofstream& Ant2::securityEventLog()
{
    static std::ofstream log("ant2_security_events.log", std::ios::trunc);
    static bool intestazione = false;
    if (!intestazione) {
        intestazione = true;
        log << "# Log dettagliato degli eventi del livello di sicurezza Ant2\n";
        log << "# formato: <tempo_simulato> <nodo> <ESITO> <tipo_messaggio> <mittente> [motivo]\n";
        log << "# tipi: FANT=scoperta rotta, BANT=risposta con stato, REQ=richiesta recruiting\n";
        log << "#\n";
        log << "# Esempi di analisi a fine run:\n";
        log << "#   grep -c OK ant2_security_events.log            -> pacchetti accettati\n";
        log << "#   grep SCARTO ant2_security_events.log           -> tutti i rifiuti, con motivo\n";
        log << "#   grep SCARTO ant2_security_events.log | grep 10.0.0.248   -> rifiuti di un dato mittente\n";
        log << "#\n";
    }
    return log;
}

// Un pacchetto rifiutato dal livello di sicurezza: indica CHI ha rifiutato,
// CHE COSA, DA CHI proveniva e soprattutto PERCHE'.
void Ant2::logScarto(const char *tipo, Ipv4Address mittente, const char *motivo, long n)
{
    securityEventLog() << simTime() << "  " << getFullPath()
                       << "  SCARTO  " << tipo << "  da " << mittente
                       << "  motivo: " << motivo << "\n";

    // Su console solo i primi casi (e poi di rado), a meno che non sia stata
    // richiesta esplicitamente la modalita' verbosa.
    if (consoleVerbose || n <= 3)
        std::cout << "[SEC][SCARTO] " << getFullPath() << " ha RIFIUTATO un " << tipo
                  << " da " << mittente << " -> " << motivo
                  << "  (scarto n." << n << ")" << std::endl;
}

// Un pacchetto accettato: firma verificata ed eventuale payload decifrato.
void Ant2::logAccettato(const char *tipo, Ipv4Address mittente, long n)
{
    securityEventLog() << simTime() << "  " << getFullPath()
                       << "  OK      " << tipo << "  da " << mittente << "\n";

    if (consoleVerbose || n <= 2)
        std::cout << "[SEC][OK] " << getFullPath() << " ha VERIFICATO un " << tipo
                  << " da " << mittente << std::endl;
}

// --- FANT: solo autenticazione, nessuna cifratura ---
// Il FANT e' un messaggio di scoperta rotta: non contiene dati sensibili
// (energia, posizione, ecc. viaggiano nel BANT). Serve pero' impedire che un
// nodo non autorizzato ne inietti di falsi per inquinare le tabelle di routing:
// per questo lo firmiamo con Ed25519.

static std::vector<uint8_t> buildFantSignedData(uint32_t srcInt, uint32_t dstInt, unsigned int seq)
{
    std::vector<uint8_t> data;
    auto append = [&data](const void *p, size_t len) {
        const uint8_t *b = reinterpret_cast<const uint8_t *>(p);
        data.insert(data.end(), b, b + len);
    };
    append(&srcInt, sizeof(uint32_t));
    append(&dstInt, sizeof(uint32_t));
    append(&seq, sizeof(unsigned int));
    return data;
}

void Ant2::signFant(const Ptr<FantM2>& fant)
{
    auto data = buildFantSignedData(fant->getSrcAddress().getInt(),
                                     fant->getDstAddress().getInt(),
                                     fant->getSequencenumber());
    uint8_t signature[Ant2Crypto::SIG_LEN];
    crypto.sign(data, signature);
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        fant->setSignature(i, signature[i]);
}

bool Ant2::verifyFant(const Ptr<const FantM2>& fant)
{
    uint32_t srcInt = fant->getSrcAddress().getInt();

    if (!crypto.isKnownNode(srcInt)) {
        sec_fant_fail++;
        sec_fail_unknown++;
        logScarto("FANT", fant->getSrcAddress(),
                  "identita' sconosciuta: non e' nel registro della flotta", sec_fant_fail);
        EV_WARN << "Ant2/security: FANT scartato, mittente non nel fleet roster: "
                << fant->getSrcAddress() << endl;
        return false;
    }

    auto data = buildFantSignedData(srcInt, fant->getDstAddress().getInt(),
                                     fant->getSequencenumber());
    uint8_t signature[Ant2Crypto::SIG_LEN];
    for (int i = 0; i < Ant2Crypto::SIG_LEN; i++)
        signature[i] = fant->getSignature(i);

    if (!crypto.verify(data, signature, srcInt)) {
        sec_fant_fail++;
        sec_fail_signature++;
        logScarto("FANT", fant->getSrcAddress(),
                  "firma Ed25519 non valida: chi ha inviato non possiede la chiave privata dichiarata",
                  sec_fant_fail);
        EV_WARN << "Ant2/security: FANT scartato, firma non valida da "
                << fant->getSrcAddress() << endl;
        return false;
    }

    sec_fant_ok++;
    logAccettato("FANT", fant->getSrcAddress(), sec_fant_ok);
    EV_INFO << "Ant2/security: FANT OK da " << fant->getSrcAddress() << endl;
    return true;
}

void Ant2::updateEnergy()
{
    J energylevel = energyManagement->getEstimatedEnergyCapacity();
    double residualEnergy = energylevel.get();
    double charge_status = (int)((residualEnergy/nominalCapacity) * 100);
    //EV_DETAIL << "Energy level is: " << charge_status << "%" << endl;
    node_energy = charge_status;

}

// Hook method to intercept packet processing at the IPv4 module
INetfilter::IHook::Result Ant2::datagramForwardHook(Packet *packet) {
    return ACCEPT;
}

INetfilter::IHook::Result Ant2::ensureRouteForDatagram(Packet *datagram)
{
    const auto& networkHeader = getNetworkProtocolHeader(datagram);
    const L3Address& destAddr = networkHeader->getDestinationAddress();
    const L3Address& sourceAddr = networkHeader->getSourceAddress();
    EV_INFO << "Finding route for source " << sourceAddr << " with destination " << destAddr << endl;
    Ipv4Address destAddr_1 = destAddr.toIpv4();
    Ipv4Address sourceAddr_1 = sourceAddr.toIpv4();
    std::string source_string = sourceAddr_1.str();
    std::string destination_string = destAddr_1.str();
    //EV_INFO << "=raaamy" << endl;
    // Get the packet name
    const char *packetName = datagram->getName();

    // Compare packet name to determine type
    if (strcmp(packetName, "Fant") == 0) {
        EV_INFO << "Handling Fant packet" << endl;
    } else if (strcmp(packetName, "Bant") == 0) {
        EV_INFO << "Handling Bant packet" << endl;
    } else if (strcmp(packetName, "Request") == 0) {
        EV_INFO << "Handling Request packet" << endl;
    } else {
        EV_INFO << "Handling unknown packet type: " << packetName << endl;

        // Access the IPv4 module
        auto ipv4Module = host->getSubmodule("ipv4");
        if (!ipv4Module) {
            EV_ERROR << "IPv4 module not found." << endl;
            return INetfilter::IHook::ACCEPT;
        }

        // Access the ARP submodule within IPv4
        auto arpModule = ipv4Module->getSubmodule("arp"); // Adjust the name to match the actual submodule
        if (!arpModule) {
            EV_ERROR << "ARP submodule not found within IPv4 module." << endl;
            return INetfilter::IHook::ACCEPT;
        }

        // Cast to GlobalArp
        auto globalArp = check_and_cast<inet::GlobalArp*>(arpModule);

        //const MacAddress* senderMacAddress = nullptr;
        auto macAddressTag = datagram->findTag<MacAddressInd>();
        if (macAddressTag) {
            const MacAddress senderMacAddress = macAddressTag->getSrcAddress();
            EV_INFO << "Sender MAC address (previous hop): " << senderMacAddress << endl;
            inet::L3Address l3Address = globalArp->getL3AddressFor(senderMacAddress);
            EV_INFO << "Sender IP address (previous hop): " << l3Address << endl;
            Ipv4Address gw = l3Address.toIpv4();
            std::string gateway = gw.str();
            handlePheromone(source_string, gateway);
        } else {
            EV_WARN << "No MAC address information available." << endl;
        }


    }

    return ACCEPT;
}

void Ant2::handlePheromone(std::string src, std::string gw)
{

    double pheromoneValue;
    /////////// routing table update /////////////
    bool entryExists = false;

    for (auto &entry : routingTable) {
        if (entry.destinationAddress == src && entry.nextHop == gw) {
            entry.pheromone += 0.1; // Update pheromone value
            EV_INFO << "Updated pheromone value for destination: " << entry.destinationAddress
                    << ", Next Hop: " << entry.nextHop
                    << ", New Pheromone: " << entry.pheromone << "\n";
            entryExists = true;
            pheromoneValue = entry.pheromone;
            break;
        }
    }

    if (!entryExists) {
        // Add the new entry to the routing table
        RoutingTableEntry newEntry = {src, gw, pheromoneValue};
        routingTable.push_back(newEntry);
        EV_INFO << "Added new entry to routing table: Destination: " << src << ", Next Hop: " << gw << ", Pheromone: " << pheromoneValue << "\n";
    }

    /////////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////////////

    // Print the routing table after updating
    EV_INFO << "== Routing table:\n";
    for (const auto& entry : routingTable) {
        EV_INFO << "Destination: " << entry.destinationAddress
                << ", Next Hop: " << entry.nextHop
                << ", Pheromone: " << entry.pheromone << "\n";
    }
}
///////////////////

} // namespace inet

}
