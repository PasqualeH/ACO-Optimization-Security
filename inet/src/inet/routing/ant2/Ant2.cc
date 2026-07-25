
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
    //}

    //CHK(interface80211ptr->getProtocolDataForUpdate<Ipv4InterfaceData>())->joinMulticastGroup(Ipv4Address::LL_MANET_ROUTERS);
    //if (name == 0){
    //    scheduleAfter(uniform(0.0, 2.0), event);
    //}
    scheduleAfter(uniform(0.0, 2.0), event);
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
            auto fant_message = makeShared<ReqM2>();

            // Create a ReqM2 message
            Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            fant_message->setChunkLength(b(128));
            fant_message->setSrcAddress(source);
            fant_message->setDstAddress(source);
            sequencenumber += 1;
            fant_message->setSequencenumber(sequencenumber);
            fant_message->setNextAddress(source);
            fant_message->setHopdistance(1);
            fant_message->appendHopAddresses(source);

            // Set the node's current position
            Coord selfPosition = mobility->getCurrentPosition();
            node_position = selfPosition;
            std::stringstream ss;
            ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
            std::string coordenates = ss.str();
            const char *coordCStr = coordenates.c_str();
            fant_message->setCoordenates(coordCStr);
            fant_message->setAllowed_accept_request(false);

            // Creating ReqM2 packet
            auto packet = new Packet("Request", fant_message);
            auto addressReq = packet->addTag<L3AddressReq>();
            packet->setKind(REQ_PACKET); // Set the packet type
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
            fant_message = nullptr;

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
            auto fant_message = makeShared<ReqM2>();

            // Create a ReqM2 message
            Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            fant_message->setChunkLength(b(128));
            fant_message->setSrcAddress(source);
            fant_message->setDstAddress(source);
            sequencenumber += 1;
            fant_message->setSequencenumber(sequencenumber);
            fant_message->setNextAddress(source);
            fant_message->setHopdistance(1);
            fant_message->appendHopAddresses(source);

            // Set the node's current position
            Coord selfPosition = mobility->getCurrentPosition();
            node_position = selfPosition;
            std::stringstream ss;
            ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
            std::string coordenates = ss.str();
            const char *coordCStr = coordenates.c_str();
            fant_message->setCoordenates(coordCStr);
            fant_message->setAllowed_accept_request(false);

            // Creating ReqM2 packet
            auto packet = new Packet("Request", fant_message);
            auto addressReq = packet->addTag<L3AddressReq>();
            packet->setKind(REQ_PACKET); // Set the packet type
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
            fant_message = nullptr;
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

                            auto bant_message = makeShared<BantM2>();

                            // Set up the Bant message fields
                            bant_message->setChunkLength(b(128));  // Set size of Bant message in bits
                            bant_message->setSrcAddress(source);   // Source is this node's address
                            bant_message->setDstAddress(src);      // Destination is the source address of the Fant message
                            bant_message->setNextAddress(source);  // Next address is also this node's address
                            bant_message->setGateway(gateway);
                            bant_message->setSequencenumber(msgsequencenumber);  // Use the same sequence number
                            bant_message->setHopdistance(int(1));

                            //added for node monitoring

                            bant_message->setThroughput(node_throughput);
                            bant_message->setEnergy(node_energy);
                            bant_message->setAllowed_accept_request(allowed_accept_request);

                            std::stringstream ss;
                            ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
                            std::string coordenates = ss.str();
                            const char *coordCStr = coordenates.c_str();

                            bant_message->setCoordenates(coordCStr);
                            bant_message->setHops(double(1.0));
                            bant_message->setMax_throughput(max_band); // Mbps
                            bant_message->setCluster_id(cluster_id);

                            // Create a Bant packet
                            auto bant_packet = new Packet("Bant", bant_message);
                            bant_packet->setKind(BANT_PACKET); // Set the packet type
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();

                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));   // Destination is the source of the Fant message
                            bantAddressReq->setSrcAddress(L3Address(source)); // Source is this node's address

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
                            bant_message = nullptr;
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
                            //////////// added for new logic /////////
                            //double waitTime1 = intuniform(1, 100);
                            //waitTime1 = waitTime1 / 10000;

                            auto bant_message = makeShared<BantM2>();

                            // Set up the Bant message fields
                            bant_message->setChunkLength(b(128));  // Set size of Bant message in bits
                            bant_message->setSrcAddress(source);   // Source is this node's address
                            bant_message->setDstAddress(src);      // Destination is the source address of the Fant message
                            bant_message->setNextAddress(source);  // Next address is also this node's address
                            bant_message->setGateway(gateway);
                            bant_message->setSequencenumber(msgsequencenumber);  // Use the same sequence number
                            bant_message->setHopdistance(int(1));

                            //added for node monitoring

                            bant_message->setThroughput(node_throughput);
                            bant_message->setEnergy(node_energy);
                            bant_message->setAllowed_accept_request(allowed_accept_request);

                            std::stringstream ss;
                            ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
                            std::string coordenates = ss.str();
                            const char *coordCStr = coordenates.c_str();

                            bant_message->setCoordenates(coordCStr);
                            bant_message->setHops(double(1.0));
                            bant_message->setMax_throughput(max_band); // Mbps
                            bant_message->setCluster_id(cluster_id);

                            // Create a Bant packet
                            auto bant_packet = new Packet("Bant", bant_message);
                            bant_packet->setKind(BANT_PACKET); // Set the packet type
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();

                            //bantAddressReq->setDestAddress(Ipv4Address(10,0,0,1));   // Destination is the source of the Fant message
                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));   // Destination is the source of the Fant message
                            bantAddressReq->setSrcAddress(L3Address(source)); // Source is this node's address

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
                            bant_message = nullptr;

                        }
                        //////////////////////////////////////////

                        packet = nullptr;
                        fhp = nullptr;

                        //////////////////////////////////////////
                    }
                }
            }

            else if (msg->getKind() == BANT_PACKET) {

                ForwardEntry *fhp = nullptr;
                auto recHello = staticPtrCast<BantM2>(check_and_cast<Packet *>(msg)->peekData<BantM2>()->dupShared());

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
                    bool allowed_accept_req;

                    src = recHello->getSrcAddress();
                    dst = recHello->getDstAddress();
                    msgsequencenumber = recHello->getSequencenumber();
                    next = recHello->getNextAddress();
                    numHops = recHello->getHopdistance();
                    gateway = recHello->getGateway();
                    allowed_accept_req = recHello->getAllowed_accept_request();

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

                        double energy = recHello->getEnergy();
                        double throughput = recHello->getThroughput();
                        std::string coordenates = recHello->getCoordenates();
                        double hops = recHello->getHops();

                        // Parse the string and extract coordinates
                        double x, y, z;
                        char dummy; // to ignore unwanted characters like '(' ',' and ')'
                        std::stringstream ss(coordenates);
                        ss >> dummy >> x >> dummy >> y >> dummy >> z >> dummy; // Parse format "(x, y, z)"
                        // Convert parsed values to a Coord object
                        Coord node_position_neighbor(x, y, z);

                        double distance = calculateEuclideanDistance(node_position_neighbor, node_position);
                        double max_throughput = recHello->getMax_throughput();
                        int cluster_id_ = recHello->getCluster_id();
                        bool allowed_accept_request_node = recHello->getAllowed_accept_request();

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

                        recHello->setNextAddress(source);
                        numHops++;
                        recHello->setHopdistance(numHops);
                        recHello->setSrcAddress(src);
                        recHello->setDstAddress(dst);
                        recHello->setGateway(next_gateway);
                        recHello->setSequencenumber(msgsequencenumber);
                        recHello->setHops(double(numHops));
                        recHello->setAllowed_accept_request(allowed_accept_req);
                        double waitTime = intuniform(1, 100);
                        waitTime = waitTime / 10000;
                        EV_DETAIL << "Forwarding Bant " << endl;
                        packet->insertAtBack(recHello);
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


                ForwardEntry *fhp = nullptr;
                auto recHello = staticPtrCast<ReqM2>(check_and_cast<Packet *>(msg)->peekData<ReqM2>()->dupShared());
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
                    std::string coordenates_to_be_recruited_packet = recHello->getCoordenates();

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
                        coordenates_to_be_recruited = coordenates_to_be_recruited_packet;

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
                            auto bant_message = makeShared<BantM2>();

                            // Set up the Bant message fields
                            bant_message->setChunkLength(b(128));  // Set size of Bant message in bits
                            bant_message->setSrcAddress(source_a);   // Source is this node's address
                            bant_message->setDstAddress(src);      // Destination is the source address of the Fant message
                            bant_message->setNextAddress(source_a);  // Next address is also this node's address
                            bant_message->setGateway(gateway);
                            bant_message->setSequencenumber(msgsequencenumber);  // Use the same sequence number
                            bant_message->setHopdistance(int(1));

                            //added for node monitoring

                            bant_message->setThroughput(node_throughput);
                            bant_message->setEnergy(node_energy);
                            bant_message->setAllowed_accept_request(allowed_accept_request);

                            std::stringstream ss;
                            ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
                            std::string coordenates = ss.str();
                            const char *coordCStr = coordenates.c_str();

                            bant_message->setCoordenates(coordCStr);
                            bant_message->setHops(double(1.0));
                            bant_message->setMax_throughput(max_band); // Mbps
                            bant_message->setCluster_id(cluster_id);

                            // Create a Bant packet
                            auto bant_packet = new Packet("Bant", bant_message);
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();
                            bant_packet->setKind(BANT_PACKET); // Set the packet type
                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq->setSrcAddress(source_a); // Source is this node's address

                            bant_packet->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                            bant_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            // Send the Bant packet
                            double waitTime = intuniform(1, 100);
                            waitTime = waitTime / 10000;
                            sendDelayed(bant_packet, waitTime, "ipOut");
                            total_manet_packets++;

                            //////////// sent to wlan1 /////////
                            /////////////////////////////////////

                            auto bant_message1 = makeShared<BantM2>();

                            // Set up the Bant message fields
                            bant_message1->setChunkLength(b(128));  // Set size of Bant message in bits
                            bant_message1->setSrcAddress(source_a);   // Source is this node's address
                            bant_message1->setDstAddress(src);      // Destination is the source address of the Fant message
                            bant_message1->setNextAddress(source_a);  // Next address is also this node's address
                            bant_message1->setGateway(gateway);
                            bant_message1->setSequencenumber(msgsequencenumber);  // Use the same sequence number
                            bant_message1->setHopdistance(int(1));

                            //added for node monitoring

                            bant_message1->setThroughput(node_throughput);
                            bant_message1->setEnergy(node_energy);
                            bant_message1->setAllowed_accept_request(allowed_accept_request);

                            std::stringstream ss1;
                            ss1 << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
                            std::string coordenates1 = ss1.str();
                            const char *coordCStr1 = coordenates1.c_str();

                            bant_message1->setCoordenates(coordCStr1);
                            bant_message1->setHops(double(1.0));
                            bant_message1->setMax_throughput(max_band); // Mbps
                            bant_message1->setCluster_id(cluster_id);

                            // Create a Bant packet
                            auto bant_packet1 = new Packet("Bant", bant_message1);
                            auto bantAddressReq1 = bant_packet1->addTag<L3AddressReq>();
                            bant_packet1->setKind(BANT_PACKET); // Set the packet type
                            bantAddressReq1->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq1->setSrcAddress(source_b); // Source is this node's address

                            bant_packet1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                            bant_packet1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            // Send the Bant packet
                            double waitTime1 = intuniform(1, 100);
                            waitTime1 = waitTime1 / 10000;
                            sendDelayed(bant_packet1, waitTime1, "ipOut");
                            total_manet_packets++;

                            // Clean up
                            bant_packet = nullptr;
                            bant_message = nullptr;
                            bant_packet1 = nullptr;
                            bant_message1 = nullptr;

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
                            auto bant_message = makeShared<BantM2>();

                            // Set up the Bant message fields
                            bant_message->setChunkLength(b(128));  // Set size of Bant message in bits
                            bant_message->setSrcAddress(source_a);   // Source is this node's address
                            bant_message->setDstAddress(src);      // Destination is the source address of the Fant message
                            bant_message->setNextAddress(source_a);  // Next address is also this node's address
                            bant_message->setGateway(gateway);
                            bant_message->setSequencenumber(msgsequencenumber);  // Use the same sequence number
                            bant_message->setHopdistance(int(1));

                            //added for node monitoring

                            bant_message->setThroughput(node_throughput);
                            bant_message->setEnergy(node_energy);
                            bant_message->setAllowed_accept_request(allowed_accept_request);

                            std::stringstream ss;
                            ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
                            std::string coordenates = ss.str();
                            const char *coordCStr = coordenates.c_str();

                            bant_message->setCoordenates(coordCStr);
                            bant_message->setHops(double(1.0));
                            bant_message->setMax_throughput(max_band); // Mbps
                            bant_message->setCluster_id(cluster_id);

                            // Create a Bant packet
                            auto bant_packet = new Packet("Bant", bant_message);
                            auto bantAddressReq = bant_packet->addTag<L3AddressReq>();
                            bant_packet->setKind(BANT_PACKET); // Set the packet type
                            bantAddressReq->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq->setSrcAddress(source_a); // Source is this node's address

                            bant_packet->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[0]->getInterfaceId());
                            bant_packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            // Send the Bant packet
                            double waitTime = intuniform(1, 100);
                            waitTime = waitTime / 10000;
                            sendDelayed(bant_packet, waitTime, "ipOut");
                            total_manet_packets++;

                            //////////// sent to wlan1 /////////
                            /////////////////////////////////////

                            auto bant_message1 = makeShared<BantM2>();

                            // Set up the Bant message fields
                            bant_message1->setChunkLength(b(128));  // Set size of Bant message in bits
                            bant_message1->setSrcAddress(source_a);   // Source is this node's address
                            bant_message1->setDstAddress(src);      // Destination is the source address of the Fant message
                            bant_message1->setNextAddress(source_a);  // Next address is also this node's address
                            bant_message1->setGateway(gateway);
                            bant_message1->setSequencenumber(msgsequencenumber);  // Use the same sequence number
                            bant_message1->setHopdistance(int(1));

                            //added for node monitoring

                            bant_message1->setThroughput(node_throughput);
                            bant_message1->setEnergy(node_energy);
                            bant_message1->setAllowed_accept_request(allowed_accept_request);

                            std::stringstream ss1;
                            ss1 << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
                            std::string coordenates1 = ss1.str();
                            const char *coordCStr1 = coordenates1.c_str();

                            bant_message1->setCoordenates(coordCStr1);
                            bant_message1->setHops(double(1.0));
                            bant_message1->setMax_throughput(max_band); // Mbps
                            bant_message1->setCluster_id(cluster_id);

                            // Create a Bant packet
                            auto bant_packet1 = new Packet("Bant", bant_message1);
                            auto bantAddressReq1 = bant_packet1->addTag<L3AddressReq>();
                            bant_packet1->setKind(BANT_PACKET); // Set the packet type
                            bantAddressReq1->setDestAddress(L3Address(broadcast_addr));
                            bantAddressReq1->setSrcAddress(source_b); // Source is this node's address

                            bant_packet1->addTag<InterfaceReq>()->setInterfaceId(wirelessInterfaces[1]->getInterfaceId());
                            bant_packet1->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                            bant_packet1->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                            // Send the Bant packet
                            double waitTime1 = intuniform(1, 100);
                            waitTime1 = waitTime1 / 10000;
                            sendDelayed(bant_packet1, waitTime1, "ipOut");
                            total_manet_packets++;

                            // Clean up
                            bant_packet = nullptr;
                            bant_message = nullptr;
                            bant_packet1 = nullptr;
                            bant_message1 = nullptr;

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

                auto recHello1 = staticPtrCast<BantM2>(check_and_cast<Packet *>(msg)->peekData<BantM2>()->dupShared());
                auto recHello2 = staticPtrCast<BantM2>(check_and_cast<Packet *>(msg)->peekData<BantM2>()->dupShared());

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

                        double energy = recHello1->getEnergy();
                        double throughput = recHello1->getThroughput();
                        std::string coordenates = recHello1->getCoordenates();
                        double hops = recHello1->getHops();

                        // Parse the string and extract coordinates
                        double x, y, z;
                        char dummy; // to ignore unwanted characters like '(' ',' and ')'
                        std::stringstream ss(coordenates);
                        ss >> dummy >> x >> dummy >> y >> dummy >> z >> dummy; // Parse format "(x, y, z)"
                        // Convert parsed values to a Coord object
                        Coord node_position_neighbor(x, y, z);

                        double distance = calculateEuclideanDistance(node_position_neighbor, node_position);
                        double max_throughput = recHello1->getMax_throughput();
                        int cluster_id_ = recHello1->getCluster_id();
                        bool allowed_accept_request_node = recHello1->getAllowed_accept_request();

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
                        recHello1->setSrcAddress(src);
                        recHello1->setDstAddress(dst);
                        recHello1->setGateway(next_gateway);
                        recHello1->setSequencenumber(msgsequencenumber);
                        recHello1->setHops(double(numHops));
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
                        recHello2->setSrcAddress(src);
                        recHello2->setDstAddress(dst);
                        recHello2->setGateway(next_gateway);
                        recHello2->setSequencenumber(msgsequencenumber);
                        recHello2->setHops(double(numHops));
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

                ForwardEntry *fhp = nullptr;
                auto recHello1 = staticPtrCast<ReqM2>(check_and_cast<Packet *>(msg)->peekData<ReqM2>()->dupShared());
                auto recHello2 = staticPtrCast<ReqM2>(check_and_cast<Packet *>(msg)->peekData<ReqM2>()->dupShared());

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

        auto fant_message = makeShared<ReqM2>();
        // Create a Bant message
        Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
        fant_message->setChunkLength(b(128));
        fant_message->setSrcAddress(source);
        fant_message->setDstAddress(source);
        sequencenumber += 1;
        fant_message->setSequencenumber(sequencenumber);
        fant_message->setNextAddress(source);
        fant_message->setHopdistance(1);
        fant_message->appendHopAddresses(source);
        Coord selfPosition = mobility->getCurrentPosition();
        node_position = selfPosition;
        std::stringstream ss;
        ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
        std::string coordenates = ss.str();
        const char *coordCStr = coordenates.c_str();
        fant_message->setCoordenates(coordCStr);
        fant_message->setAllowed_accept_request(false);
        // creatig fant packet
        auto packet = new Packet("Request", fant_message);
        auto addressReq = packet->addTag<L3AddressReq>();
        packet->setKind(REQ_PACKET); // Set the packet type
        addressReq->setDestAddress(L3Address(broadcast_addr));
        addressReq->setSrcAddress(L3Address(source));

        packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
        packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
        packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

        // broadcast the fant to other nodes
        send(packet, "ipOut");
        total_manet_packets++;
        packet = nullptr;
        fant_message = nullptr;

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
        auto fant_message = makeShared<ReqM2>();

        if (x2ppp_address != Ipv4Address::UNSPECIFIED_ADDRESS){
            // creating fant message
            //Ipv4Address source1 = x2ppp_address;
            Ipv4Address source = (interface80211ptr->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            fant_message->setChunkLength(b(128));
            fant_message->setSrcAddress(source);


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

                fant_message->setDstAddress(Ipv4Address(a,b,c,d));
                sequencenumber += 1;
                fant_message->setSequencenumber(sequencenumber);
                fant_message->setNextAddress(source);
                fant_message->setHopdistance(1);
                fant_message->appendHopAddresses(source);

                if (mobility == nullptr){
                    Coord selfPosition = Coord(100000,1000,1000);
                    node_position = selfPosition;
                }
                else {
                    Coord selfPosition = mobility->getCurrentPosition();
                    node_position = selfPosition;
                }

                std::stringstream ss;
                ss << "(" << node_position.x << ", " << node_position.y << ", " << node_position.z << ")";
                std::string coordenates = ss.str();
                const char *coordCStr = coordenates.c_str();
                fant_message->setCoordenates(coordCStr);


                // creatig fant packet
                auto packet = new Packet("Request", fant_message);
                auto addressReq = packet->addTag<L3AddressReq>();
                packet->setKind(REQ_PACKET); // Set the packet type
                addressReq->setDestAddress(L3Address(broadcast_addr));
                addressReq->setSrcAddress(source);

                packet->addTag<InterfaceReq>()->setInterfaceId(interface80211ptr->getInterfaceId());
                packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::manet);
                packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);

                // broadcast the fant to other nodes
                send(packet, "ipOut");
                total_manet_packets++;

                packet = nullptr;
                fant_message = nullptr;

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
