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

    virtual int numInitStages() const override { return NUM_INIT_STAGES; }

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

