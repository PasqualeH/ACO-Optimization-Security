//
// Copyright (C) 2009 by Alfonso Ariza, Malaga University
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


package inet.routing.ant;
import inet.routing.contract.IManetRouting;

simple Ant like IManetRouting
{
    parameters:
        @class("ant::Ant");
        @display("i=block/routing");
        string interfaceTableModule;   // The path to the InterfaceTable module
        string routingTableModule;
        double helloInterval @unit(s);  // How often Fant messages should be sent out
        string netmask = default("255.255.0.0");  // Netmask for the ad-hoc network
        double maxVariance = default(1); // This is the maximum of a random value to determine when the first hello message will be sent out
        double routeLifetime @unit(s);  // The expiry time of the routing entries
        bool manetPurgeRoutingTables = default(true);
        volatile double broadcastDelay @unit(s) = default(uniform(0s,0.001s)); // Delay to broadcast messages and avoid collisions
        
        // Added for ACO algorithm
        double alpha = default(1.0); // Incidence factor of the pheromone
        double betaa = default(1.0); // Incidence factor of the Heuristics
        double pheromoneDecayRate = default(1.0); // Decay rate of pheromones
        double initialPheromoneValue = default(1.0); // Initial pheromone value
        double pheromoneIncrement = default(1.0); // Increment value of heromones
        
        
        double update_pheromone_Interval @unit(s);  // How often the pheromones decay
        double update_throughput_Interval @unit(s);  // How often the metrics (throughput, energy, coordinates, etc) are updated
        
        // Added to monitor the traffic passing though a node
        string networkProtocolModule = default("^.ipv4.ip");
        
        // Added for recruiting algorithm
        bool allowed_accept_request = default(false);
        bool allowed_send_request = default(true);
        
        // Added for energy consumption monitoring
        double nominalCapacity;
        
        // Added to identify each UAV
        int name = default(0);
        
        // Added to compute the bandwidth usage
        double max_band = default(0.0);
        
        // Added to identify the parent cluster ID of each UAV
        int cluster_id;
        
    gates:
        input ipIn;
        output ipOut;
}

