//
// Copyright (C) 2009 by Alfonso Ariza, Malaga University
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// 

package inet.routing.ant2;
import inet.routing.contract.IManetRouting;

simple Ant2 like IManetRouting
{
    parameters:
        @class("ant2::Ant2");
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
        int name = default(100);
        
        // Added to compute the bandwidth usage
        double max_band = default(0.0);
        
        // Added to identify the parent cluster ID of each UAV
        int cluster_id;

        // Added for security (Ascon-AEAD128 + Ed25519): percorsi dei file di
        // provisioning OFFLINE, generati con gli strumenti in tools/ prima
        // della missione. Usati solo se useCentralAuthority = false.
        // NB: default("") obbligatorio, altrimenti OMNeT++ pretende un valore per
        // ogni nodo anche quando si usa l'autorita' centrale e questi file non
        // servono affatto (errore "Enter parameter ... (unassigned)").
        // Se si usa il provisioning offline e ci si dimentica di valorizzarli,
        // il caricamento fallisce comunque con un errore esplicito: il nodo non
        // parte mai "silenziosamente insicuro".
        string groupKeyFile = default("");      // chiave simmetrica di gruppo (16 byte), uguale per tutta la flotta
        string ownPubKeyFile = default("");     // chiave pubblica Ed25519 di QUESTO nodo (32 byte)
        string ownPrivKeyFile = default("");    // chiave privata Ed25519 di QUESTO nodo (64 byte) - MAI condivisa
        string fleetRosterFile = default("");   // tabella indirizzo -> chiave pubblica di tutta la flotta

        // APPROCCIO ALTERNATIVO: autorita' centrale "in-simulazione" (vedi
        // Ant2KeyAuthority). Se true, i quattro parametri sopra vengono ignorati
        // e le chiavi si ottengono chiamando il modulo Ant2KeyAuthority presente
        // al livello top della rete, con questo nome.
        bool useCentralAuthority = default(false);
        string keyAuthorityName = default("keyAuthority");

        // SOLO PER I TEST: se true, questo nodo si comporta da attaccante.
        // Firma i propri messaggi con una chiave NON riconosciuta dagli altri
        // nodi, simulando un drone compromesso che tenta di iniettare
        // messaggi di routing falsi. Serve a dimostrare che la verifica
        // crittografica discrimina davvero (test negativo).
        bool isAttacker = default(false);

        // Se true, ogni singolo evento di sicurezza viene stampato anche in
        // console. Di default false: il dettaglio completo finisce comunque
        // sempre nel file ant2_security_events.log, mentre la console resta
        // leggibile (banner iniziale, avvio dei nodi, riepilogo finale).
        bool securityConsoleVerbose = default(false);
        
        // Added for energy monitoring
	    @signal[arrival](type="long");
        @statistic[energy](title="energy"; source="arrival"; record=vector,stats; interpolationmode=none);
        @signal[arrival1](type="int");
        @statistic[totalMantPkts](title="totalPacketsManet"; source="arrival1"; record=last,vector);
        @signal[arrival2](type="int");
        @statistic[totalReqPkts](title="totalPacketsReq"; source="arrival2"; record=last,vector);
        @signal[arrival3](type="int");
        @statistic[energyNode](title="energyNode"; source="arrival3"; record=last,vector);  
              
    gates:
        input ipIn;
        output ipOut;
}
