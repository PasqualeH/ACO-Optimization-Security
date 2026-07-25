// 
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

package scs.base;

import inet.mobility.contract.IMobility;
import os3_leosatellites.mobility.NoradScs;
import leosatellites.mobility.INorad;

// added red dropper
import inet.queueing.filter.RedDropper;
import inet.queueing.queue.PacketQueue;
import inet.node.inet.Router;
import inet.node.inet.MulticastRouter;

import inet.node.inet.AdhocHost;
import inet.applications.contract.IApp;
import inet.routing.contract.IManetRouting;

import scs.common.beamInfo.BeamInfo;
import inet_scs.mobility.BeamVisualizer;
// Laser Satellite model that uses the NoradA implementation, which therefore allows the use of inter-satellite links.
//
//
module LaserSatellite2 extends AdhocHost
{
    parameters:
        
        @node; //because of MobilityBase initialization
        @networkNode;
        string satelliteName = default(""); // Parameter for satellite name

        @display("t=$satelliteName");
        mobility.typename = default("SatelliteMobility");
    submodules:
        routingApp: <default("")> like IApp if typename != "" {      // Aodv or other manet routing over UDP/TCP protocol
            @display("p=913,75");
        }
        routing: <default("")> like IManetRouting  if typename != "" {
            @display("p=913,225");
        }
        NoradModule:<default("NoradScs")> like INorad if typename != "" { // Module for transformation between omnet and libNorad
            parameters:
                @display("p=708.75,34.649998");         
                satIndex = parentIndex();
				satName = "sat";
				planes = 1;
				satPerPlane = 66;
        }
        bm: BeamInfo {
            parameters:
            @display("p=100, 700");
        }    
        bv: BeamVisualizer {
             parameters:
            @display("p=100, 700");
        }
    connections:
        routing.ipOut --> tn.in++ if exists(routing);
        routing.ipIn <-- tn.out++ if exists(routing);
        routingApp.socketOut --> at.in++ if exists(routingApp);
        routingApp.socketIn <-- at.out++ if exists(routingApp);
        
                
}
