// 
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

package scs_optional.node;

import inet.node.inet.StandardHost;
import inet.mobility.contract.IMobility;
import scs_optional.veins_inet_scs.VeinsInetMobility;

import simu5g.nodes.Ue;
import simu5g.nodes.NR.NRUe;

module UECar extends Ue
{
    parameters:
        @display("i=device/car");

        //# Mobility
        mobility.typename = default("VeinsInetMobility");

        //# Network Layer specs
        *.routingTableModule = default(absPath(".ipv4.routingTable"));
        *.interfaceTableModule = default(absPath(".interfaceTable"));
        
        ipv4.configurator.typename = "HostAutoConfigurator";
        ipv4.configurator.interfaces = "cellular";
        
   submodules:
     
}

module NRCar extends NRUe
{
    parameters:
        @display("i=device/car");

        //# Mobility
        mobility.typename = default("VeinsInetMobility");

        //# Network Layer specs
        *.routingTableModule = default(absPath(".ipv4.routingTable"));
        *.interfaceTableModule = default(absPath(".interfaceTable"));
        
        ipv4.configurator.typename = "HostAutoConfigurator";
        ipv4.configurator.interfaces = "cellular";
        
   submodules:
     
}

