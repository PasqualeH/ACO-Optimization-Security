//
// Copyright (C) 2006-2017 Christoph Sommer <sommer@ccs-labs.org>
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// Documentation for these modules is at http://veins.car2x.org/
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
// This program was developed based on Veins Framework (https://veins.car2x.org/). 
// The original code can be found at `veins_inet/VeinsInetCar.ned` of Veins-5.2.

package scs_optional.veins_inet_scs;

import inet.node.inet.AdhocHost;
import inet.mobility.contract.IMobility;
import scs_optional.veins_inet_scs.VeinsInetMobility;
import inet.node.inet.StandardHost;
//
// Wireless-enabled Host
//
//module InetCar extends AdhocHost
module InetCar extends StandardHost
{
    parameters:
  		@node;
        @networkNode;
        //@class(veins::CircleMobility);
        @display("i=block/cogwheel");
        //@signal[mobilityStateChanged](type=inet::MobilityBase);
        
        //bool initFromDisplayString=default(true);
        mobility.typename = default("VeinsInetMobility");  
                //# Network Layer specs
        *.routingTableModule = default(absPath("ipv4.routingTable"));
        *.interfaceTableModule = default(absPath(".interfaceTable"));
        
        ipv4.configurator.typename = "HostAutoConfigurator";
        ipv4.configurator.interfaces = "wlan0";   
        
        numWlanInterfaces = default(1);
        
        wlan[*].typename = default("AckingWirelessInterface");
        wlan[*].radio.transmitter.typename = default("SatelliteApskScalarTransmitter");
        wlan[*].radio.receiver.typename = default("ApskScalarReceiver");
		wlan[*].radio.typename = default("ApskScalarRadio");
        wlan[*].radio.receiver.errorModel.typename = default("SatelliteErrorModel");
        wlan[*].radio.centerFrequency = default(13.5GHz);
		wlan[*].radio.bandwidth = default(250MHz);
        wlan[*].radio.receiver.errorModel.typename = default("SatelliteErrorModel");
        wlan[*].radio.displayCommunicationRange = default(false);
 		wlan[*].radio.antenna.mobilityModule = default("^.^.^.mobility");
        
   submodules:

}

