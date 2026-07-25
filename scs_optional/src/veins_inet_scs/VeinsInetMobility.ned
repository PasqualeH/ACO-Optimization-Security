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
//
// Veins Mobility module for the INET Framework
// Based on inet::MovingMobilityBase of INET Framework v4.0.0
//
//
// This program was developed based on Veins Framework (https://veins.car2x.org/). 
// The original code can be found at `veins_inet/src/VeinsInetMobility.ned` of Veins-5.2. 

package scs_optional.veins_inet_scs;

import inet.mobility.contract.IMobility;
import inet.mobility.base.MobilityBase;
import inet.mobility.base.MovingMobilityBase;

//module VeinsInetMobility extends CircleMobility //LUTMotionMobility
simple VeinsInetMobility extends MovingMobilityBase
{
    parameters:
        @class(veins::VeinsInetMobility);
        @display("i=block/cogwheel");
        @signal[mobilityStateChanged](type=inet::MobilityBase);
		bool initFromDisplayString = default(false);
        double latitude = default(35.18698);
        double longitude = default(136.90033);
        //double updateInterval @unit(s); // Time interval to update the hosts position
        
}
