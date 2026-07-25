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
// The original code can be found at `veins_inet/src/VeinsInetApplicationManager.h` of Veins-5.2. 

#pragma once

#include "../veins_scs/modules/mobility/traci/TraCIScenarioNetManager.h"
#include "veins_inet.h"
#include "VeinsInetManagerBase.h"

namespace veins {

/**
 * @brief
 * Creates and manages network nodes corresponding to cars.
 *
 * See the Veins website <a href="http://veins.car2x.org/"> for a tutorial, documentation, and publications </a>.
 *
 * @author Christoph Sommer
 *
 */
class veins_sim5g_API VeinsInetManager : public VeinsInetManagerBase, virtual public TraCIScenarioNetManager {
    virtual void initialize(int stage) override;
};

class veins_sim5g_API VeinsInetManagerAccess {
public:
    VeinsInetManager* get()
    {
        return FindModule<VeinsInetManager*>::findGlobalModule();
    };
};

} // namespace veins
