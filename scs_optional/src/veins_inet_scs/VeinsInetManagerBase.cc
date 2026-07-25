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
// The original code can be found at `veins_inet/src/VeinsInetManagerBase.cc` of Veins-5.2.

#include "VeinsInetManagerBase.h"

#include "veins/base/utils/Coord.h"
#include "inet/common/scenario/ScenarioManager.h"
#include "inet/networklayer/configurator/ipv4/Ipv4NetworkConfigurator.h"
#include "VeinsInetMobility.h"


using veins::VeinsInetManagerBase;

Define_Module(veins::VeinsInetManagerBase);

VeinsInetManagerBase::~VeinsInetManagerBase()
{
}

void VeinsInetManagerBase::initialize(int stage)
{
    if (stage != 1)
        return;

#if INET_VERSION >= 0x0402
    signalManager.subscribeCallback(this, TraCIScenarioNetManager::traciModulePreInitSignal, [this](SignalPayload<cObject*> payload) {
        cModule* module = dynamic_cast<cModule*>(payload.p);
        ASSERT(module);

        cModule* root = getSimulation()->getSystemModule();

        auto* notification = new inet::cPreModuleInitNotification();
        notification->module = module;

        // configuration
        /*
        Ipv4NetworkConfigurator * CF = dynamic_cast<Ipv4NetworkConfigurator *>(cSimulation::getActiveSimulation()->getSystemModule()->getSubmodule("configurator"));
        if (CF!=nullptr)
        {
            CF->reInitialize();
        }
        */
        root->emit(POST_MODEL_CHANGE, notification, NULL);
    });
#endif
}

void VeinsInetManagerBase::preInitializeModule(cModule* mod, const std::string& nodeId, const Coord& position, const std::string& road_id, double speed, Heading heading, VehicleSignalSet signals)
{
    TraCIScenarioNetManager::preInitializeModule(mod, nodeId, position, road_id, speed, heading, signals);

    // pre-initialize VeinsInetMobility
    auto mobilityModules = getSubmodulesOfType<VeinsInetMobility>(mod);
    for (auto inetmm : mobilityModules) {
        inetmm->preInitialize(nodeId, inet::Coord(position.x, position.y), road_id, speed, heading.getRad());
    }
}

void VeinsInetManagerBase::updateModulePosition(cModule* mod, const Coord& p, const std::string& edge, double speed, Heading heading, VehicleSignalSet signals)
{
    TraCIScenarioNetManager::updateModulePosition(mod, p, edge, speed, heading, signals);

    // update position in VeinsInetMobility
    auto mobilityModules = getSubmodulesOfType<VeinsInetMobility>(mod);
    for (auto inetmm : mobilityModules) {
        inetmm->nextPosition(inet::Coord(p.x, p.y), edge, speed, heading.getRad());
    }
}

