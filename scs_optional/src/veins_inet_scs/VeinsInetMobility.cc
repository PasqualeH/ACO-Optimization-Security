//
// Copyright (C) 2006-2018 Christoph Sommer <sommer@ccs-labs.org>
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
// This program was developed based on Veins Framework (https://veins.car2x.org/). 
// The original code can be found at `veins_inet/src/VeinsInetMobility.cc` of Veins-5.2.

#include "VeinsInetMobility.h"

#include "inet/common/INETMath.h"
#include "inet/common/Units.h"
#include "inet/common/geometry/common/GeographicCoordinateSystem.h"

namespace veins {

using namespace inet::units::values;

Define_Module(VeinsInetMobility);

VeinsInetMobility::VeinsInetMobility()
{
}

VeinsInetMobility::~VeinsInetMobility()
{
    delete vehicleCommandInterface;
}

void VeinsInetMobility::preInitialize(std::string external_id, const inet::Coord& position, std::string road_id, double speed, double angle)
{
    Enter_Method_Silent();
    this->external_id = external_id;
    lastPosition = position;
    lastVelocity = inet::Coord(cos(angle), -sin(angle)) * speed;
    lastOrientation = inet::Quaternion(inet::EulerAngles(rad(-angle), rad(0.0), rad(0.0)));
}

void VeinsInetMobility::initialize(int stage)
{
    MobilityBase::initialize(stage);
    if (stage == 0) {
        latitude = par("latitude");
        longitude = par("longitude");
    }

}

void VeinsInetMobility::nextPosition(const inet::Coord& position, std::string road_id, double speed, double angle)
{
    Enter_Method_Silent();

    lastPosition = position;
    lastVelocity = inet::Coord(cos(angle), -sin(angle)) * speed;
    lastOrientation = inet::Quaternion(inet::EulerAngles(rad(-angle), rad(0.0), rad(0.0)));

    // Update display string to show node is getting updates
    auto hostMod = getParentModule();
    if (std::string(hostMod->getDisplayString().getTagArg("veins", 0)) == ". ") {
        hostMod->getDisplayString().setTagArg("veins", 0, " .");
    }
    else {
        hostMod->getDisplayString().setTagArg("veins", 0, ". ");
    }

    emitMobilityStateChangedSignal();
}

#if INET_VERSION >= 0x0403
const inet::Coord& VeinsInetMobility::getCurrentPosition()
{
    return lastPosition;
}

const inet::Coord& VeinsInetMobility::getCurrentVelocity()
{
    return lastVelocity;
}

const inet::Coord& VeinsInetMobility::getCurrentAcceleration()
{
    throw cRuntimeError("Invalid operation");
}

const inet::Quaternion& VeinsInetMobility::getCurrentAngularPosition()
{
    return lastOrientation;
}

const inet::Quaternion& VeinsInetMobility::getCurrentAngularVelocity()
{
    return lastAngularVelocity;
}

const inet::Quaternion& VeinsInetMobility::getCurrentAngularAcceleration()
{
    throw cRuntimeError("Invalid operation");
}
#else

inet::Coord VeinsInetMobility::getCurrentPosition()
{
    return lastPosition;
}

inet::Coord VeinsInetMobility::getCurrentVelocity()
{
    return lastVelocity;
}

inet::Coord VeinsInetMobility::getCurrentAcceleration()
{
    throw cRuntimeError("Invalid operation");
}

inet::Quaternion VeinsInetMobility::getCurrentAngularPosition()
{
    return lastOrientation;
}

inet::Quaternion VeinsInetMobility::getCurrentAngularVelocity()
{
    return lastAngularVelocity;
}

inet::Quaternion VeinsInetMobility::getCurrentAngularAcceleration()
{
    throw cRuntimeError("Invalid operation");
}
#endif
void VeinsInetMobility::setInitialPosition()
{
    subjectModule->getDisplayString().setTagArg("p", 0, lastPosition.x);
    subjectModule->getDisplayString().setTagArg("p", 1, lastPosition.y);
    MobilityBase::setInitialPosition();
}

void VeinsInetMobility::handleSelfMessage(cMessage* message)
{
}

std::string VeinsInetMobility::getExternalId() const
{
    if (external_id == "") throw cRuntimeError("TraCIMobility::getExternalId called with no external_id set yet");
    return external_id;
}

TraCIScenarioNetManager* VeinsInetMobility::getManager() const
{
    if (!manager) manager = TraCIScenarioNetManagerAccess().get();
    return manager;
}

TraCICommandInterfaceScs* VeinsInetMobility::getCommandInterface() const
{
    if (!commandInterface) commandInterface = getManager()->getCommandInterface();
    return commandInterface;
}

TraCICommandInterfaceScs::Vehicle* VeinsInetMobility::getVehicleCommandInterface() const
{
    if (!vehicleCommandInterface) vehicleCommandInterface = new TraCICommandInterfaceScs::Vehicle(getCommandInterface()->vehicle(getExternalId()));
    return vehicleCommandInterface;
}

double VeinsInetMobility::getLUTPositionX() const
{
    EV  << "\n Veins LUT position X" << longitude << "\n";
    return longitude;
}
double VeinsInetMobility::getLUTPositionY() const
{
    EV  << "\n Veins LUT position Y" << latitude << "\n";
    return latitude;
}


double VeinsInetMobility::getLUTAltitude() const
{
    // for now tentatively altitude 0
    return 0;
}

double VeinsInetMobility::getDistance(const double& refLatitude, const double& refLongitude, const double& refAltitude) const
{
    return 0;
}

//
// this mobility model does not deal with speed, but it must be implemented
// because it is a pure virtual function declared in IMobility
//
Coord VeinsInetMobility::getCurrentSpeed()
{
    return Coord(0,0,0);
}

} // namespace veins
