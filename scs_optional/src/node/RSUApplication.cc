// 
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

#include "RSUApplication.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"
#include <string.h>
#include <thread>

// message
#include <math.h>
#include <chrono>
#include "date/date.h"
#include <cstdint>

using namespace inet;

Define_Module(RSUApplication);

RSUApplication::RSUApplication()
{

}

RSUApplication::~RSUApplication()
{

}


void RSUApplication::initialize()
{
    // TODO - Generated method body
}

void RSUApplication::handleMessage(cMessage *msg)
{
    // TODO - Generated method body
}

bool RSUApplication::startApplication()
{
    EV_INFO << "RSU App started !\n";
    // Insert your application code here.

    return true;
}

bool RSUApplication::stopApplication()
{
    return true;
}

void RSUApplication::processPacket(std::shared_ptr <inet::Packet> pk)
{
    EV_INFO << "RSU received a message! \n";
    // Insert your application code
    return;
}
