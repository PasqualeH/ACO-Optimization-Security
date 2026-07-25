// 
// Copyright (C) 2023 TOYOTA MOTOR CORPORATION. ALL RIGHTS RESERVED.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//

#ifndef __SATELLITEVEINS_RSUAPPLICATION_H_
#define __SATELLITEVEINS_RSUAPPLICATION_H_

#include <omnetpp.h>

#include "veins_inet_scs/veins_inet.h"
#include "veins_inet_scs/VeinsInetApplicationBase.h"

using namespace omnetpp;

/**
 * TODO - Generated class
 */
class veins_sim5g_API RSUApplication : public veins::VeinsInetApplicationBase
{
  protected:
    virtual void initialize() override;
    virtual void handleMessage(cMessage *msg) override;

    virtual bool startApplication() override;
    virtual bool stopApplication() override;
    virtual void processPacket(std::shared_ptr<inet::Packet> pk) override;

  public:
    RSUApplication();
    ~RSUApplication();
};

#endif
