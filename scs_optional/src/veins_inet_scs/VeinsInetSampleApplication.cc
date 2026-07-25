//
// Copyright (C) 2018 Christoph Sommer <sommer@ccs-labs.org>
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
// This program was developed based on Veins Framework (https://veins.car2x.org/). 
// The original code can be found at `veins_inet/src/VeinsInetSampleApplication.cc` of Veins-5.2.

#include "VeinsInetSampleApplication.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"

#include <math.h>

#include "VeinsInetSampleMessage_m.h"
#ifdef CAM_ENABLED
#include "CAM.h"
#endif

#include <chrono>
#include "date/date.h"
#include <cstdint>

using namespace inet;

Define_Module(VeinsInetSampleApplication);

// Clock structure for generationDeltaTime
struct myclock
{
    using rep       = std::int32_t;
    using period    = std::milli;
    using duration  = std::chrono::duration<rep, period>;
    using time_point = std::chrono::time_point <myclock>;
    static constexpr  bool  is_steady = false;

    static time_point now ()  noexcept
    {
        using namespace std::chrono;
        using namespace date;
        return time_point {
          duration_cast<duration>(system_clock::now()- sys_days{jan/1/2022})
        };
    }
};



VeinsInetSampleApplication::VeinsInetSampleApplication()
{
}



uint64_t VeinsInetSampleApplication::getGenerationDeltaTime()
{
    auto tp = myclock::now();
    uint64_t   generationDeltaTime;
    generationDeltaTime = tp.time_since_epoch().count();

    return generationDeltaTime;
}



bool VeinsInetSampleApplication::startApplication()
{
   generateCAM();

   if (getParentModule()->getIndex() == 0) {
       auto callback = [this]() {
           getParentModule()->getDisplayString().setTagArg("i", 1, "red");

          // traciVehicle->setSpeed(0);

          // auto payload = makeShared<VeinsInetSampleMessage>();
          // payload->setChunkLength(B(100));
          // payload->setRoadId(traciVehicle->getRoadId().c_str());
          // timestampPayload(payload);

          // auto packet = createPacket("accident");
          // packet->insertAtBack(payload);
           //sendPacket(std::move(packet));

           // host should continue after 30s
           auto callback = [this]() {
               //traciVehicle->setSpeed(-1);
           };
           timerManager.create(veins::TimerSpecification(callback).oneshotIn(SimTime(30, SIMTIME_S)));
       };
       timerManager.create(veins::TimerSpecification(callback).oneshotAt(SimTime(20, SIMTIME_S)));
   }
    return true;
}

bool VeinsInetSampleApplication::stopApplication()
{
    return true;
}

VeinsInetSampleApplication::~VeinsInetSampleApplication()
{
}

void VeinsInetSampleApplication::processPacket(std::shared_ptr<inet::Packet> pk)
{
    auto payload = pk->peekAtFront<VeinsInetSampleMessage>();

    EV_INFO << "Received packet: " << payload << endl;

    getParentModule()->getDisplayString().setTagArg("i", 1, "green");

    ///debug received encoded message
    for (int i=0; i<1024; i++)
    {
        std::cout << std::hex << std::uppercase << +payload->getMessageBuffer(i);
    }
    std::cout << std::nouppercase << std::dec << "\n";

    if (haveForwarded)  return;

    auto packet = createPacket("relay");
    packet->insertAtBack(payload);
    sendPacket(std::move(packet));

    //////

    haveForwarded = true;
}

void VeinsInetSampleApplication::generateCAM()
{
    // Send CAM message from node[0].
    if (getParentModule()->getIndex() == 0)
    {
        auto callback = [this]()
        {
            // set node icon to red
            getParentModule()->getDisplayString().setTagArg("i", 1, "red");

            // CAM message structure
#ifdef CAM_ENABLED
            CAM_t *cam = new CAM_t();
            asn_enc_rval_t erv;

            // clear msg buffer
            memset(msg_buffer, 0, sizeof(msg_buffer));

            // Get vehicle parameter
            // node id
            int nodeID = getParentModule()->getIndex();
            std::cout << "Start CAM generation ..\n";

            cam->header.stationID = nodeID;
            cam->header.protocolVersion = 1;
            cam->header.messageID = ItsPduHeader__messageID_cam;

            // GenDeltaTime
            cam->cam.generationDeltaTime = 11409;

            // basic container
            cam->cam.camParameters.basicContainer.stationType = StationType_passengerCar;

            cam->cam.camParameters.highFrequencyContainer.present = HighFrequencyContainer_PR_basicVehicleContainerHighFrequency;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingConfidence =   HeadingConfidence_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingValue = HeadingValue_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedConfidence = SpeedConfidence_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.vehicleLength.vehicleLengthValue = VehicleLengthValue_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.vehicleLength.vehicleLengthConfidenceIndication = VehicleLengthConfidenceIndication_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.vehicleWidth = VehicleWidth_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.longitudinalAcceleration.longitudinalAccelerationValue = LongitudinalAccelerationValue_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.curvature.curvatureConfidence = CurvatureConfidence_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.curvatureCalculationMode = CurvatureCalculationMode_unavailable;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.yawRate.yawRateConfidence =  YawRateConfidence_unavailable;
            /*
            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.accelerationControl = (AccelerationControl_t *)calloc(1, sizeof(AccelerationControl_t));

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.accelerationControl->size = 1;

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.accelerationControl->buf = (uint8_t *) calloc(1,sizeof(uint8_t));

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.lateralAcceleration = (LateralAcceleration *) calloc(1, sizeof(LateralAcceleration));

            cam->cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.lateralAcceleration->lateralAccelerationValue = -2;

*/
            //Print out serialized CAM MSG
            asn_fprint(stdout, &asn_DEF_CAM, cam);

            // UPPER ENCODE to buffer
            std::cout << "Serialize ...\n";

            erv = asn_encode_to_buffer(0, ATS_UNALIGNED_BASIC_PER, &asn_DEF_CAM, cam, msg_buffer, sizeof(msg_buffer));

            if(erv.encoded == -1)
            {
                std::cout << "ERROR: CAM Serialization failed! \n";
            } else
            {
                std::cout << "\n";

                for (int i = 0; i < sizeof(msg_buffer); i++)
                {
                    // print out buffer in uppercased hex
                    std::cout << std::hex << std::uppercase << +msg_buffer[i] << " ";

                }

                std::cout << std::nouppercase << std::dec << "\n";

                std::cout << "Encoded bytes: " << erv.encoded << "\n";

            }

            auto payload = makeShared <VeinsInetSampleMessage>();

            //Timestamp adds the newst generation time to the payload
            // don't know reason for causing an error below.
            //timestampPayload(payload);

            payload->setChunkLength(B(1024));

            for (int k=0; k<(int)sizeof(msg_buffer); k++)
            {
                payload->setMessageBuffer(k, msg_buffer[k]);
            }

            auto packet = createPacket("camPacket");

            // Insert the payoad at the end pointer of the packet
            packet->insertAtBack(payload);
            //sendPacket(std::move(packet));

            ASN_STRUCT_FREE(asn_DEF_CAM, cam);
            memset(msg_buffer, 0, sizeof(msg_buffer));
            cam = NULL;
            delete cam;
#endif
        };

        timerManager.create(veins::TimerSpecification(callback).interval(SimTime(1, SIMTIME_S)), "CAM");
    }
}

std::pair<double, double> VeinsInetSampleApplication::getVehicleLatLong()
{
    // Get the vehicle coordinate
    inet::Coord vehiclePosition = mobility->getCurrentPosition();

    veins::Coord veinsCoord;

    veinsCoord.x = vehiclePosition.x;

    veinsCoord.y = vehiclePosition.y;

    std::pair<double, double>  CoordPair = traci->getLonLat(veinsCoord);

    CoordPair.first *= 1000.0;

    CoordPair.second *= 1000.0;

    return CoordPair;
}


