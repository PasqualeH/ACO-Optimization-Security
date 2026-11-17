//
// Generatore di energia della stazione di ricarica (vedi il file .ned).
//

#ifndef __INET_CHARGINGSTATIONEPENERGYGENERATOR_H
#define __INET_CHARGINGSTATIONEPENERGYGENERATOR_H

#include "inet/power/contract/IEpEnergyGenerator.h"
#include "inet/power/contract/IEpEnergySink.h"

namespace inet {
namespace power {

class INET_API ChargingStationEpEnergyGenerator : public cSimpleModule, public IEpEnergyGenerator
{
  protected:
    IEpEnergySink *energySink = nullptr;
    W chargingPower = W(0);
    W powerGeneration = W(0);
    bool charging = false;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *message) override;
    void updatePowerGeneration();

  public:
    /** Accende (true) o spegne (false) la ricarica. Chiamato da Ant2. */
    void setCharging(bool on);
    bool isCharging() const { return charging; }
    W getChargingPower() const { return chargingPower; }

    virtual IEnergySink *getEnergySink() const override { return energySink; }
    virtual W getPowerGeneration() const override { return powerGeneration; }
};

} // namespace power
} // namespace inet

#endif
