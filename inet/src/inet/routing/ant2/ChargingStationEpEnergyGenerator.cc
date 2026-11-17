//
// Generatore di energia della stazione di ricarica (vedi il file .ned).
//
// Schema identico a AlternatingEpEnergyGenerator di INET: il generatore si
// registra presso la batteria (energySink) e, a ogni cambiamento di potenza,
// emette il segnale powerGenerationChanged; la batteria lo riceve e aggiorna
// la propria energia residua tenendo conto della potenza generata.
//

#include "inet/routing/ant2/ChargingStationEpEnergyGenerator.h"

namespace inet {
namespace power {

Define_Module(ChargingStationEpEnergyGenerator);

void ChargingStationEpEnergyGenerator::initialize(int stage)
{
    if (stage == INITSTAGE_LOCAL) {
        const char *energySinkModule = par("energySinkModule");
        energySink = dynamic_cast<IEpEnergySink *>(getModuleByPath(energySinkModule));
        if (!energySink)
            throw cRuntimeError("Energy sink module '%s' not found", energySinkModule);
        chargingPower = W(par("chargingPower"));
        charging = false;
        updatePowerGeneration();
        WATCH(charging);
        WATCH(powerGeneration);
    }
    else if (stage == INITSTAGE_POWER)
        energySink->addEnergyGenerator(this);
}

void ChargingStationEpEnergyGenerator::handleMessage(cMessage *message)
{
    throw cRuntimeError("ChargingStationEpEnergyGenerator non riceve messaggi");
}

void ChargingStationEpEnergyGenerator::setCharging(bool on)
{
    Enter_Method("setCharging(%s)", on ? "true" : "false");
    if (on == charging)
        return;
    charging = on;
    updatePowerGeneration();
}

void ChargingStationEpEnergyGenerator::updatePowerGeneration()
{
    powerGeneration = charging ? chargingPower : W(0);
    emit(IEpEnergyGenerator::powerGenerationChangedSignal, powerGeneration.get());
    auto text = "power: " + powerGeneration.str();
    getDisplayString().setTagArg("t", 0, text.c_str());
}

} // namespace power
} // namespace inet
