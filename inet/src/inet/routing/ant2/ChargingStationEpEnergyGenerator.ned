//
// Generatore di energia della stazione di ricarica (correzioni sull'energia).
//
// Va inserito come sottomodulo "energyGenerator" di ogni drone, per esempio:
//   **.adh[*].energyGenerator.typename = "inet.routing.ant2.ChargingStationEpEnergyGenerator"
//   **.adh[*].energyGenerator.chargingPower = 100mW
//
// Fornisce alla batteria la potenza chargingPower SOLO quando il protocollo
// Ant2 lo accende (drone arrivato alla stazione di ricarica) e zero in tutti
// gli altri momenti. A differenza di AlternatingEpEnergyGenerator di INET,
// non si accende e spegne a intervalli fissi: lo comanda Ant2.
//

package inet.routing.ant2;

import inet.power.base.EpEnergyGeneratorBase;

simple ChargingStationEpEnergyGenerator extends EpEnergyGeneratorBase
{
    parameters:
        string energySinkModule = default("^.energyStorage"); // batteria del drone
        double chargingPower @unit(W) = default(100mW);       // potenza del caricatore della stazione (P_c)
        @class(power::ChargingStationEpEnergyGenerator);
}
