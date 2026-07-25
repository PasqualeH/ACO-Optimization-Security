package simulations.simulations4;
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


import inet.linklayer.contract.ITunnelInterface;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.Eth100M;
import inet.node.ethernet.EthernetHub;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.inet.WirelessHost;
import inet.node.wireless.AccessPoint;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.showcases.tsn.framereplication.automaticfailureprotection.LocalTsnSwitch;
import inet.visualizer.contract.IIntegratedVisualizer;
import inet.node.inet.ManetRouter;
import inet.node.ethernet.Eth10G;
network Test4
{
    parameters:
        int numUes = default(1);
        int numUAVs = default(5);
    submodules:
        visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            @display("p=100,300;is=s");
        }
        configurator: Ipv4NetworkConfigurator;
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,200;is=s");
        }
        node[numUAVs]: AccessPoint {
            @display("p=400,250;i=device/smallrouter");
        }
        ue1[numUes]: WirelessHost {
            @display("p=628.09375,411.68124");
        }
        ue2[numUes]: WirelessHost {
            @display("p=628.09375,411.68124");
        }
        adh[numUAVs]: ManetRouter {
            @display("p=400,250;i=device/smallrouter");
        }
        router[numUAVs]: Router {
            @display("p=400,250;i=device/smallrouter");
        }
    connections:
        for i=0..numUAVs-1 {
            node[i].ethg++ <--> Eth10G <--> router[i].ethg++;
            router[i].pppg++ <--> Eth10G <--> adh[i].pppg++;
        }
}
