// 
//                  Simu5G
//
// Authors: Giovanni Nardini, Giovanni Stea, Antonio Virdis (University of Pisa)
// 
// This file is part of a software released under the license included in file
// "license.pdf". Please read LICENSE and README files before using it.
// The above files and the present reference are part of the software itself, 
// and cannot be removed from it.
// 
package simu5g.simulations.Simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.networklayer.ipv4.RoutingTableRecorder;
import inet.node.ethernet.Eth10G;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import simu5g.common.binder.Binder;
import simu5g.common.carrierAggregation.CarrierAggregation;
import simu5g.nodes.Upf;
import simu5g.nodes.NR.gNodeB;
import simu5g.nodes.NR.NRUe;
import simu5g.nodes.backgroundCell.BackgroundCell;
import simu5g.world.radio.LteChannelControl;


// ADDED
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;
import inet.node.inet.AdhocHost;
import inet.mobility.static.StationaryMobility;
import inet.node.inet.ManetRouter;
import inet.visualizer.common.IntegratedMultiVisualizer;
import inet.visualizer.canvas.integrated.IntegratedCanvasVisualizer;

// SingleCell_standalone
//
// This network represents the deployment option 3 in 3GPP 38.801
//
network Test
{
    parameters:
        int numUe = default(25);
        int numBgCells = default(0);
        int numgNb = default(5);
        @display("i=block/network2;bgb=1000,1000;bgi=background/pisa");
    submodules:
        channelControl: LteChannelControl {
            @display("p=50,25;is=s");
        }
        routingRecorder: RoutingTableRecorder {
            @display("p=50,75;is=s");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=50,125");
        }
        binder: Binder {
            @display("p=50,175;is=s");
        }
        carrierAggregation: CarrierAggregation {
            @display("p=50.993748,258.7;is=s");
        }
        server[numUe]: StandardHost {
            @display("p=212,118;is=n;i=device/server");
        }
        router: Router {
            @display("p=363.175,115.66875;i=device/smallrouter");
        }
        upf: Upf {
            @display("p=527.35,116.9125");
        }
        iUpf: Upf {
            @display("p=725,118");
        }
        gnb0: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        gnb1: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        gnb2: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        gnb3: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        gnb4: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        bgCell[numBgCells]: BackgroundCell {
            @display("p=416,277;is=vl");
        }
        ue[numUe]: NRUe {
            @display("p=628.09375,411.68124");
        }
        
        // ADDED
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,100");
        }
        adh[numgNb]: ManetRouter {
            @display("p=400,250;i=device/smallrouter");
        }  
        gat: ManetRouter{
            @display("p=825,118;i=device/antennatower");
        }
        visualizer: IntegratedMultiVisualizer {
        //visualizer: IntegratedCanvasVisualizer {
            @display("p=38.461544,106.50889");
        }
        
    connections:
        router.pppg++ <--> Eth10G <--> upf.filterGate;
        upf.pppg++ <--> Eth10G <--> iUpf.pppg++;
        iUpf.pppg++ <--> Eth10G <--> gat.pppg++;
        
        gnb0.ppp <--> Eth10G <--> adh[0].pppg++;
        gnb0.x2++ <--> Eth10G <--> adh[0].pppg++;

        gnb1.ppp <--> Eth10G <--> adh[1].pppg++;
        gnb1.x2++ <--> Eth10G <--> adh[1].pppg++;

        gnb2.ppp <--> Eth10G <--> adh[2].pppg++;
        gnb2.x2++ <--> Eth10G <--> adh[2].pppg++;
        
        gnb3.ppp <--> Eth10G <--> adh[3].pppg++;
        gnb3.x2++ <--> Eth10G <--> adh[3].pppg++;
        
        gnb4.ppp <--> Eth10G <--> adh[4].pppg++;
        gnb4.x2++ <--> Eth10G <--> adh[4].pppg++;
        
        server[0].pppg++ <--> Eth10G <--> router.pppg++;
        server[1].pppg++ <--> Eth10G <--> router.pppg++;
        server[2].pppg++ <--> Eth10G <--> router.pppg++;
        server[3].pppg++ <--> Eth10G <--> router.pppg++;
        server[4].pppg++ <--> Eth10G <--> router.pppg++;
        server[5].pppg++ <--> Eth10G <--> router.pppg++;
        server[6].pppg++ <--> Eth10G <--> router.pppg++;
        server[7].pppg++ <--> Eth10G <--> router.pppg++;
        server[8].pppg++ <--> Eth10G <--> router.pppg++;
        server[9].pppg++ <--> Eth10G <--> router.pppg++;
        server[10].pppg++ <--> Eth10G <--> router.pppg++;
        server[11].pppg++ <--> Eth10G <--> router.pppg++;
        server[12].pppg++ <--> Eth10G <--> router.pppg++;
        server[13].pppg++ <--> Eth10G <--> router.pppg++;
        server[14].pppg++ <--> Eth10G <--> router.pppg++;
        server[15].pppg++ <--> Eth10G <--> router.pppg++;
        server[16].pppg++ <--> Eth10G <--> router.pppg++;
        server[17].pppg++ <--> Eth10G <--> router.pppg++;
        server[18].pppg++ <--> Eth10G <--> router.pppg++;
        server[19].pppg++ <--> Eth10G <--> router.pppg++;
        server[20].pppg++ <--> Eth10G <--> router.pppg++;
        server[21].pppg++ <--> Eth10G <--> router.pppg++;
        server[22].pppg++ <--> Eth10G <--> router.pppg++;
        server[23].pppg++ <--> Eth10G <--> router.pppg++;
        server[24].pppg++ <--> Eth10G <--> router.pppg++;


}
