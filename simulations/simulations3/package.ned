package simulations.simulations3;
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
network Test3
{
    parameters:
        int numUe = default(25);
        int numS = default(100);
        int numBgCells = default(0);
        int numgNb = default(9);
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
        server1[numS]: StandardHost {
            @display("p=212,118;is=n;i=device/server");
        }
        server2[numS]: StandardHost {
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
        gnb5: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        gnb6: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        gnb7: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        gnb8: gNodeB {
            @display("p=726.35,277.35626;i=device/antennatower");
        }
        bgCell[numBgCells]: BackgroundCell {
            @display("p=416,277;is=vl");
        }
        ue1[numUe]: NRUe {
            @display("p=628.09375,411.68124");
        }
        ue2[numUe]: NRUe {
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

        gnb5.ppp <--> Eth10G <--> adh[5].pppg++;
        gnb5.x2++ <--> Eth10G <--> adh[5].pppg++;
        
        gnb6.ppp <--> Eth10G <--> adh[6].pppg++;
        gnb6.x2++ <--> Eth10G <--> adh[6].pppg++;

        gnb7.ppp <--> Eth10G <--> adh[7].pppg++;
        gnb7.x2++ <--> Eth10G <--> adh[7].pppg++;
        
        gnb8.ppp <--> Eth10G <--> adh[8].pppg++;
        gnb8.x2++ <--> Eth10G <--> adh[8].pppg++;
        
        for i=0..numS-1 {
            server1[i].pppg++ <--> Eth10G <--> router.pppg++;
        }
        for i=0..numS-1 {
            server2[i].pppg++ <--> Eth10G <--> router.pppg++;
        }
}
@license(LGPL);
