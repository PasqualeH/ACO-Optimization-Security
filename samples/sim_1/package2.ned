package samples.sim_1;
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

// ADDED FOR SATELLITE
import scs.base.LaserSatellite2;
import scs.base.GroundStation;
import inet.physicallayer.wireless.common.contract.packetlevel.IRadioMedium;
import inet.physicallayer.wireless.apsk.packetlevel.ApskScalarRadioMedium;
import inet_leosatellites.networklayer.configurator.ipv4.SatelliteNetworkConfiguratorScs;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.visualizer.contract.IIntegratedVisualizer;

import inet.common.geometry.common.SimpleGeographicCoordinateSystem;
import inet.common.geometry.common.OsgGeographicCoordinateSystem;
import inet.environment.objectcache.GridObjectCache;

import inet_scs.physicallayer.apskradio.SatelliteScalarRadioMedium;
import inet.node.wireless.AccessPoint;
import inet.node.inet.Router;
import inet.node.ethernet.Eth10G;
import inet.node.inet.StandardHost;
import scs.common.binder.SBinder;
import scs_utils.converter.PositionConverter;


// SingleCell_standalone
//
// This network represents the deployment option 3 in 3GPP 38.801
//

network sim2
{
    parameters:
        int numUe = default(0); // Number of users
        int numS = default(0); // Number of servers
        int numBgCells = default(0);
        int numgNb = default(0); // Number of total UAVs (15)
        int numOfSats = default(1); // Number of satellites

        @display("bgi=background_earth;bgb=2160,1080");

    submodules:
        channelControl: LteChannelControl {
            @display("p=67.625,462.555;is=s");
        }
        routingRecorder: RoutingTableRecorder {
            @display("p=1457.995,70.33;is=s");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=1276.76,411.16");
        }
        binder: Binder {
            @display("p=1379.55,275.91;is=s");
        }
        carrierAggregation: CarrierAggregation {
            @display("p=50.993748,258.7;is=s");
        }
        server1[numS]: StandardHost {
            @display("p=286.73,338.125;is=n;i=device/server");
        }
        server2[numS]: StandardHost {
            @display("p=397.635,216.4;is=n;i=device/server");
        }
        router: Router {
            @display("p=286.73,21.64;i=device/smallrouter");
        }
        upf: Upf {
            @display("p=554.525,73.034996");
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
            @display("p=841.255,462.555;i=device/antennatower");
        }
        gnb7: gNodeB {
            @display("p=397.635,551.82;i=device/antennatower");
        }
        gnb8: gNodeB {
            @display("p=210.99,489.605;i=device/antennatower");
        }
        bgCell[numBgCells]: BackgroundCell {
            @display("p=1612.1799,357.06;is=vl");
        }
        ue1[numUe]: NRUe {
            @display("p=628.09375,411.68124");
        }
        ue2[numUe]: NRUe {
            @display("p=628.09375,411.68124");
        }

        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=546.41,254.27");
        }
        adh[numgNb]: ManetRouter {
            @display("p=660.02,600.51;i=device/smallrouter");
        }
        gat1: ManetRouter {
            @display("p=949.455,275.91;i=device/antennatower");
        }
        gat2: ManetRouter {
            @display("p=949.455,516.65497;i=device/antennatower");
        }
        gat3: ManetRouter {
            @display("p=1103.64,340.83;i=device/antennatower");
        }

        visualizer: IntegratedCanvasVisualizer {
            @display("p=1755.545,124.43");
        }

        // Added for cubesat support
        satellite[numOfSats]: LaserSatellite2 {
            parameters:
                @display("p=1152.33,146.06999;i=os3/satellit_blue");
        }
        Pos: PositionConverter {
            parameters:
                @display("p=94.675,335.42;i=onedot");
        }


    connections:
        router.pppg++ <--> Eth10G <--> upf.filterGate;
        upf.pppg++ <--> Eth10G <--> iUpf.pppg++;
        iUpf.pppg++ <--> Eth10G <--> gat1.pppg++;

        gnb0.ppp <--> {  datarate = 0.40Mbps; } <--> adh[0].pppg++;
        gnb0.x2++ <--> Eth10G <--> adh[0].pppg++;

        gnb1.ppp <--> {  datarate = 0.40Mbps; } <--> adh[1].pppg++;
        gnb1.x2++ <--> Eth10G <--> adh[1].pppg++;

        gnb2.ppp <--> {  datarate = 0.40Mbps; } <--> adh[2].pppg++;
        gnb2.x2++ <--> Eth10G <--> adh[2].pppg++;

        gnb3.ppp <--> {  datarate = 0.40Mbps; } <--> adh[3].pppg++;
        gnb3.x2++ <--> Eth10G <--> adh[3].pppg++;

        gnb4.ppp <--> {  datarate = 0.40Mbps; } <--> adh[4].pppg++;
        gnb4.x2++ <--> Eth10G <--> adh[4].pppg++;

        gnb5.ppp <--> {  datarate = 0.40Mbps; } <--> adh[5].pppg++;
        gnb5.x2++ <--> Eth10G <--> adh[5].pppg++;

        gnb6.ppp <--> {  datarate = 0.40Mbps; } <--> adh[6].pppg++;
        gnb6.x2++ <--> Eth10G <--> adh[6].pppg++;

        gnb7.ppp <--> {  datarate = 0.40Mbps; } <--> adh[7].pppg++;
        gnb7.x2++ <--> Eth10G <--> adh[7].pppg++;

        gnb8.ppp <--> {  datarate = 0.40Mbps; } <--> adh[8].pppg++;
        gnb8.x2++ <--> Eth10G <--> adh[8].pppg++;

        for i=0..numS-1 {
            server1[i].pppg++ <--> Eth10G <--> router.pppg++;
        }
        for i=0..numS-1 {
            server2[i].pppg++ <--> Eth10G <--> router.pppg++;
        }
}
@license(LGPL);
