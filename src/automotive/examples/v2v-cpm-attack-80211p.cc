/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
/*
 * Based on v2v-congestion-80211p.cc from the VaN3Twin framework
 * Original authors:
 *   Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 *   Junling Bu <linlinjavaer@gmail.com>
 *   Francesco Raviglione <francescorav.es483@gmail.com>
 *
 * Extended by:
 *   Matthias Krallinger (2026) - CPM attack simulation and IDS evaluation
 *   Developed with assistance from Claude Opus 4.6 (Anthropic), used as a coding aid.
 *   FH Salzburg, Bachelor's Thesis
 *
 * This file extends the original V2V scenario with:
 *   - CPM attribute manipulation (speed/heading) on configurable attacker vehicles
 *   - Rule-based Host-based IDS with plausibility checks on the receiver side
 *   - Dual logging of ground-truth and manipulated values for evaluation
 *   - Configurable attack start time (--attack-start)
 *   - Optional exclusion of attacker receivers from the evaluation (--eval-exclude-attackers)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "ns3/carla-module.h"
#include "ns3/vector.h"
#include "ns3/string.h"
#include "ns3/socket.h"
#include "ns3/double.h"
#include "ns3/config.h"
#include "ns3/log.h"
#include "ns3/command-line.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/position-allocator.h"
#include "ns3/mobility-helper.h"
#include <iostream>
#include <set>
#include <map>
#include <fstream>
#include "ns3/random-variable-stream.h"
#include "ns3/sumo_xml_parser.h"
#include "ns3/BSMap.h"
#include "ns3/caBasicService.h"
#include "ns3/btp.h"
#include "ns3/ocb-wifi-mac.h"
#include "ns3/wifi-80211p-helper.h"
#include "ns3/wave-mac-helper.h"
#include "ns3/packet-socket-helper.h"
#include "ns3/gn-utils.h"
#include "ns3/MetricSupervisor.h"
#include "ns3/DCC.h"

// Include the three CPM modules
#include "ns3/CPMAttackModule.h"
#include "ns3/CPMIDSModule.h"
#include "ns3/CPMEvalModule.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("V2VCPMAttack80211p");

// ====== Global variables ======
static int cam_packet_count = 0;
static int cpm_packet_count = 0;
BSMap basicServices;

// ====== Module instances ======
// Attack modules: one per vehicle (indexed by stationID)
static std::unordered_map<long, CPMAttackModule*> attackModules;
// IDS module: one per receiving vehicle
static std::unordered_map<long, CPMIDSModule*> idsModules;
// Evaluation module: global
static CPMEvalModule evalModule;
// Ground-truth logger: global (receiver-side, logs all received objects with GT label)
static CPMAttackModule groundTruthLogger;
// Set of attacker station IDs (for ground-truth labeling)
static std::set<long> attackerStationIds;
// If true, IDS decisions made by attacker vehicles (as receivers) are not counted
static bool evalExcludeAttackers = true;

// ====== Callbacks ======
void receiveCAM(asn1cpp::Seq<CAM> cam, Address from, StationID_t my_stationID,
                StationType_t my_StationType, SignalInfo phy_info)
{
    cam_packet_count++;
}

void receiveCPM(asn1cpp::Seq<CollectivePerceptionMessage> cpm, Address from,
                StationID_t my_stationID, StationType_t my_StationType, SignalInfo phy_info)
{
    cpm_packet_count++;

    // Get sender station ID from CPM header
    long senderStationId = asn1cpp::getField(cpm->header.stationId, long);

    // Ground truth: the CPM counts as manipulated only if the sender is an attacker
    // AND its attack had already started when the CPM was generated. hasStarted() is
    // set by the sender's first manipulated CPM, so CPMs generated before the attack
    // start keep the label "normal" even if they are received after it.
    bool isFromAttacker = (attackerStationIds.find(senderStationId) != attackerStationIds.end());
    bool wasManipulated = false;
    if (isFromAttacker) {
        auto atkIt = attackModules.find(senderStationId);
        wasManipulated = (atkIt != attackModules.end() && atkIt->second->hasStarted());
    }

    // Attackers still run the IDS, but their decisions can be left out of the metrics
    bool receiverIsAttacker = (attackerStationIds.count((long)my_stationID) > 0);
    bool countInEval = !(evalExcludeAttackers && receiverIsAttacker);

    // Get IDS module for this receiver
    auto idsIt = idsModules.find((long)my_stationID);
    if (idsIt == idsModules.end()) return;
    CPMIDSModule* ids = idsIt->second;

    // Iterate over CPM containers to find PerceivedObjectContainer
    int numContainers = asn1cpp::sequenceof::getSize(cpm->payload.cpmContainers);
    for (int c = 0; c < numContainers; c++) {
        auto container = asn1cpp::sequenceof::getSeq(cpm->payload.cpmContainers,
                                                      WrappedCpmContainer, c);
        if (!container) continue;

        long containerId = asn1cpp::getField(container->containerId, long);
        if (containerId != 5) continue; // 5 = PerceivedObjectContainer

        auto poc = asn1cpp::getSeq(container->containerData.choice.PerceivedObjectContainer,
                                    PerceivedObjectContainer);
        if (!poc) continue;

        int numObjects = asn1cpp::sequenceof::getSize(poc->perceivedObjects);
        for (int o = 0; o < numObjects; o++) {
            auto po = asn1cpp::sequenceof::getSeq(poc->perceivedObjects, PerceivedObject, o);
            if (!po) continue;

            long objectId = asn1cpp::getField(po->objectId, long);
            long posX = asn1cpp::getField(po->position.xCoordinate.value, long);
            long posY = asn1cpp::getField(po->position.yCoordinate.value, long);

            // Extract velocity
// Extract velocity (direct C struct access)
            long xSpeed = 0, ySpeed = 0;
            if (po->velocity) {
                if (po->velocity->present == Velocity3dWithConfidence_PR_cartesianVelocity) {
                    xSpeed = po->velocity->choice.cartesianVelocity.xVelocity.value;
                    ySpeed = po->velocity->choice.cartesianVelocity.yVelocity.value;
                }
            }

            // Extract heading (direct C struct access)
            long headingDeci = 3601; // unavailable default
            if (po->angles) {
                headingDeci = po->angles->zAngle.value;
            }

            // Run IDS evaluation
            IDSClassification idsResult = ids->evaluate(
                (long)my_stationID, senderStationId, objectId,
                posX, posY, xSpeed, ySpeed, headingDeci);
                
            // Log ground-truth for this received object
            double headingDeg = (headingDeci != 3601) ? headingDeci / 10.0 : -1.0;
            groundTruthLogger.logGroundTruth(senderStationId, objectId,
                                             xSpeed, ySpeed, headingDeg,
                                             wasManipulated);

            // Record in evaluation module
            if (countInEval) {
                bool flaggedAnomalous = (idsResult != IDS_NORMAL);
                evalModule.record(wasManipulated, flaggedAnomalous,
                                  Simulator::Now().GetMilliSeconds(),
                                  senderStationId, objectId);
            }
        }
    }
}


int main(int argc, char *argv[])
{
    std::string phyMode("OfdmRate6MbpsBW10MHz");
    int up = 0;
    bool verbose = false;
    int numberOfNodes;
    double m_baseline_prr = 150.0;
    int txPower = 33;
    xmlDocPtr rou_xml_file;
    double simTime = 120.0;

    // ====== Attack configuration (command-line configurable) ======
    double attackSpeedOffset = 100.0;   // km/h
    double attackHeadingOffset = 90.0;  // degrees
    double attackerPercentage = 20.0;   // percent of vehicles that are attackers
    std::string attackMode = "fixed";   // "fixed" | "fixed_random"
    double attackStart = 0.0;           // s, time from which attackers manipulate CPMs
    double idsSpeedThreshold = 150.0;   // km/h
    double idsHeadingTolerance = 45.0;  // degrees

    // SUMO files
    std::string sumo_folder = "src/automotive/examples/sumo_files_v2v_CPM_attack/";
    std::string mob_trace = "cars.rou.xml";
    std::string sumo_config = "src/automotive/examples/sumo_files_v2v_CPM_attack/crossroads.sumocfg";

    CommandLine cmd(__FILE__);
    cmd.AddValue("phyMode", "Wifi Phy mode", phyMode);
    cmd.AddValue("verbose", "turn on all WifiNetDevice log components", verbose);
    cmd.AddValue("userpriority", "EDCA User Priority", up);
    cmd.AddValue("baseline", "Baseline for PRR calculation", m_baseline_prr);
    cmd.AddValue("tx-power", "OBUs transmission power [dBm]", txPower);
    cmd.AddValue("sim-time", "Total duration of the simulation [s]", simTime);
    cmd.AddValue("attack-speed-offset", "Speed manipulation offset [km/h]", attackSpeedOffset);
    cmd.AddValue("attack-heading-offset", "Heading manipulation offset [degrees]", attackHeadingOffset);
    cmd.AddValue("attacker-percentage", "Percentage of attacker vehicles [%]", attackerPercentage);
    cmd.AddValue("attack-mode", "Offset mode: fixed | fixed_random (offsets act as max values)", attackMode);
    cmd.AddValue("attack-start", "Time from which attackers manipulate CPMs [s]", attackStart);
    cmd.AddValue("eval-exclude-attackers", "Exclude IDS decisions of attacker receivers from the evaluation", evalExcludeAttackers);
    cmd.AddValue("ids-speed-threshold", "IDS max plausible speed [km/h]", idsSpeedThreshold);
    cmd.AddValue("ids-heading-tolerance", "IDS heading consistency tolerance [degrees]", idsHeadingTolerance);
    cmd.Parse(argc, argv);

    // Load SUMO route file
    xmlInitParser();
    std::string path = sumo_folder + mob_trace;
    rou_xml_file = xmlParseFile(path.c_str());
    if (rou_xml_file == NULL) {
        NS_FATAL_ERROR("Error: unable to parse XML file: " << path);
    }
    numberOfNodes = XML_rou_count_vehicles(rou_xml_file);
    xmlFreeDoc(rou_xml_file);
    xmlCleanupParser();

    if (numberOfNodes == -1 || numberOfNodes < 2) {
        NS_FATAL_ERROR("Fatal error: need at least 2 vehicles. Found: " << numberOfNodes);
    }

    // ====== Determine attacker vehicles ======
    int numAttackers = (int)std::round(numberOfNodes * attackerPercentage / 100.0);
    std::cout << "Vehicles: " << numberOfNodes << ", Attackers: " << numAttackers
              << " (" << attackerPercentage << "%)" << std::endl;
    std::cout << "Attack config: speed_offset=" << attackSpeedOffset
              << " km/h, heading_offset=" << attackHeadingOffset << " deg"
              << ", start=" << attackStart << " s" << std::endl;
    std::cout << "Eval config: exclude_attacker_receivers="
              << (evalExcludeAttackers ? "true" : "false") << std::endl;
    std::cout << "IDS config: speed_threshold=" << idsSpeedThreshold
              << " km/h, heading_tolerance=" << idsHeadingTolerance << " deg" << std::endl;

    // Designate first N vehicles as attackers (veh1 .. vehN)
    for (int i = 1; i <= numAttackers; i++) {
        attackerStationIds.insert(i);
        std::cout << "  Vehicle veh" << i << " designated as ATTACKER" << std::endl;
    }

    // ====== Per-attacker offsets ======
    // fixed:        every attacker uses the configured offsets
    // fixed_random: each attacker draws its offsets once at start-up and keeps them;
    //               speed ~ U(0, attack-speed-offset), heading ~ U(-max, +max).
    //               Reproducible via ns-3 RNG: same --RngRun => same offsets.
    if (attackMode != "fixed" && attackMode != "fixed_random") {
        NS_FATAL_ERROR("Unknown --attack-mode: " << attackMode << " (use fixed | fixed_random)");
    }
    if (attackStart < 0.0 || attackStart >= simTime) {
        NS_FATAL_ERROR("--attack-start must be >= 0 and < --sim-time (" << simTime << " s)");
    }
    std::map<long, std::pair<double, double>> attackerOffsets; // stationId -> (speed km/h, heading deg)
    Ptr<UniformRandomVariable> offsetRng = CreateObject<UniformRandomVariable>();
    offsetRng->SetStream(1);
    double speedLo = std::min(0.0, attackSpeedOffset), speedHi = std::max(0.0, attackSpeedOffset);
    double headingMax = std::fabs(attackHeadingOffset);

    std::ofstream offsetLog("cpm_attacker_offsets.csv", std::ios::out | std::ios::trunc);
    offsetLog << "station_id,mode,speed_offset_kmh,heading_offset_deg,attack_start_s" << std::endl;
    for (long id : attackerStationIds) {   // std::set => ascending, deterministic draw order
        double speed = attackSpeedOffset, heading = attackHeadingOffset;
        if (attackMode == "fixed_random") {
            speed = offsetRng->GetValue(speedLo, speedHi);
            heading = offsetRng->GetValue(-headingMax, headingMax);
        }
        attackerOffsets[id] = {speed, heading};
        offsetLog << id << "," << attackMode << "," << speed << "," << heading
                  << "," << attackStart << std::endl;
        std::cout << "  veh" << id << " offsets: speed=" << speed
                  << " km/h, heading=" << heading << " deg" << std::endl;
    }
    offsetLog.close();

    // Create nodes
    NodeContainer c;
    c.Create(numberOfNodes);

    // ====== 802.11p Setup ======
    YansWifiPhyHelper wifiPhy;
    wifiPhy.Set("TxPowerStart", DoubleValue(txPower));
    wifiPhy.Set("TxPowerEnd", DoubleValue(txPower));
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    Ptr<YansWifiChannel> channel = wifiChannel.Create();
    wifiPhy.SetChannel(channel);
    wifiPhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11);

    QosWaveMacHelper wifi80211pMac = QosWaveMacHelper::Default();
    Wifi80211pHelper wifi80211p = Wifi80211pHelper::Default();
    if (verbose) wifi80211p.EnableLogComponents();

    wifi80211p.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                        "DataMode", StringValue(phyMode),
                                        "ControlMode", StringValue(phyMode),
                                        "NonUnicastMode", StringValue(phyMode));
    NetDeviceContainer devices = wifi80211p.Install(wifiPhy, wifi80211pMac, c);
    wifiPhy.EnablePcap("v2v-cpm-attack-80211p", devices);

    // ====== SUMO + TraCI Setup ======
    MobilityHelper mobility;
    mobility.Install(c);

    Ptr<TraciClient> sumoClient = CreateObject<TraciClient>();
    sumoClient->SetAttribute("SumoConfigPath", StringValue(sumo_config));
    sumoClient->SetAttribute("SumoBinaryPath", StringValue(""));
    sumoClient->SetAttribute("SynchInterval", TimeValue(Seconds(0.01)));
    sumoClient->SetAttribute("StartTime", TimeValue(Seconds(0.0)));
    sumoClient->SetAttribute("SumoGUI", BooleanValue(true));
    sumoClient->SetAttribute("SumoPort", UintegerValue(3400));
    sumoClient->SetAttribute("PenetrationRate", DoubleValue(1.0));
    sumoClient->SetAttribute("SumoLogFile", BooleanValue(false));
    sumoClient->SetAttribute("SumoStepLog", BooleanValue(false));
    sumoClient->SetAttribute("SumoSeed", IntegerValue(10));
    sumoClient->SetAttribute("SumoWaitForSocket", TimeValue(Seconds(1.5)));

    // ====== Metric Supervisor ======
    Ptr<MetricSupervisor> metSup = NULL;
    MetricSupervisor metSupObj(m_baseline_prr);
    metSup = &metSupObj;
    metSup->setTraCIClient(sumoClient);
    metSup->setChannelTechnology("80211p");
    metSup->setSimulationTimeValue(simTime);
    metSup->setNodeContainer(c);

    // ====== DCC Setup ======
    int dcc_nodes = numberOfNodes;
    std::unordered_map<Ptr<Node>, Ptr<DCC>> dcc_per_node;
    for (int i = 0; i < dcc_nodes; i++) {
        dcc_per_node[c.Get(i)] = CreateObject<DCC>();
    }
PacketSocketHelper packetSocket;
packetSocket.Install(c);

    std::cout << "\nStarting simulation..." << std::endl;

    // ====== Vehicle Setup Lambda ======
    STARTUP_FCN setupNewWifiNode = [&](std::string vehicleID,
                                       TraciClient::StationTypeTraCI_t stationType) -> Ptr<Node>
    {
        unsigned long nodeID = std::stol(vehicleID.substr(3)) - 1;
        long stationId = std::stol(vehicleID.substr(3));

        std::cout << "Setting up vehicle " << vehicleID
                  << (attackerStationIds.count(stationId) ? " [ATTACKER]" : " [BENIGN]")
                  << std::endl;

        std::cout << "  [DEBUG] Creating socket..." << std::endl;
        Ptr<Socket> sock = GeoNet::createGNPacketSocket(c.Get(nodeID));
        sock->SetPriority(up);

        std::cout << "  [DEBUG] Creating BSContainer..." << std::endl;
        Ptr<BSContainer> bs_container = CreateObject<BSContainer>(
            stationId, StationType_passengerCar, sumoClient, false, sock);
        bs_container->linkMetricSupervisor(metSup);
        bs_container->disablePRRSupervisorForGNBeacons();

        std::cout << "  [DEBUG] Setting callbacks..." << std::endl;
        bs_container->addCAMRxCallback(std::bind(&receiveCAM,
            std::placeholders::_1, std::placeholders::_2,
            std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));
        bs_container->addCPMRxCallback(std::bind(&receiveCPM,
            std::placeholders::_1, std::placeholders::_2,
            std::placeholders::_3, std::placeholders::_4, std::placeholders::_5));

        std::cout << "  [DEBUG] setupContainer..." << std::endl;
        bs_container->setupContainer(true, false, false, true, false, false);

        std::cout << "  [DEBUG] Creating attack module..." << std::endl;
        CPMAttackModule* atkMod = new CPMAttackModule();
        if (attackerStationIds.count(stationId)) {
            const auto &off = attackerOffsets.at(stationId);
            atkMod->enable(off.first, off.second);
            atkMod->setStartTime(Seconds(attackStart));
            atkMod->setLogFile("cpm_attack_log.csv");
        }
        attackModules[stationId] = atkMod;

        std::cout << "  [DEBUG] Linking attack module..." << std::endl;
        bs_container->getCPBasicService()->setAttackModule(atkMod);

        std::cout << "  [DEBUG] Creating IDS module..." << std::endl;
        CPMIDSModule* idsMod = new CPMIDSModule();
        idsMod->configure(idsSpeedThreshold, idsHeadingTolerance);
        idsMod->setLogFile("cpm_ids_log.csv");
        idsModules[stationId] = idsMod;

        basicServices.add(bs_container);

        std::cout << "  [DEBUG] Starting DCC..." << std::endl;
        Ptr<GeoNet> gn = bs_container->getGeoNet();
        if (dcc_per_node.find(c.Get(nodeID)) != dcc_per_node.end()) {
            dcc_per_node[c.Get(nodeID)]->SetupDCC(vehicleID, metSup, c.Get(nodeID), "adaptive", 200);
            dcc_per_node[c.Get(nodeID)]->setBitRate(6e6);
            gn->setDCC(dcc_per_node[c.Get(nodeID)]);
            dcc_per_node[c.Get(nodeID)]->StartDCC();
        }

        std::cout << "  [DEBUG] Starting dissemination..." << std::endl;
        std::srand(Simulator::Now().GetNanoSeconds() * 2);
        double desync = ((double)std::rand() / RAND_MAX);
        bs_container->getCABasicService()->startCamDissemination(desync);
        bs_container->getCPBasicService()->startCpmDissemination();

        std::cout << "  [DEBUG] Vehicle setup complete." << std::endl;
        return c.Get(nodeID);
    };

    // ====== Vehicle Shutdown Lambda ======
    SHUTDOWN_FCN shutdownWifiNode = [&](Ptr<Node> exNode, std::string vehicleID)
    {
        Ptr<ConstantPositionMobilityModel> mob = exNode->GetObject<ConstantPositionMobilityModel>();
        mob->SetPosition(Vector(-1000.0 + (rand() % 25), 320.0 + (rand() % 25), 250.0));

        unsigned long intVehicleID = std::stol(vehicleID.substr(3));
        Ptr<BSContainer> bsc = basicServices.get(intVehicleID);
        bsc->cleanup();
    };

    // Link ns-3 and SUMO
    sumoClient->SumoSetup(setupNewWifiNode, shutdownWifiNode);

    // Run simulation
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // ====== Output Results ======
    std::cout << "\nRun terminated." << std::endl;
    std::cout << "CAM RX: " << cam_packet_count << std::endl;
    std::cout << "CPM RX: " << cpm_packet_count << std::endl;
    std::cout << "RX overall: " << cam_packet_count + cpm_packet_count << std::endl;

    // Print and save evaluation
    evalModule.printSummary();
    evalModule.writeSummaryCSV("cpm_eval_summary.csv");
    evalModule.closeLog();
    groundTruthLogger.closeGroundTruthLog();

    // Cleanup attack and IDS modules
    for (auto &pair : attackModules) {
        pair.second->closeLog();
        delete pair.second;
    }
    for (auto &pair : idsModules) {
        pair.second->closeLog();
        delete pair.second;
    }

    Simulator::Destroy();
    return 0;
}
