/* =====================================================================
 * v2v_radio_comparison.cc
 *
 * Measures application-layer latency and packet delivery ratio for the same
 * V2V safety-message workload over two radio access technologies:
 *
 *   --tech=dsrc   IEEE 802.11p / OCB, 10 MHz, direct one-hop broadcast.
 *
 *   --tech=cv2x   LTE Uu (network-scheduled, 3GPP "C-V2X mode 3"): each
 *                 vehicle is a UE; safety messages traverse uplink to the
 *                 eNB, through the EPC, and back down on the downlink to
 *                 peer vehicles.
 *
 * SCOPE, AND IT MATTERS FOR HOW THE RESULT IS REPORTED
 * ----------------------------------------------------
 * This is mode 3, NOT mode 4. C-V2X mode 4 is autonomous direct sidelink
 * with sensing-based semi-persistent scheduling, and it is the mode most V2V
 * papers mean by "C-V2X". Mainline ns-3 contains no sidelink/D2D model, and
 * the 5G-LENA `nr` module that does is not installed here, so mode 4 CANNOT
 * be simulated with this toolchain and is not attempted.
 *
 * The consequence is architectural and must be stated wherever the numbers
 * appear: mode 3 pays an uplink plus downlink traversal through the core
 * network, where DSRC pays one direct hop. Any latency difference measured
 * here is therefore a property of the ACCESS ARCHITECTURE, not evidence
 * about C-V2X sidelink performance. Reporting it as the latter would be
 * wrong.
 *
 * Mobility, vehicle count, message size and message rate are identical
 * across the two arms so the comparison isolates the access technology.
 *
 * Build: copy into <ns-3-root>/scratch/ and ./ns3 build
 *   Requires modules: wifi, lte, internet, mobility, applications.
 * ===================================================================== */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/lte-module.h"
#include "ns3/applications-module.h"
#include "ns3/point-to-point-module.h"

#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("V2vRadioComparison");

// Message payload: a sequence number and the true transmission time, so the
// receiver can compute one-way latency without a shared clock assumption
// beyond the simulator's global time.
#pragma pack(push, 1)
struct SafetyMsg
{
    uint32_t senderId;
    uint32_t seq;
    double   txTime;
};
#pragma pack(pop)

static const double ROAD_LEN = 5000.0;
static const double COMM_RANGE = 300.0;   // range used for the PDR denominator

static uint64_t g_sent = 0;          // transmissions attempted
static uint64_t g_expected = 0;      // in-range receiver opportunities
static uint64_t g_received = 0;      // in-range receptions counted
static double   g_latencySum = 0.0;
static uint64_t g_latencyN = 0;

/* Counts how many peers were within COMM_RANGE at transmission time. Using a
 * geometric denominator keeps PDR comparable across the two arms: the LTE arm
 * has no notion of radio range at the application layer, so counting actual
 * deliveries against "all peers" would flatter it. */
static uint64_t PeersInRange(uint32_t selfId)
{
    Ptr<MobilityModel> self = NodeList::GetNode(selfId)->GetObject<MobilityModel>();
    if (!self)
    {
        return 0;
    }
    Vector p = self->GetPosition();
    uint64_t n = 0;
    for (auto it = NodeList::Begin(); it != NodeList::End(); ++it)
    {
        Ptr<Node> node = *it;
        if (node->GetId() == selfId)
        {
            continue;
        }
        Ptr<MobilityModel> om = node->GetObject<MobilityModel>();
        if (om && CalculateDistance(p, om->GetPosition()) <= COMM_RANGE)
        {
            ++n;
        }
    }
    return n;
}

class SafetyApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("SafetyApp")
                                .SetParent<Application>()
                                .AddConstructor<SafetyApp>();
        return tid;
    }

    void Setup(uint32_t id, Address peerGroup, uint16_t port, double interval,
               uint32_t bytes, bool countRange)
    {
        m_id = id;
        m_peer = peerGroup;
        m_port = port;
        m_interval = interval;
        m_bytes = bytes;
        m_countRange = countRange;
    }

    void SetPeers(std::vector<Address> peers, std::vector<uint32_t> ids)
    {
        m_peers = std::move(peers);
        m_peerIds = std::move(ids);
    }

  private:
    void StartApplication() override
    {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->SetAllowBroadcast(true);
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
        m_socket->SetRecvCallback(MakeCallback(&SafetyApp::Receive, this));
        m_socket->Connect(m_peer);
        Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
        m_event = Simulator::Schedule(Seconds(jitter->GetValue(0.0, m_interval)),
                                      &SafetyApp::Send, this);
    }

    void StopApplication() override
    {
        Simulator::Cancel(m_event);
        if (m_socket)
        {
            m_socket->Close();
        }
    }

    void Send()
    {
        SafetyMsg m;
        m.senderId = m_id;
        m.seq = m_seq++;
        m.txTime = Simulator::Now().GetSeconds();

        Ptr<Packet> pkt =
            Create<Packet>(reinterpret_cast<uint8_t*>(&m), sizeof(SafetyMsg));
        if (m_bytes > sizeof(SafetyMsg))
        {
            pkt->AddPaddingAtEnd(m_bytes - sizeof(SafetyMsg));
        }
        if (m_peers.empty())
        {
            m_socket->Send(pkt);   // 802.11p: one broadcast reaches all
        }
        else
        {
            // LTE Uu carries no broadcast. Without MBMS, mode 3 must unicast
            // the same safety message to every peer, so one 10 Hz beacon
            // becomes N-1 transmissions through the uplink and back down.
            // That cost is a property of the architecture and is part of what
            // this comparison measures.
            // A real mode-3 V2X server knows subscriber positions and fans out
            // only to peers in the relevance area. Unicasting to every peer
            // regardless of distance would be a strawman, so the fan-out is
            // geo-filtered to the same COMM_RANGE the PDR denominator uses.
            Ptr<MobilityModel> self = GetNode()->GetObject<MobilityModel>();
            for (size_t k = 0; k < m_peers.size(); ++k)
            {
                Ptr<MobilityModel> om =
                    NodeList::GetNode(m_peerIds[k])->GetObject<MobilityModel>();
                if (self && om &&
                    CalculateDistance(self->GetPosition(), om->GetPosition()) >
                        COMM_RANGE)
                {
                    continue;
                }
                m_socket->SendTo(pkt->Copy(), 0, m_peers[k]);
            }
        }
        ++g_sent;
        if (m_countRange)
        {
            g_expected += PeersInRange(m_id);
        }
        m_event = Simulator::Schedule(Seconds(m_interval), &SafetyApp::Send, this);
    }

    void Receive(Ptr<Socket> socket)
    {
        Ptr<Packet> pkt;
        Address from;
        while ((pkt = socket->RecvFrom(from)))
        {
            if (pkt->GetSize() < sizeof(SafetyMsg))
            {
                continue;
            }
            SafetyMsg m;
            pkt->CopyData(reinterpret_cast<uint8_t*>(&m), sizeof(SafetyMsg));
            if (m.senderId == m_id)
            {
                continue;   // own broadcast echo
            }
            // Only count a delivery if the sender was in range at TX time,
            // matching the denominator.
            Ptr<MobilityModel> self = GetNode()->GetObject<MobilityModel>();
            Ptr<MobilityModel> src = NodeList::GetNode(m.senderId)->GetObject<MobilityModel>();
            if (self && src &&
                CalculateDistance(self->GetPosition(), src->GetPosition()) > COMM_RANGE)
            {
                continue;
            }
            ++g_received;
            g_latencySum += std::max(0.0, Simulator::Now().GetSeconds() - m.txTime);
            ++g_latencyN;
        }
    }

    uint32_t m_id = 0;
    Address  m_peer;
    uint16_t m_port = 0;
    double   m_interval = 0.1;
    uint32_t m_bytes = 320;
    bool     m_countRange = true;
    std::vector<Address> m_peers;   // empty => broadcast (802.11p)
    std::vector<uint32_t> m_peerIds;
    uint32_t m_seq = 0;
    Ptr<Socket> m_socket;
    EventId  m_event;
};

int main(int argc, char* argv[])
{
    std::string tech = "dsrc";
    uint32_t nVehicles = 70;
    double   simTime = 60.0;
    double   interval = 0.1;
    uint32_t bytes = 320;
    uint32_t runId = 1;

    CommandLine cmd(__FILE__);
    cmd.AddValue("tech", "dsrc | cv2x  (cv2x = LTE Uu, 3GPP mode 3)", tech);
    cmd.AddValue("nVehicles", "Number of vehicles", nVehicles);
    cmd.AddValue("simTime", "Simulation seconds", simTime);
    cmd.AddValue("interval", "Safety-message interval (s)", interval);
    cmd.AddValue("bsmBytes", "On-air message size (B)", bytes);
    cmd.AddValue("run", "RNG run number", runId);
    cmd.Parse(argc, argv);

    if ((tech != "dsrc" && tech != "cv2x") || nVehicles < 2 || simTime <= 1.0 ||
        interval <= 0.0 || runId == 0)
    {
        std::cerr << "ERROR: invalid configuration\n";
        return 2;
    }

    RngSeedManager::SetSeed(12345);
    RngSeedManager::SetRun(runId);

    Ptr<LteHelper> lte;
    Ptr<PointToPointEpcHelper> epc;
    if (tech == "cv2x")
    {
        lte = CreateObject<LteHelper>();
        epc = CreateObject<PointToPointEpcHelper>();
        lte->SetEpcHelper(epc);
        lte->SetAttribute("PathlossModel",
                          StringValue("ns3::LogDistancePropagationLossModel"));
    }

    NodeContainer vehicles;
    vehicles.Create(nVehicles);

    /* --- identical mobility in both arms ----------------------------- */
    const double kMaxSpeed = 33.0;
    double span = std::max(1.0, ROAD_LEN - kMaxSpeed * simTime);
    Ptr<UniformRandomVariable> u = CreateObject<UniformRandomVariable>();
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
    std::vector<double> speed(nVehicles), dir(nVehicles);
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        dir[i] = (i % 4 < 2) ? 1.0 : -1.0;
        double x = u->GetValue(0.0, span);
        if (dir[i] < 0.0)
        {
            x = ROAD_LEN - x;
        }
        pos->Add(Vector(x, (i % 4) * 3.5 - 5.25, 1.5));
        speed[i] = u->GetValue(20.0, kMaxSpeed);
    }
    MobilityHelper mobility;
    mobility.SetPositionAllocator(pos);
    mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobility.Install(vehicles);
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        vehicles.Get(i)->GetObject<ConstantVelocityMobilityModel>()->SetVelocity(
            Vector(speed[i] * dir[i], 0.0, 0.0));
    }

    uint16_t port = 8080;
    ApplicationContainer apps;

    if (tech == "dsrc")
    {
        /* --- IEEE 802.11p, direct one-hop broadcast -------------------- */
        YansWifiChannelHelper channel;
        channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
        channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                                   "Exponent", DoubleValue(2.5),
                                   "ReferenceLoss", DoubleValue(46.6777));
        channel.AddPropagationLoss("ns3::NakagamiPropagationLossModel");
        YansWifiPhyHelper phy;
        phy.SetChannel(channel.Create());
        phy.Set("TxPowerStart", DoubleValue(20.0));
        phy.Set("TxPowerEnd", DoubleValue(20.0));
        WifiHelper wifi;
        wifi.SetStandard(WIFI_STANDARD_80211p);
        wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
                                     "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));
        WifiMacHelper mac;
        mac.SetType("ns3::AdhocWifiMac");
        NetDeviceContainer devices = wifi.Install(phy, mac, vehicles);

        InternetStackHelper internet;
        internet.Install(vehicles);
        Ipv4AddressHelper address;
        address.SetBase("10.1.0.0", "255.255.0.0");
        address.Assign(devices);

        for (uint32_t i = 0; i < nVehicles; ++i)
        {
            Ptr<SafetyApp> app = CreateObject<SafetyApp>();
            app->Setup(vehicles.Get(i)->GetId(),
                       InetSocketAddress(Ipv4Address("10.1.255.255"), port),
                       port, interval, bytes, true);
            vehicles.Get(i)->AddApplication(app);
            app->SetStartTime(Seconds(1.0));
            app->SetStopTime(Seconds(simTime));
        }
    }
    else
    {
        /* --- LTE Uu: uplink -> eNB -> EPC -> downlink ------------------ */
        Ptr<Node> pgw = epc->GetPgwNode();

        // A remote host completes the EPC data path. Without it the PGW is
        // left partially configured and the stack asserts during setup.
        NodeContainer remoteHostContainer;
        remoteHostContainer.Create(1);
        InternetStackHelper internet;
        internet.Install(remoteHostContainer);
        PointToPointHelper p2ph;
        p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
        p2ph.SetDeviceAttribute("Mtu", UintegerValue(1500));
        p2ph.SetChannelAttribute("Delay", TimeValue(MilliSeconds(0)));
        NetDeviceContainer internetDevices =
            p2ph.Install(pgw, remoteHostContainer.Get(0));
        Ipv4AddressHelper ipv4h;
        ipv4h.SetBase("1.0.0.0", "255.0.0.0");
        ipv4h.Assign(internetDevices);
        Ipv4StaticRoutingHelper routingHelper;
        routingHelper.GetStaticRouting(
            remoteHostContainer.Get(0)->GetObject<Ipv4>())
            ->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

        NodeContainer enb;
        enb.Create(1);
        Ptr<ListPositionAllocator> enbPos = CreateObject<ListPositionAllocator>();
        enbPos->Add(Vector(ROAD_LEN / 2.0, 0.0, 25.0));
        MobilityHelper enbMob;
        enbMob.SetPositionAllocator(enbPos);
        enbMob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        enbMob.Install(enb);

        NetDeviceContainer enbDev = lte->InstallEnbDevice(enb);
        NetDeviceContainer ueDev = lte->InstallUeDevice(vehicles);
        internet.Install(vehicles);
        Ipv4InterfaceContainer ueIf =
            epc->AssignUeIpv4Address(NetDeviceContainer(ueDev));
        for (uint32_t i = 0; i < nVehicles; ++i)
        {
            routingHelper.GetStaticRouting(vehicles.Get(i)->GetObject<Ipv4>())
                ->SetDefaultRoute(epc->GetUeDefaultGatewayAddress(), 1);
        }
        lte->Attach(ueDev, enbDev.Get(0));

        for (uint32_t i = 0; i < nVehicles; ++i)
        {
            std::vector<Address> peers;
            std::vector<uint32_t> peerIds;
            for (uint32_t j = 0; j < nVehicles; ++j)
            {
                if (j != i)
                {
                    peers.push_back(InetSocketAddress(ueIf.GetAddress(j), port));
                    peerIds.push_back(vehicles.Get(j)->GetId());
                }
            }
            Ptr<SafetyApp> app = CreateObject<SafetyApp>();
            app->Setup(vehicles.Get(i)->GetId(),
                       InetSocketAddress(ueIf.GetAddress(i), port),
                       port, interval, bytes, true);
            app->SetPeers(peers, peerIds);
            vehicles.Get(i)->AddApplication(app);
            app->SetStartTime(Seconds(1.0));
            app->SetStopTime(Seconds(simTime));
        }
    }

    Simulator::Stop(Seconds(simTime + 1.0));
    Simulator::Run();

    double meanLatencyMs =
        g_latencyN ? (g_latencySum / g_latencyN) * 1000.0
                   : std::numeric_limits<double>::quiet_NaN();
    double pdr = g_expected ? double(g_received) / double(g_expected)
                            : std::numeric_limits<double>::quiet_NaN();

    std::cout << "\n===== V2V radio access comparison =====\n"
              << "technology     : " << tech
              << (tech == "cv2x" ? "  (LTE Uu, 3GPP mode 3 -- NOT sidelink mode 4)"
                                 : "  (IEEE 802.11p, direct one hop)")
              << "\nvehicles       : " << nVehicles
              << "\nrun            : " << runId
              << "\nmessages sent  : " << g_sent
              << "\nin-range opps  : " << g_expected
              << "\ndeliveries     : " << g_received
              << "\nmean latency ms: " << meanLatencyMs
              << "\nPDR            : " << pdr << "\n";

    std::cout << "RADIOCSV," << tech << "," << nVehicles << "," << runId << ","
              << simTime << "," << interval << "," << bytes << "," << g_sent
              << "," << g_expected << "," << g_received << "," << meanLatencyMs
              << "," << pdr << "\n";

    Simulator::Destroy();
    return 0;
}
