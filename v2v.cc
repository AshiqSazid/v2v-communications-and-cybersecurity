#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/ipv4-global-routing-helper.h"

using namespace ns3;


NS_LOG_COMPONENT_DEFINE("V2VCybersecurity");


int
main(int argc, char *argv[])
{
    LogComponentEnable("V2VCybersecurity", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    NodeContainer vehicles;
    vehicles.Create(2);


    PointToPointHelper pointTopoint;
    pointTopoint.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    pointTopoint.SetChannelAttribute("Delay", StringValue("2ms"));


    NetDeviceContainer devices;
    devices = pointTopoint.Install(vehicles);


    InternetStackHelper internet;
    internet.Install(vehicles);


    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");


    Ipv4InterfaceContainer interfaces;
    interfaces = address.Assign(devices);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();


    uint16_t port = 8080;


    UdpEchoServerHelper echoServer(port);
    ApplicationContainer serverApps = echoServer.Install(vehicles.Get(1));
    serverApps.Start(Seconds(1.0));
    serverApps.Stop(Seconds(10.0));


    UdpEchoClientHelper echoClient(interfaces.GetAddress(1), port);
    echoClient.SetAttribute("MaxPackets", UintegerValue(5));
    echoClient.SetAttribute("Interval", TimeValue(Seconds(1.0)));
    echoClient.SetAttribute("PacketSize", UintegerValue(512));


    ApplicationContainer clientApps = echoClient.Install(vehicles.Get(0));
    clientApps.Start(Seconds(2.0));
    clientApps.Stop(Seconds(10.0));

    NS_LOG_INFO("Two V2V nodes created successfully.");
    NS_LOG_INFO("Vehicle 1 IP: " << interfaces.GetAddress(0));
    NS_LOG_INFO("Vehicle 2 IP: " << interfaces.GetAddress(1)); 


    bool suspiciousTraffic = false;

    std::string strideThreat = "None";

    int damage = 2;
    int reproducibility = 2;
    int exploitability = 1;
    int affectedUsers = 2;
    int discoverability = 1;


    int dreadScore = damage +
                     reproducibility +
                     exploitability +
                     affectedUsers +
                     discoverability;


    std::string dreadRisk;

    if (dreadScore >=15)
     {

        dreadRisk = "HIGH";
     }
     else if (dreadScore >= 10)
     {

        dreadRisk = "MEDIUM";
     }
     else
     {

       dreadRisk = "LOW";
     }


     double compromiseProbability = 0.0;


     if (dreadScore >= 15)
     {

         compromiseProbability = 0.90;

     }
     else if (dreadScore >= 10)
     {

         compromiseProbability = 0.60;

     }
    else
     {
          compromiseProbability = 0.20;
     }

     std::string systemDecision;


    if (compromiseProbability >= 0.50)
    {

         systemDecision = "COMPROMISED";
    }
    else
    {

         systemDecision = "TRUSTED";
    }



    if (suspiciousTraffic)
    {


        strideThreat = "Spoofing";

        NS_LOG_INFO("===========================================");
        NS_LOG_INFO("Detection Mechanism");
        NS_LOG_INFO("STRIDE Threat Identified : " << strideThreat);
        NS_LOG_INFO("Cybersecurity Alert");
        NS_LOG_INFO("Suspicious communication detected.");
        NS_LOG_INFO("===========================================");
    }
    else
    {
        NS_LOG_INFO("===========================================");
        NS_LOG_INFO("Detection Mechanism");
        NS_LOG_INFO("System status : NORMAL");
        NS_LOG_INFO("No suspicious traffic detected.");
        NS_LOG_INFO("STRIDE Threat Identified : " <<strideThreat);
        NS_LOG_INFO("Damage Potential : " << damage);
        NS_LOG_INFO("Reproducibility : " << reproducibility);
        NS_LOG_INFO("Exploitability :  " << exploitability);
        NS_LOG_INFO("Affected Users : " << affectedUsers);
        NS_LOG_INFO("Discoverability : " << discoverability);
        NS_LOG_INFO("DREAD Score : " << dreadScore);
        NS_LOG_INFO("DREAD Risk Level : " << dreadRisk);
        NS_LOG_INFO("Bayesian Probability of Compromise : " << compromiseProbability);
        NS_LOG_INFO("Bayesian Decision : " << systemDecision);
        NS_LOG_INFO("===========================================");
    }


 
    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();


    return 0;
}
