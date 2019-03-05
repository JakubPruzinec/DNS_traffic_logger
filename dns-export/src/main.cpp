#include "main.h"

int main(int argc, char *argv[])
{
	if (!global::processCmdLine(argc, argv))
	{
		global::manual();
		return 1;
	}

	if (!global::initStructures())
	{
		std::cerr << "[ERR] Failed to initialize necessary structures" << std::endl;
		return 1;
	}

	global::dnsCapture = std::make_unique<DnsCapture>();

	if (!global::pcapFile.empty())
	{
		if (!global::dnsCapture->parsePcapFile())
		{
			std::cerr << "[ERR] Failed to parse the pcap file: " << global::pcapFile << std::endl;
			return 1;
		}
	}

	else
	{
		if (!global::dnsCapture->captureTraffic())
		{
			std::cerr << "[ERR] Failed to capture the DNS traffic" << std::endl;
			return 1;
		}
	}

	return 0;
}