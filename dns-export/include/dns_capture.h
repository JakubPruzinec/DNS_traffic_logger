#ifndef _DNS_CAPTURE_H_
#define _DNS_CAPTURE_H_

#include <iostream>
#include <map>
#include <memory>
#include <mutex>

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include "tcp.h"
#include "udp.h"
#include <netinet/ip.h>

#include "parser.h"
#include "global.h"

#define SET_PROMISCUOUS_MODE	1
#define BUFFER_TIMEOUT			1000

class DnsCapture
{
	private:
		int syslogServerSock;
		std::map<std::string, std::size_t> statistics;
		std::vector<std::string> statisticsBuffer;			// vector for temporary storage of statistics
		std::mutex statisticsMutex;							// mutex for statistics used by a sender and a gatherer

		void processPacket(const uint8_t *packet, std::size_t packetLen);
		static void loopHandler(uint8_t *thisPtr, const struct pcap_pkthdr *hdr, const uint8_t *bytes);

	public:
		DnsCapture();
		~DnsCapture();

		void addStatistic(const std::string &recordData);
		bool setSyslogServer(void);
		bool sendStatisticsToSyslogServer(void) const;
		bool parsePcapFile(void);
		bool captureTraffic(void);
		void dumpStatistics(void) const;
		std::string toSyslogMsg(const std::string &data, std::size_t count) const;
		bool lockStatisticsMutex(void);
		void unlockStatisticsMutex(void);
		bool hasOpenSocket(void);
		void cleanUp(void);
};

#endif