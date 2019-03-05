#include "dns_capture.h"
#include "global.h"

#include <pcap.h>
#include <thread>
#include <ctime>
#include <netdb.h>
#include <string.h>				// memcpy

#define SYSLOG_PORT		514

DnsCapture::DnsCapture() : syslogServerSock(-1)
{
}

DnsCapture::~DnsCapture()
{
	cleanUp();
}

/**
 * Parses a packet and stores it as a Statistic
 * @param packet The packet to parse
 * @param packetLen The length of the packet
 */
void DnsCapture::processPacket(const uint8_t *packet, std::size_t packetLen)
{
	const uint8_t	*packetEnd = &packet[packetLen];
	uint8_t			transProt = 0;

	if (!Parser::skipL2L3L4Headers(packet, packetEnd, transProt)) { return; }

	auto dnsPacket = Parser::parseDnsPacket(packet, packetEnd, transProt);

	if (!dnsPacket) { return; };

	for (const auto &answ : dnsPacket->getAnswers())
	{
		auto rName = answ->getRname();
		auto type = answ->getType();
		auto data = answ->getData();

		if (type.empty() || data.empty())
		{
			continue;
		}

		std::string statistic = rName + " " + type + " " + data;

		/* statistics are available */
		if (statisticsMutex.try_lock())
		{
			/* statistics are owned, store what you have buffered so far */
			for (const auto &s : statisticsBuffer)
			{
				addStatistic(s);
			}

			addStatistic(statistic);
			statisticsMutex.unlock();
		}

		/* statistics are being sent, thus not available */
		else
		{
			statisticsBuffer.push_back(statistic);
		}

	}
}

/**
 * A handler for pcap_loop
 * @param thisPtr a pointer to CaptureDns instance
 * @param hdr A pointer to pcap header
 * @param bytes A pointer to raw packet bytes
 */
void DnsCapture::loopHandler(uint8_t *thisPtr, const struct pcap_pkthdr *hdr, const uint8_t *bytes)
{
	auto thisDnsCapture = reinterpret_cast<DnsCapture *>(thisPtr);
	thisDnsCapture->processPacket(bytes, hdr->len);
}

/**
 * Adds statistic if it is the first of kind, otherwise increments it's counter
 * @param recordData DNS record data
 */
void DnsCapture::addStatistic(const std::string &recordData)
{
	auto it = statistics.find(recordData);

	if (it == statistics.end())
	{
		statistics.insert(std::make_pair(recordData, 1));
	}

	else
	{
		it->second++;
	}
}

/**
 * Sets syslogServerSock
 * @return Success flag
 */
bool DnsCapture::setSyslogServer(void)
{
	struct sockaddr_in server;
	struct hostent *he;

	syslogServerSock = socket(AF_INET, SOCK_DGRAM, 0);

	if (syslogServerSock < 0)
	{
		return false;
	}

	he = gethostbyname(global::syslogServer.c_str());

	if (!he)
	{
		return false;
	}


	memcpy(&server.sin_addr, he->h_addr_list[0], he->h_length);
	server.sin_family = AF_INET;
	server.sin_port = htons(SYSLOG_PORT);

	if (connect(syslogServerSock, reinterpret_cast<const struct sockaddr *>(&server), sizeof(server)) < 0)
	{
		return false;
	}

	return true;
}

/**
 * Sends statistics to syslog server
 * @return Sucess flag
 */
bool DnsCapture::sendStatisticsToSyslogServer(void) const
{
	bool noError = true;

	if (syslogServerSock < 0)
	{
		return false;
	}

	for (const auto &stat : statistics)
	{
		auto m = toSyslogMsg(stat.first, stat.second);

		if (send(syslogServerSock, m.c_str(), m.size(), 0) < 0)
		{
			noError = false;
		}
	}

	return noError;
}

/**
 * Parses the .pcap file and stores successfully parsed DNS resource records captures 
 * @return Success flag
 */
bool DnsCapture::parsePcapFile(void)
{
	char 				errbuff[PCAP_ERRBUF_SIZE];	// used as dummy here
	const uint8_t		*packet = nullptr;
	struct pcap_pkthdr	header;

	/* open the input file */
	if (!(global::handle = pcap_open_offline(global::pcapFile.c_str(), errbuff)))
	{
		return false;
	}

	/* iterate over captured packets */
	while ((packet = pcap_next(global::handle, &header)))
	{
		processPacket(packet, header.len);
	}

	if (!global::syslogServer.empty())
	{
		if (!hasOpenSocket() && !setSyslogServer())
		{
			std::cerr << "[ERR] Failed to open syslog server" << std::endl;
			return false;
		}

		sendStatisticsToSyslogServer();
	}

	else
	{
		dumpStatistics();
	}

	return true;
}

/**
 * A gatherer of DNS statistics
 * @return Success flag
 */
bool DnsCapture::captureTraffic(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];		// used as dummy here

	if (!(global::handle = pcap_open_live(global::interface.c_str(), BUFSIZ, SET_PROMISCUOUS_MODE, BUFFER_TIMEOUT,
											errbuf)))
	{
		std::cerr << "[ERR] live connection capturing failed. Check your privilege" << std::endl;
		return false;
	}

	std::thread t1(global::sender);

	if (!global::maskMainSignals())
	{
		std::cerr << "[ERR] Failed to set signal masks";
		return false;
	}

	while (1)
	{
		if (pcap_loop(global::handle, 0, loopHandler, reinterpret_cast<uint8_t *>(this)) == -1)
		{
			std::cerr << "[ERR] pcap_loop return error" << std::endl;
			t1.join();
			return false;
		}

		if (global::quit)
		{
			std::cerr << "[LOG] Will quit on next timeout" << std::endl;
			break;
		}

		if (global::userInt)
		{
			global::userInt = false;
			dumpStatistics();
			continue;
		}
	}

	t1.join();
	return true;
}

/**
 * Dumps statistics to standard output
 */
void DnsCapture::dumpStatistics(void) const
{
	for (const auto &stat : statistics)
	{
		std::cout << toSyslogMsg(stat.first, stat.second) << std::endl;
	}
}

/**
 * Wraps data to syslog message
 * @param data Data to be wrapped
 * @param count Count to be wrapped
 */
std::string DnsCapture::toSyslogMsg(const std::string &data, std::size_t count) const
{
	/* Source: https://stackoverflow.com/questions/16357999/current-date-and-time-as-string */
	time_t		rawtime;
	struct tm	*timeinfo;
	char		buffer[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S.003Z", timeinfo);
	std::string timeStamp(buffer);

	return "<134>1 " + timeStamp + " " + global::hostName
			+ " dns-export " + std::to_string(global::pid) + " - - - [" + data + "] " + std::to_string(count);
}

/**
 * Attempts to lock a mutex, the thread is NOT blocked
 * returns Succes flag
 */
bool DnsCapture::lockStatisticsMutex(void)
{
	return statisticsMutex.try_lock();
}

/**
 * Unlocks a mutex
 */
void DnsCapture::unlockStatisticsMutex(void)
{
	statisticsMutex.unlock();
}

/**
 * Indicates open socket
 * @return True on open socket, otherwise false
 */
bool DnsCapture::hasOpenSocket(void)
{
	return (syslogServerSock > 0);
}

/**
 * Cleans up strucutres
 */
void DnsCapture::cleanUp(void)
{
	if (hasOpenSocket())
	{
		close(syslogServerSock);
		syslogServerSock = -1;
	}
}