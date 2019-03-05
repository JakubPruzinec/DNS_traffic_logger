#ifndef _PARSER_H_
#define _PARSER_H_

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
// #include <linux/ipv6.h>
#include "ipv6.h"
#include <netinet/ip6.h>
#include <netinet/in.h>
#include "tcp.h"
#include "udp.h"

#include <memory>
#include "make_unique.h"

#include "dns.h"
#include "dns_packet.h"
#include "dns_question.h"
#include "dns_answer.h"
#include "dns_records.h"


/* https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers */
// the rest is not relevant
#define IP_HDR_HOPOPT			0
#define IP_HDR_PROTOCOL_TCP		6
#define IP_HDR_PROTOCOL_UDP		17
#define IP_HDR_IPV6_ROUTE		43
#define IP_HDR_IPV6_FRAG		44
#define IP_HDR_AH				55

class Parser
{
	private:
		static std::string parseDnsName(const uint8_t *&packet, const uint8_t *packetStart,
										const uint8_t *packetEnd, uint8_t n);

	public:
		Parser();
		~Parser();

		// HEADER PARSERS
		static bool parseEthernetHeader(const uint8_t *&packet, const uint8_t *packetEnd,
										struct ether_header &hdr, std::size_t &headerLen);
		static bool parseIPv4Header(const uint8_t *&packet, const uint8_t *packetEnd,
										struct ip &hdr, std::size_t &headerLen, uint8_t &transProt);
		static bool parseIPv6Header(const uint8_t *&packet, const uint8_t *packetEnd,
										uint8_t &transProt);
		static bool parseTcpHeader(const uint8_t *&packet, const uint8_t *packetEnd,
										struct tcphdr &hdr, std::size_t &headerLen);
		static bool parseUdpHeader(const uint8_t *&packet, const uint8_t *packetEnd,
										struct udphdr &hdr, std::size_t &headerLen);
		static bool parseDnsHeader(const uint8_t *&packet, const uint8_t *packetEnd,
										struct dnshdr &hdr, std::size_t &headerLen);

		// DNS BODY PARSERS
		static std::unique_ptr<DnsPacket> parseDnsPacket(const uint8_t *&packet, const uint8_t *packetEnd,
															uint8_t transProt);

		static std::unique_ptr<DnsQuestion> parseDnsQuestion(const uint8_t *&packet, const uint8_t *packetStart,
															const uint8_t *packetEnd);
		static std::unique_ptr<DnsAnswer> parseDnsAnswer(const uint8_t *&packet, const uint8_t *packetStart,
															const uint8_t *packetEnd);

		static std::unique_ptr<DnsRecordA> parseDnsRecordA(const uint8_t *&packet, const uint8_t *packetEnd);
		static std::unique_ptr<DnsRecordAAAA> parseDnsRecordAAAA(const uint8_t *&packet, const uint8_t *packetEnd);
		static std::unique_ptr<DnsRecordNS> parseDnsRecordNS(const uint8_t *&packet, const uint8_t *packetStart,
														const uint8_t *packetEnd);
		static std::unique_ptr<DnsRecordCNAME> parseDnsRecordCNAME(const uint8_t *&packet, const uint8_t *packetStart,
														const uint8_t *packetEnd);
		static std::unique_ptr<DnsRecordSOA> parseDnsRecordSOA(const uint8_t *&packet, const uint8_t *packetStart,
														const uint8_t *packetEnd);
		static std::unique_ptr<DnsRecordMX> parseDnsRecordMX(const uint8_t *&packet, const uint8_t *packetStart,
														const uint8_t *packetEnd);
		static std::unique_ptr<DnsRecordTXT> parseDnsRecordTXT(const uint8_t *&packet, const uint8_t *packetEnd);
		static std::unique_ptr<DnsRecordDNSKEY> parseDnsRecordDNSKEY(const uint8_t *&packet, const uint8_t *packetEnd,
																		uint16_t rdlength);
		static std::unique_ptr<DnsRecordRRSIG> parseDnsRecordRRSIG(const uint8_t *&packet, const uint8_t *packetStart,
																	const uint8_t *packetEnd, uint16_t rdlength);
		static std::unique_ptr<DnsRecordNSEC> parseDnsRecordNSEC(const uint8_t *&packet, const uint8_t *packetStart,
																	const uint8_t *packetEnd, uint16_t rdlength);
		static std::unique_ptr<DnsRecordDS> parseDnsRecordDS(const uint8_t *&packet, const uint8_t *packetEnd,
																uint16_t rdlength);

		static std::string parseDnsName(const uint8_t *&packet, const uint8_t *packetStart,
										const uint8_t *packetEnd);
		static std::string parseDnsBinary(const uint8_t *&packet, const uint8_t *packetEnd,
												uint16_t rdlength);

		// WRAPPERS
		static bool skipL2L3L4Headers(const uint8_t *&packet, const uint8_t *packetEnd, uint8_t &transProt);

		// DEBUG
		static void dumpEthernetHeader(const struct ether_header &hdr);
		static void dumpIPv4Header(const struct ip &hdr);
		static void dumpIPv6Header(const struct ipv6hdr &hdr);
		static void dumpTcpHeader(const struct tcphdr &hdr);
		static void dumpUdpHeader(const struct udphdr &hdr);
		static void dumpDnsHeader(const struct dnshdr &hdr);
		static void dumpDnsPacket(const DnsPacket &packet);
};

#endif