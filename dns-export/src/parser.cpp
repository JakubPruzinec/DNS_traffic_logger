#include <iostream>
#include <string.h>		// memcpy

#include "parser.h"
#include "utils.h"


Parser::Parser()
{
}

Parser::~Parser()
{
}

/**
 * Parses the Ethernet Header
 * @param packet A pointer to raw header data
 * @param packetEnd A pointer iteration stopmark
 * @param hdr A header structure to store data to
 * @param headerLen A variable to store the header length to
 * @return Success flag
 */
bool Parser::parseEthernetHeader(const uint8_t *&packet, const uint8_t *packetEnd,
								struct ether_header &hdr, std::size_t &headerLen)
{
	auto packetStart = packet;
	auto eHeader = reinterpret_cast<const struct ether_header *>(packet);

	if ((packet += sizeof(struct ether_header)) > packetEnd)
	{
		return false;
	}

	memcpy(hdr.ether_dhost, &eHeader->ether_dhost, sizeof(hdr.ether_dhost));
	memcpy(hdr.ether_shost, &eHeader->ether_shost, sizeof(hdr.ether_shost));
	hdr.ether_type = ntohs(eHeader->ether_type);

	headerLen = packet - packetStart;
	return true;
}

/**
 * Parses the IPv4 Header
 * @param packet A pointer to raw header data
 * @param packetEnd A pointer iteration stopmark
 * @param hdr A header structure to store data to
 * @param headerLen A variable to store the header length to
 * @param transProt A variable to store the result transport protocol to
 * @return Success flag
 */
bool Parser::parseIPv4Header(const uint8_t *&packet, const uint8_t *packetEnd,
							struct ip &hdr, std::size_t &headerLen, uint8_t &transProt)
{
	auto ipHeader = reinterpret_cast<const struct ip *>(packet);
	
	if (packet + sizeof(struct ip) > packetEnd)
	{
		return false;
	}

	hdr.ip_hl		= ipHeader->ip_hl;
	hdr.ip_v		= ipHeader->ip_v;
	hdr.ip_tos		= ipHeader->ip_tos;
	hdr.ip_len		= ntohs(ipHeader->ip_len);
	hdr.ip_id		= ntohs(ipHeader->ip_id);
	hdr.ip_off		= ntohs(ipHeader->ip_off);
	hdr.ip_ttl		= ipHeader->ip_ttl;
	hdr.ip_p		= ipHeader->ip_p;
	hdr.ip_sum		= ntohs(ipHeader->ip_sum);
	hdr.ip_src		= ipHeader->ip_src;			// network byteorder
	hdr.ip_dst		= ipHeader->ip_dst;			// network byteorder

	/* ip header length is the number of 4B words in header */
	if ((packet += hdr.ip_hl * 4) > packetEnd)
	{
		return false;
	}

	headerLen = hdr.ip_hl;
	transProt = hdr.ip_p;
	return true;
}

/**
 * Parses the IPv6 Header
 * @param packet A pointer to raw header data
 * @param packetEnd A pointer iteration stopmark
 * @param transProt A variable to store the result transport protocol to
 * @param headerLen A variable to store the header length to
 * @return Success flag
 */
bool Parser::parseIPv6Header(const uint8_t *&packet, const uint8_t *packetEnd,
							uint8_t &transProt)
{
	struct ipv6hdr fixedHeader;
	auto fh = reinterpret_cast<const struct ipv6hdr *>(packet);

	if (packet + sizeof(struct ipv6hdr) > packetEnd)
	{
		return false;
	}

	fixedHeader.priority = fh->priority;
	fixedHeader.version = fh->version;
	fixedHeader.flow_lbl[0] = fh->flow_lbl[0];		// network byteorder
	fixedHeader.flow_lbl[1] = fh->flow_lbl[1];
	fixedHeader.flow_lbl[2] = fh->flow_lbl[2];
	fixedHeader.payload_len = ntohs(fh->payload_len);
	fixedHeader.nexthdr = fh->nexthdr;
	fixedHeader.hop_limit = fh->hop_limit;
	fixedHeader.saddr = fh->saddr;					// network byteorder
	fixedHeader.daddr = fh->daddr;					// network byteorder

	/* jump over additional headers */
	uint8_t nextHdr = fixedHeader.nexthdr;
	uint8_t hdrLen = sizeof(struct ipv6hdr);

	while (nextHdr != IP_HDR_PROTOCOL_UDP && nextHdr != IP_HDR_PROTOCOL_TCP)
	{
		if (nextHdr != IP_HDR_HOPOPT && nextHdr != IP_HDR_IPV6_ROUTE && nextHdr != IP_HDR_IPV6_FRAG && IP_HDR_AH)
		{
			return false;
		}

		if ((packet += hdrLen) > packetEnd)
		{
			return false;
		}

		if (packet + sizeof(uint8_t) + sizeof(uint8_t) > packetEnd)
		{
			return false;
		}

		nextHdr = packet[0];
		hdrLen = packet[1];

		if (hdrLen == 0)
		{
			return false;
		}
	}

	if (nextHdr != IP_HDR_PROTOCOL_UDP && nextHdr != IP_HDR_PROTOCOL_TCP)
	{
		return false;
	}

	transProt = nextHdr;
	return true;
}

/**
 * Parses the Tcp Header
 * @param packet A pointer to raw header data
 * @param packetEnd A pointer iteration stopmark
 * @param hdr A header structure to store data to
 * @param headerLen A variable to store the header length to
 * @return Success flag
 */
bool Parser::parseTcpHeader(const uint8_t *&packet, const uint8_t *packetEnd,
							struct tcphdr &hdr, std::size_t &headerLen)
{
	auto tcpHeader = reinterpret_cast<const struct tcphdr *>(packet);

	if (packet + sizeof(struct tcphdr) > packetEnd)
	{
		return false;
	}

	hdr.th_sport = ntohs(tcpHeader->th_sport);
	hdr.th_dport = ntohs(tcpHeader->th_dport);
	hdr.th_seq = ntohl(tcpHeader->th_seq);
	hdr.th_ack = ntohl(tcpHeader->th_ack);
	hdr.th_off = tcpHeader->th_off;
	// the rest is not relevant even for debugging purpose

	/* the tcp header length is the number of 4B words in header */
	if ((packet += hdr.th_off * 4) > packetEnd)
	{
		return false;
	}

	headerLen = hdr.th_off;
	return true;
}

/**
 * Parses the Udp Header
 * @param packet A pointer to raw header data
 * @param packetEnd A pointer iteration stopmark
 * @param hdr A header structure to store data to
 * @param headerLen A variable to store the header length to
 * @return Success flag
 */
bool Parser::parseUdpHeader(const uint8_t *&packet, const uint8_t *packetEnd,
							struct udphdr &hdr, std::size_t &headerLen)
{
	auto packetStart = packet;
	auto udpHeader = reinterpret_cast<const struct udphdr *>(packet);

	if ((packet += sizeof(struct udphdr)) > packetEnd)
	{
		return false;
	}

	hdr.uh_sport = ntohs(udpHeader->uh_sport);
	hdr.uh_dport = ntohs(udpHeader->uh_dport);
	hdr.uh_ulen = ntohs(udpHeader->uh_ulen);
	hdr.uh_sum = ntohs(udpHeader->uh_sum);

	headerLen = packet - packetStart;
	return true;
}

/**
 * Parses the Dns Header
 * @param packet A pointer to raw header data
 * @param packetEnd A pointer iteration stopmark
 * @param hdr A header structure to store data to
 * @param headerLen A variable to store the header length to
 * @return Success flag
 */
bool Parser::parseDnsHeader(const uint8_t *&packet, const uint8_t *packetEnd,
							struct dnshdr &hdr, std::size_t &headerLen)
{
	auto packetStart = packet;
	auto dnsHeader = reinterpret_cast<const struct dnshdr *>(packet);

	if ((packet += sizeof(struct dnshdr)) > packetEnd)
	{
		return false;
	}


	hdr.id = ntohs(dnsHeader->id);
	hdr.qr = dnsHeader->qr;
	hdr.opcode = dnsHeader->opcode;
	hdr.aa = dnsHeader->aa;
	hdr.tc = dnsHeader->tc;
	hdr.rd = dnsHeader->rd;
	hdr.ra = dnsHeader->ra;
	hdr.zero = dnsHeader->zero;
	hdr.rcode = dnsHeader->rcode;
	hdr.qcount = ntohs(dnsHeader->qcount);
	hdr.ancount = ntohs(dnsHeader->ancount);
	hdr.nscount = ntohs(dnsHeader->nscount);
	hdr.adcount = ntohs(dnsHeader->adcount);

	headerLen = packet - packetStart;
	return true;
}


/**
 * Parses the Dns Packet
 * @param packet A pointer to raw header packet data (starting with dns header)
 * @param packetEnd A pointer iteration stopmark
 * @param transProt A transport protocol
 * @return Dns packet or nullptr on error
 */
std::unique_ptr<DnsPacket> Parser::parseDnsPacket(const uint8_t *&packet, const uint8_t *packetEnd,
													uint8_t transProt)
{
	std::size_t		headerLen;				// used as dummy here
	struct dnshdr	hdr;
	auto			packetStart = packet;

	/* skip 2B length field */
	if (transProt == IP_HDR_PROTOCOL_TCP)
	{
		if ((packet += 2) > packetEnd)
		{
			return nullptr;
		}
	}

	if (!parseDnsHeader(packet, packetEnd, hdr, headerLen))
	{
		return nullptr;
	}

	auto dnsPacket = std::make_unique<DnsPacket>();
	dnsPacket->setHeader(hdr);

	/* parse questions */
	for (uint16_t i = 0; i < hdr.qcount; i++)
	{
		auto question = parseDnsQuestion(packet, packetStart, packetEnd);
		if (question)
		{
			dnsPacket->addQuestion(std::move(question));
		}

		/* no point to proceed, return what you have so far */
		else
		{
			return dnsPacket;
		}
	}

	for (uint16_t i = 0; i < hdr.ancount; i++)
	{
		auto answer = parseDnsAnswer(packet, packetStart, packetEnd);
		if (answer)
		{
			dnsPacket->addAnswer(std::move(answer));
		}

		/* no point to proceed, return what you have so far */
		else
		{
			return dnsPacket;
		}
	}

	return dnsPacket;
}

/**
 * Parses the Dns Question
 * @param packet A pointer to raw dns data question
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @return Dns question or nullptr on error
 */
std::unique_ptr<DnsQuestion> Parser::parseDnsQuestion(const uint8_t *&packet, const uint8_t *packetStart,
														const uint8_t *packetEnd)
{
	std::string qname = parseDnsName(packet, packetStart, packetEnd);

	if (qname.empty())
	{
		return nullptr;
	}

	if (packet + sizeof(uint16_t) + sizeof(uint16_t) > packetEnd)
	{
		return nullptr;
	}

	auto question = std::make_unique<DnsQuestion>();
	question->setQname(qname);
	question->setQtype(ntohs(*reinterpret_cast<const uint16_t *>(packet)));
	packet += sizeof(uint16_t);
	question->setQclass(ntohs(*reinterpret_cast<const uint16_t *>(packet)));
	packet += sizeof(uint16_t);

	return question;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetEnd A pointer iteration stopmark
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordA> Parser::parseDnsRecordA(const uint8_t *&packet, const uint8_t *packetEnd)
{
	std::string address;

	if (packet + (sizeof(uint8_t) * 4) > packetEnd)
	{
		return nullptr;
	}

	for (uint8_t i = 0; i < 4; i++)
	{
		if (!address.empty())
		{
			address.push_back('.');
		}

		address += std::to_string(*packet);
		packet++;
	}

	auto r = std::make_unique<DnsRecordA>();
	r->setAddress(address);

	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetEnd A pointer iteration stopmark
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordAAAA> Parser::parseDnsRecordAAAA(const uint8_t *&packet, const uint8_t *packetEnd)
{
	std::string address;

	if (packet + (sizeof(uint8_t) * 16) > packetEnd)
	{
		return nullptr;
	}

	for (uint8_t i = 0; i < 16; i += 2)
	{
		if (!address.empty())
		{
			address.push_back(':');
		}

		address += utils::byteToHex(packet[0]);
		address += utils::byteToHex(packet[1]);

		packet += 2;
	}

	auto r = std::make_unique<DnsRecordAAAA>();
	r->setAddress(address);

	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordNS> Parser::parseDnsRecordNS(const uint8_t *&packet, const uint8_t *packetStart,
												const uint8_t *packetEnd)
{
	auto nameServer = parseDnsName(packet, packetStart, packetEnd);

	if (nameServer.empty())
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordNS>();
	r->setNameServer(nameServer);

	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordCNAME> Parser::parseDnsRecordCNAME(const uint8_t *&packet, const uint8_t *packetStart,
												const uint8_t *packetEnd)
{
	auto cName = parseDnsName(packet, packetStart, packetEnd);

	if (cName.empty())
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordCNAME>();
	r->setCname(cName);

	return r;	
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordSOA> Parser::parseDnsRecordSOA(const uint8_t *&packet, const uint8_t *packetStart,
												const uint8_t *packetEnd)
{
	auto mName = parseDnsName(packet, packetStart, packetEnd);

	if (mName.empty())
	{
		return nullptr;
	}

	auto rName = parseDnsName(packet, packetStart, packetEnd);

	if (rName.empty())
	{
		return nullptr;
	}

	if (packet + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) > packetEnd)
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordSOA>();
	r->setMname(mName);
	r->setRname(rName);
	r->setSerial(ntohl(*reinterpret_cast<const uint32_t *>(packet))); packet += sizeof(uint32_t);
	r->setRefresh(ntohl(*reinterpret_cast<const uint32_t *>(packet))); packet += sizeof(uint32_t);
	r->setRetry(ntohl(*reinterpret_cast<const uint32_t *>(packet))); packet += sizeof(uint32_t);
	r->setExpire(ntohl(*reinterpret_cast<const uint32_t *>(packet))); packet += sizeof(uint32_t);

	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordMX> Parser::parseDnsRecordMX(const uint8_t *&packet, const uint8_t *packetStart,
												const uint8_t *packetEnd)
{
	auto preference = reinterpret_cast<const uint16_t *>(packet);

	if ((packet += sizeof(uint16_t)) > packetEnd)
	{
		return nullptr;
	}

	auto mailServer = parseDnsName(packet, packetStart, packetEnd);

	if (mailServer.empty())
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordMX>();
	r->setPreference(ntohs(*preference));
	r->setMailServer(mailServer);

	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetEnd A pointer iteration stopmark
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordTXT> Parser::parseDnsRecordTXT(const uint8_t *&packet, const uint8_t *packetEnd)
{
	std::string text;

	auto nCharPtr = packet;

	if ((packet += sizeof(uint8_t)) > packetEnd)
	{
		return nullptr;
	}

	uint8_t nChars = *nCharPtr;

	if (packet + nChars > packetEnd)
	{
		return nullptr;
	}

	for (; nChars > 0; nChars--, packet++)
	{
		text.push_back(*packet);
	}

	if (nChars != 0)
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordTXT>();
	r->setText(text);

	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetEnd A pointer iteration stopmark
 * @param rdlength Length of answer data field
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordDNSKEY> Parser::parseDnsRecordDNSKEY(const uint8_t *&packet, const uint8_t *packetEnd,
																uint16_t rdlength)
{
	if (packet + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) > packetEnd)
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordDNSKEY>();
	r->setFlags(ntohs(*reinterpret_cast<const uint16_t *>(packet))); packet += sizeof(uint16_t);
	r->setProtocol(*packet); packet += sizeof(uint8_t);
	r->setAlgorithm(*packet); packet += sizeof(uint8_t);

	/* subtract the flags, protocol and algorithm field sizes */
	rdlength -= sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);
	std::string publicKey = parseDnsBinary(packet, packetEnd, rdlength);

	if (publicKey.empty())
	{
		return nullptr;
	}

	r->setPublicKey(publicKey);
	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @param rdlength Length of answer data field
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordRRSIG> Parser::parseDnsRecordRRSIG(const uint8_t *&packet, const uint8_t *packetStart,
																	const uint8_t *packetEnd, uint16_t rdlength)
{
	const uint8_t *recordStart = packet;

	if (packet + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t)
		 + sizeof(uint32_t) + sizeof(uint16_t) > packetEnd)
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordRRSIG>();

	r->setTypeCovered(ntohs(*reinterpret_cast<const uint16_t *>(packet))); packet += sizeof(uint16_t);
	r->setAlgorithm(*reinterpret_cast<const uint8_t *>(packet)); packet += sizeof(uint8_t);
	r->setLabels(*reinterpret_cast<const uint8_t *>(packet)); packet += sizeof(uint8_t);
	r->setOriginalTtl(ntohl(*reinterpret_cast<const uint32_t *>(packet))); packet += sizeof(uint32_t);
	r->setSignatureExpiration(ntohl(*reinterpret_cast<const uint32_t *>(packet))); packet += sizeof(uint32_t);
	r->setSignatureInception(ntohl(*reinterpret_cast<const uint32_t *>(packet))); packet += sizeof(uint32_t);
	r->setKeyTag(ntohs(*reinterpret_cast<const uint16_t *>(packet))); packet += sizeof(uint16_t);

	std::string signersName = parseDnsName(packet, packetStart, packetEnd);

	if (signersName.empty())
	{
		return nullptr;
	}

	r->setSignersName(signersName);

	rdlength -= packet - recordStart;
	std::string signature = parseDnsBinary(packet, packetEnd, rdlength);

	if (signature.empty())
	{
		return nullptr;
	}

	r->setSignature(signature);
	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @param rdlength Length of answer data field
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordNSEC> Parser::parseDnsRecordNSEC(const uint8_t *&packet, const uint8_t *packetStart,
															const uint8_t *packetEnd, uint16_t rdlength)
{
	const uint8_t *recordStart = packet;

	std::string nextDomainName = parseDnsName(packet, packetStart, packetEnd);

	if (nextDomainName.empty())
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordNSEC>();
	r->setNextDomainName(nextDomainName);

	rdlength -= packet - recordStart;

	if (rdlength)
	{
		auto typesBitmap = parseDnsBinary(packet, packetEnd, rdlength);

		if (typesBitmap.empty())
		{
			return nullptr;
		}

		r->setTypesBitmap(typesBitmap);
	}

	return r;
}

/**
 * Parses a Dns Record
 * @param packet A pointer to raw dns record data
 * @param packetEnd A pointer iteration stopmark
 * @param rdlength Length of answer data field
 * @return Dns Record or nullptr on error
 */
std::unique_ptr<DnsRecordDS> Parser::parseDnsRecordDS(const uint8_t *&packet, const uint8_t *packetEnd,
														uint16_t rdlength)
{
	if (packet + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) > packetEnd)
	{
		return nullptr;
	}

	auto r = std::make_unique<DnsRecordDS>();

	r->setKeyTag(ntohs(*reinterpret_cast<const uint16_t *>(packet))); packet += sizeof(uint16_t);
	r->setAlgorithm(*reinterpret_cast<const uint8_t *>(packet)); packet += sizeof(uint8_t);
	r->setDigestType(*reinterpret_cast<const uint8_t *>(packet)); packet += sizeof(uint8_t);

	rdlength -= sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t);

	std::string digest = parseDnsBinary(packet, packetEnd, rdlength);

	if (digest.empty())
	{
		return nullptr;
	}

	r->setDigest(digest);
	return r;
}


/**
 * Parses the Dns Answer
 * @param packet A pointer to raw dns data answer
 * @param packetStart The beginning of the DNS packet (dns header).
 * @param packetEnd A pointer iteration stopmark
 * @return Dns answer or nullptr on error
 */
std::unique_ptr<DnsAnswer> Parser::parseDnsAnswer(const uint8_t *&packet, const uint8_t *packetStart,
													const uint8_t *packetEnd)
{
	std::string rName = parseDnsName(packet, packetStart, packetEnd);

	if (rName.empty())
	{
		return nullptr;
	}

	if (packet + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t) > packetEnd)
	{
		return nullptr;
	}

	uint16_t rtype = ntohs(*reinterpret_cast<const uint16_t *>(packet)); packet += sizeof(uint16_t);
	uint16_t rclass = ntohs(*reinterpret_cast<const uint16_t *>(packet)); packet += sizeof(uint16_t);
	uint32_t rttl = ntohs(*reinterpret_cast<const uint32_t *>(packet)); packet += sizeof(uint32_t);
	uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t *>(packet)); packet += sizeof(uint16_t);

	std::unique_ptr<DnsAnswer> answer;

	switch (rtype)
	{
		case DNS_QTYPE_A:		answer = parseDnsRecordA(packet, packetEnd);
								break;
		case DNS_QTYPE_AAAA:	answer = parseDnsRecordAAAA(packet, packetEnd);
								break;
		case DNS_QTYPE_NS:		answer = parseDnsRecordNS(packet, packetStart, packetEnd);
								break;
		case DNS_QTYPE_CNAME:	answer = parseDnsRecordCNAME(packet, packetStart, packetEnd);
								break;
		case DNS_QTYPE_SOA:		answer = parseDnsRecordSOA(packet, packetStart, packetEnd);
								break;
		case DNS_QTYPE_MX:		answer = parseDnsRecordMX(packet, packetStart, packetEnd);
								break;
		case DNS_QTYPE_TXT:		answer = parseDnsRecordTXT(packet, packetEnd);
								break;
		case DNS_QTYPE_DNSKEY:	answer = parseDnsRecordDNSKEY(packet, packetEnd, rdlength);
								break;
		case DNS_QTYPE_RRSIG:	answer = parseDnsRecordRRSIG(packet, packetStart, packetEnd, rdlength);
								break;
		case DNS_QTYPE_DS:		answer = parseDnsRecordDS(packet, packetEnd, rdlength);
								break;

		default: 				answer = nullptr;
								break;
	}

	if (answer)
	{
		answer->setRname(rName);
		answer->setRtype(rtype);
		answer->setRclass(rclass);
		answer->setRttl(rttl);
		answer->setRdlength(rdlength);
	}

	return answer;
}

/**
 * Parses a domain name in Dns[Question|Answer] format.
 * @param packet A pointer to raw dns name
 * @param packetStart The beginning of the DNS packet (dns header). Used for pointer notation of a domain name
 * @param packetEnd A pointer iteration stopmark
 * @return Human readable domain name or an empty string on error
 */
std::string Parser::parseDnsName(const uint8_t *&packet, const uint8_t *packetStart, const uint8_t *packetEnd)
{
	return parseDnsName(packet, packetStart, packetEnd, 8);
}


/**
 * Parses a domain name in Dns[Question|Answer] format with specific depth.
 * @param packet A pointer to raw dns name
 * @param packetStart The beginning of the DNS packet (dns header). Used for pointer notation of a domain name
 * @param packetEnd A pointer iteration stopmark
 * @param n Depth to terminate infinite pointer following
 * @return Human readable domain name or an empty string on error
 */
std::string Parser::parseDnsName(const uint8_t *&packet, const uint8_t *packetStart,
									const uint8_t *packetEnd, uint8_t n)
{
	if (n == 0)
	{
		return "";
	}

	/* check for root domain name */
	if (packet != packetEnd && *packet == 0)
	{
		packet++;
		return "<root>";
	}

	std::string	domainName;

	uint8_t nChars = 0;
	for (; packet != packetEnd && *packet; packet++)
	{
		if (nChars == 0)
		{
			nChars = *packet;

			if (DNS_IS_POINTER(nChars))
			{
				auto pointer = reinterpret_cast<const uint16_t *>(packet);

				if ((packet += sizeof(uint16_t)) > packetEnd)
				{
					return "";
				}

				auto offset = DNS_OFFSET_FROM_POINTER(ntohs(*pointer));
				auto rest = packetStart + offset;

				if (rest >= packetEnd)
				{
					return "";
				}

				auto res = parseDnsName(rest, packetStart, packetEnd, n - 1);

				if (res.empty())
				{
					return "";
				}

				if (!domainName.empty())
				{
					domainName.push_back('.');
				}

				return domainName + res;
			}

			if (!domainName.empty())
			{
				domainName.push_back('.');
			}

			continue;
		}

		domainName.push_back(static_cast<char>(*packet));
		nChars--;
	}

	if (packet == packetEnd || *packet != 0)
	{
		return "";
	}

	packet++;
	return domainName;
}

/**
 * Parses a dns binary
 * @param packet A pointer to raw dns signature
 * @param packetEnd A pointer iteration stopmark
 * @param rdlength The length of signature
 * @return Signature in base64 format string or an empty string on error
 */
std::string Parser::parseDnsBinary(const uint8_t *&packet, const uint8_t *packetEnd,
												uint16_t rdlength)
{
	const uint8_t *signatureStart = packet;

	if ((packet += rdlength) > packetEnd)
	{
		return "";
	}

	return utils::encode(signatureStart, rdlength);
}

/**
 * Parses the link, network and transport layer headers
 * @param packet A pointer to the beggining of a raw packet data. Packet is set to point to L7 layer header.
 * @param packetEnd A pointer iteration stopmark
 * @param transProt A variable to store the result transport protocol to
 * @return Success flag
 */
bool Parser::skipL2L3L4Headers(const uint8_t *&packet, const uint8_t *packetEnd, uint8_t &transProt)
{
	struct ether_header	ethernetHeader;
	struct ip			ipHeader;
	struct tcphdr		tcpHeader;
	struct udphdr		udpHeader;
	std::size_t			headerLen;

	if (!parseEthernetHeader(packet, packetEnd, ethernetHeader, headerLen)) { return false; }

	if (ethernetHeader.ether_type == ETHERTYPE_IP)
	{
		if (!parseIPv4Header(packet, packetEnd, ipHeader, headerLen, transProt)) { return false; }

		if (transProt == IP_HDR_PROTOCOL_TCP)
		{
			if (!parseTcpHeader(packet, packetEnd, tcpHeader, headerLen)) { return false; }
			if (tcpHeader.th_sport != 53) { return false; }
		}

		else if (transProt == IP_HDR_PROTOCOL_UDP)
		{
			if (!parseUdpHeader(packet, packetEnd, udpHeader, headerLen)) { return false; }
			if (udpHeader.uh_sport != 53) { return false; }
		}

		/* unknown transport protocol */
		else
		{
			return false;
		}
	}
	
	else if (ethernetHeader.ether_type == ETHERTYPE_IPV6)
	{
		if (!Parser::parseIPv6Header(packet, packetEnd, transProt)) { return false; }

		if (transProt == IP_HDR_PROTOCOL_TCP)
		{
			if (!parseTcpHeader(packet, packetEnd, tcpHeader, headerLen)) { return false; }
			if (tcpHeader.th_sport != 53) { return false; }
		}

		else if (transProt == IP_HDR_PROTOCOL_UDP)
		{
			if (!parseUdpHeader(packet, packetEnd, udpHeader, headerLen)) { return false; }
			if (udpHeader.uh_sport != 53) { return false; }
		}

		else
		{
			return false;
		}
	}

	else
	{
		return false;
	}

	return true;
}



/**
 * Dumps the header to stderr
 */
void Parser::dumpEthernetHeader(const struct ether_header &hdr)
{
	std::string type;

	if (hdr.ether_type == ETHERTYPE_IP)
	{
		type = "ETHERTYPE_IP";
	}

	else if (hdr.ether_type == ETHERTYPE_IPV6)
	{
		type = "ETHERTYPE_IPV6";
	}

	else
	{
		type = "UNKNOWN";
	}

	std::cerr << "Ethernet_Source_MAC:\t"
		<< ether_ntoa(reinterpret_cast<const struct ether_addr *>(&hdr.ether_shost)) << std::endl;
	std::cerr << "Ethernet_Dest_MAC:\t"
		<< ether_ntoa(reinterpret_cast<const struct ether_addr *>(&hdr.ether_dhost)) << std::endl;
	std::cerr << "Ethernet_Type:\t\t" << type << std::endl;
}

/**
 * Dumps the header to stderr
 */
void Parser::dumpIPv4Header(const struct ip &hdr)
{
	std::string protocol;
	std::string sourceIP;
	std::string destIP;

	if (hdr.ip_p == IP_HDR_PROTOCOL_TCP)
	{
		protocol = "TCP";
	}

	else if (hdr.ip_p == IP_HDR_PROTOCOL_UDP)
	{
		protocol = "UDP";
	}

	else
	{
		protocol = "UNKNOWN";
	}

	sourceIP = inet_ntoa(hdr.ip_src);
	destIP = inet_ntoa(hdr.ip_dst);

	std::cerr << "IPv4_Header_length:\t" << hdr.ip_hl << std::endl;
	std::cerr << "IPv4_version:\t\t" << hdr.ip_v << std::endl;
	std::cerr << "IPv4_type_of_service:\t" << static_cast<uint16_t>(hdr.ip_tos) << std::endl;
	std::cerr << "IPv4_total_length:\t" << hdr.ip_len << std::endl;
	std::cerr << "IPv4_id:\t\t" << hdr.ip_id << std::endl;
	std::cerr << "IPv4_fragm_offset:\t" << hdr.ip_off << std::endl;
	std::cerr << "IPv4_time_to_live:\t" << static_cast<uint16_t>(hdr.ip_ttl) << std::endl;
	std::cerr << "IPv4_protocol:\t\t" << protocol << std::endl;
	std::cerr << "IPv4_checksum:\t\t" << hdr.ip_sum << std::endl;
	std::cerr << "IPv4_source_addr:\t" << sourceIP << std::endl;
	std::cerr << "IPv4_dest_addr:\t\t" << destIP << std::endl;
}

/**
 * Dumps the header to stderr
 */
void Parser::dumpIPv6Header(const struct ipv6hdr &hdr)
{
	std::cerr << "IPv6_priority:\t\t" << static_cast<uint16_t>(hdr.priority) << std::endl;
	std::cerr << "IPv6_version:\t\t" << static_cast<uint16_t>(hdr.version) << std::endl;
	std::cerr << "IPv6_flow_lbl:\t\t" << static_cast<uint16_t>(hdr.flow_lbl[0])
										<< static_cast<uint16_t>(hdr.flow_lbl[1])
										<< static_cast<uint16_t>(hdr.flow_lbl[2]) << std::endl;
	std::cerr << "IPv6_payload_len:\t" << hdr.payload_len << std::endl;
	std::cerr << "IPv6_nexthdr:\t\t" << static_cast<uint16_t>(hdr.nexthdr) << std::endl;
	std::cerr << "IPv6_hop_limit:\t\t" << static_cast<uint16_t>(hdr.hop_limit) << std::endl;
}

/**
 * Dumps the header to stderr
 */
void Parser::dumpTcpHeader(const struct tcphdr &hdr)
{
	std::cerr << "Tcp_source_port:\t" << hdr.th_sport << std::endl;
	std::cerr << "Tcp_dest_port:\t\t" << hdr.th_dport << std::endl;
	std::cerr << "Tcp_seq_num:\t\t" << hdr.th_seq << std::endl;
	std::cerr << "Tcp_ack_num:\t\t" << hdr.th_ack << std::endl;
	std::cerr << "Tcp_header_length:\t" << static_cast<uint16_t>(hdr.th_off) << std::endl;
}

/**
 * Dumps the header to stderr
 */
void Parser::dumpUdpHeader(const struct udphdr &hdr)
{
	std::cerr << "Udp_source_port:\t" << hdr.uh_sport << std::endl;
	std::cerr << "Udp_dest_port:\t\t" << hdr.uh_dport << std::endl;
	std::cerr << "Udp_length:\t\t" << hdr.uh_ulen << std::endl;
	std::cerr << "Udp_sum:\t\t" << hdr.uh_sum << std::endl;
}

/**
 * Dumps the header to stderr
 */
void Parser::dumpDnsHeader(const struct dnshdr &hdr)
{
	std::cerr << "Dns_id:\t\t\t" << hdr.id << std::endl;
	std::cerr << "Dns_qr:\t\t\t" << hdr.qr << std::endl;
	std::cerr << "Dns_opcode:\t\t" << hdr.opcode << std::endl;
	std::cerr << "Dns_aa:\t\t\t" << hdr.aa << std::endl;
	std::cerr << "Dns_tc:\t\t\t" << hdr.tc << std::endl;
	std::cerr << "Dns_rd:\t\t\t" << hdr.rd << std::endl;
	std::cerr << "Dns_ra:\t\t\t" << hdr.ra << std::endl;
	std::cerr << "Dns_zero:\t\t" << hdr.zero << std::endl;
	std::cerr << "Dns_rcode:\t\t" << hdr.rcode << std::endl;
	std::cerr << "Dns_qcount:\t\t" << hdr.qcount << std::endl;
	std::cerr << "Dns_ancount:\t\t" << hdr.ancount << std::endl;
	std::cerr << "Dns_nscount:\t\t" << hdr.nscount << std::endl;
	std::cerr << "Dns_adcount:\t\t" << hdr.adcount << std::endl;
}

/**
 * Dumps the dns packet to stderr
 */
void Parser::dumpDnsPacket(const DnsPacket &packet)
{
	dumpDnsHeader(packet.getHeader());
	packet.dump();
}