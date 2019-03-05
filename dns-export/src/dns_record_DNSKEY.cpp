#include "dns_record_DNSKEY.h"

DnsRecordDNSKEY::DnsRecordDNSKEY() : flags(0), protocol(0), algorithm(0)
{
}

DnsRecordDNSKEY::~DnsRecordDNSKEY()
{
}

std::string DnsRecordDNSKEY::getData(void) const
{
	return std::to_string(flags) + " " + std::to_string(protocol) + " " + std::to_string(algorithm)
			+ " " + publicKey;
}

std::string DnsRecordDNSKEY::getType(void) const
{
	return "DNSKEY";
}

uint16_t DnsRecordDNSKEY::getFlags(void) const
{
	return flags;
}

uint8_t DnsRecordDNSKEY::getProtocol(void) const
{
	return protocol;
}

uint8_t DnsRecordDNSKEY::getAlgorithm(void) const
{
	return algorithm;
}

const std::string &DnsRecordDNSKEY::getPublicKey(void) const
{
	return publicKey;
}

void DnsRecordDNSKEY::setFlags(uint16_t f)
{
	flags = f;
}

void DnsRecordDNSKEY::setProtocol(uint8_t prot)
{
	protocol = prot;
}

void DnsRecordDNSKEY::setAlgorithm(uint8_t alg)
{
	algorithm = alg;
}

void DnsRecordDNSKEY::setPublicKey(const std::string &pubKey)
{
	publicKey = pubKey;
}
