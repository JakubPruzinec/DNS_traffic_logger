#include "dns_record_DS.h"

DnsRecordDS::DnsRecordDS()
{
}

DnsRecordDS::~DnsRecordDS()
{
}

std::string DnsRecordDS::getData(void) const
{
	return std::to_string(keyTag) + " " + std::to_string(algorithm) + " " + std::to_string(digestType) + " " + digest;
}

std::string DnsRecordDS::getType(void) const
{
	return "DS";
}

uint16_t DnsRecordDS::getKeyTag(void) const
{
	return keyTag;	
}

uint8_t DnsRecordDS::getAlgorithm(void) const
{
	return algorithm;	
}

uint8_t DnsRecordDS::getDigestType(void) const
{
	return digestType;	
}

const std::string &DnsRecordDS::getDigest(void) const
{
	return digest;	
}


void DnsRecordDS::setKeyTag(uint16_t tag)
{
	keyTag = tag;
}

void DnsRecordDS::setAlgorithm(uint8_t alg)
{
	algorithm = alg;
}

void DnsRecordDS::setDigestType(uint8_t type)
{
	digestType = type;
}

void DnsRecordDS::setDigest(const std::string &dig)
{
	digest = dig;
}
