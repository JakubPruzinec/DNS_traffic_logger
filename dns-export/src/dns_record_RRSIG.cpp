#include "dns_record_RRSIG.h"

DnsRecordRRSIG::DnsRecordRRSIG()
{
}

DnsRecordRRSIG::~DnsRecordRRSIG()
{
}

std::string DnsRecordRRSIG::getData(void) const
{
	return std::to_string(typeCovered) + " " + std::to_string(algorithm) + " " + std::to_string(labels) + " "
			+ std::to_string(originalTtl) + " " + std::to_string(signatureExpiration) + " "
			+ std::to_string(signatureInception) + " " + std::to_string(keyTag) + " " + signersName + " " + signature;
}

std::string DnsRecordRRSIG::getType(void) const
{
	return "RRSIG";
}

uint16_t DnsRecordRRSIG::getTypeCovered(void) const
{
	return typeCovered;
}

uint8_t DnsRecordRRSIG::getAlgorithm(void) const
{
	return algorithm;
}

uint8_t DnsRecordRRSIG::getLabels(void) const
{
	return labels;
}

uint32_t DnsRecordRRSIG::getOriginalTtl(void) const
{
	return originalTtl;
}

uint32_t DnsRecordRRSIG::getSignatureExpiration(void) const
{
	return signatureExpiration;
}

uint32_t DnsRecordRRSIG::getSignatureInception(void) const
{
	return signatureInception;
}

uint16_t DnsRecordRRSIG::getKeyTag(void) const
{
	return keyTag;
}

const std::string &DnsRecordRRSIG::getSignersName(void) const
{
	return signersName;
}

const std::string &DnsRecordRRSIG::getSignature(void) const
{
	return signature;
}

void DnsRecordRRSIG::setTypeCovered(uint16_t type)
{
	typeCovered = type;
}

void DnsRecordRRSIG::setAlgorithm(uint8_t al)
{
	algorithm = al;
}

void DnsRecordRRSIG::setLabels(uint8_t lab)
{
	labels = lab;
}

void DnsRecordRRSIG::setOriginalTtl(uint32_t ttl)
{
	originalTtl = ttl;
}

void DnsRecordRRSIG::setSignatureExpiration(uint32_t expiration)
{
	signatureExpiration = expiration;
}

void DnsRecordRRSIG::setSignatureInception(uint32_t inception)
{
	signatureInception = inception;
}

void DnsRecordRRSIG::setKeyTag(uint16_t tag)
{
	keyTag = tag;
}

void DnsRecordRRSIG::setSignersName(const std::string &name)
{
	signersName = name;
}

void DnsRecordRRSIG::setSignature(const std::string &signat)
{
	signature = signat;
}
