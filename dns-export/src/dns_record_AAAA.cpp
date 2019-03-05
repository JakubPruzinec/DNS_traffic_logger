#include "dns_record_AAAA.h"

DnsRecordAAAA::DnsRecordAAAA()
{
}

DnsRecordAAAA::~DnsRecordAAAA()
{
}

std::string DnsRecordAAAA::getData(void) const
{
	return address;
}

std::string DnsRecordAAAA::getType(void) const
{
	return "AAAA";
}

void DnsRecordAAAA::setAddress(const std::string &addr)
{
	address = addr;
}