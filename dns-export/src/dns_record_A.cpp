#include "dns_record_A.h"

DnsRecordA::DnsRecordA()
{
}

DnsRecordA::~DnsRecordA()
{
}

std::string DnsRecordA::getData(void) const
{
	return address;
}

std::string DnsRecordA::getType(void) const
{
	return "A";
}

void DnsRecordA::setAddress(const std::string &addr)
{
	address = addr;
}