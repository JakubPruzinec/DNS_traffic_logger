#include "dns_record_NS.h"

DnsRecordNS::DnsRecordNS()
{
}

DnsRecordNS::~DnsRecordNS()
{
}

std::string DnsRecordNS::getData(void) const
{
	return nameServer;
}

std::string DnsRecordNS::getType(void) const
{
	return "NS";
}

void DnsRecordNS::setNameServer(const std::string &ns)
{
	nameServer = ns;
}