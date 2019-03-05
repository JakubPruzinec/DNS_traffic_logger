#include "dns_record_MX.h"

DnsRecordMX::DnsRecordMX() : preference(0)
{
}

DnsRecordMX::~DnsRecordMX()
{
}

std::string DnsRecordMX::getData(void) const
{
	return mailServer + " " + std::to_string(preference);
}

std::string DnsRecordMX::getType(void) const
{
	return "MX";
}

void DnsRecordMX::setPreference(uint16_t p)
{
	preference = p;
}

void DnsRecordMX::setMailServer(const std::string &ms)
{
	mailServer = ms;
}