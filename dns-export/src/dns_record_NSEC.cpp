#include "dns_record_NSEC.h"

DnsRecordNSEC::DnsRecordNSEC()
{
}

DnsRecordNSEC::~DnsRecordNSEC()
{
}

std::string DnsRecordNSEC::getData(void) const
{
	return nextDomainName + " " + typesBitmap;
}

std::string DnsRecordNSEC::getType(void) const
{
	return "NSEC";
}

const std::string &DnsRecordNSEC::getNextDomainName(void) const
{
	return nextDomainName;
}

const std::string &DnsRecordNSEC::getTypesBitmap(void) const
{
	return typesBitmap;
}

void DnsRecordNSEC::setNextDomainName(const std::string &name)
{
	nextDomainName = name;
}

void DnsRecordNSEC::setTypesBitmap(const std::string &types)
{
	typesBitmap = types;
}