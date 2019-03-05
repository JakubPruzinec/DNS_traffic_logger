#include "dns_record_CNAME.h"

DnsRecordCNAME::DnsRecordCNAME()
{
}

DnsRecordCNAME::~DnsRecordCNAME()
{
}

std::string DnsRecordCNAME::getData(void) const
{
	return cName;
}

std::string DnsRecordCNAME::getType(void) const
{
	return "CNAME";
}

void DnsRecordCNAME::setCname(const std::string &cn)
{
	cName = cn;
}