#include "dns_record_SOA.h"

DnsRecordSOA::DnsRecordSOA()
{
}

DnsRecordSOA::~DnsRecordSOA()
{
}

std::string DnsRecordSOA::getData(void) const
{
	return mName + " " + rName + " " + std::to_string(serial) + " " + std::to_string(refresh) + " "
				+ std::to_string(retry) + " " + std::to_string(expire);
}

std::string DnsRecordSOA::getType(void) const
{
	return "SOA";
}

void DnsRecordSOA::setMname(const std::string &mn)
{
	mName = mn;
}

void DnsRecordSOA::setRname(const std::string &rn)
{
	rName = rn;
}

void DnsRecordSOA::setSerial(uint32_t s)
{
	serial = s;
}

void DnsRecordSOA::setRefresh(uint32_t ref)
{
	refresh = ref;
}

void DnsRecordSOA::setRetry(uint32_t ret)
{
	retry = ret;
}

void DnsRecordSOA::setExpire(uint32_t exp)
{
	expire = exp;
}