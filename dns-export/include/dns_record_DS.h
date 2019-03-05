#ifndef _DNS_RECORD_DS_H_
#define _DNS_RECORD_DS_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordDS : public DnsAnswer
{
	uint16_t keyTag;
	uint8_t algorithm;
	uint8_t digestType;
	std::string digest;

	public:
		DnsRecordDS();
		~DnsRecordDS();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		uint16_t getKeyTag(void) const;
		uint8_t getAlgorithm(void) const;
		uint8_t getDigestType(void) const;
		const std::string &getDigest(void) const;

		void setKeyTag(uint16_t tag);
		void setAlgorithm(uint8_t alg);
		void setDigestType(uint8_t type);
		void setDigest(const std::string &dig);
};

#endif