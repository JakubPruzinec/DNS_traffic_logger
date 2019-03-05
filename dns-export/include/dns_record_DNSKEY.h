#ifndef _DNS_RECORD_DNSKEY_H_
#define _DNS_RECORD_DNSKEY_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordDNSKEY : public DnsAnswer
{
	uint16_t flags;
	uint8_t protocol;
	uint8_t algorithm;
	std::string publicKey;

	public:
		DnsRecordDNSKEY();
		~DnsRecordDNSKEY();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		uint16_t getFlags(void) const;
		uint8_t getProtocol(void) const;
		uint8_t getAlgorithm(void) const;
		const std::string &getPublicKey(void) const;
		
		void setFlags(uint16_t f);
		void setProtocol(uint8_t prot);
		void setAlgorithm(uint8_t alg);
		void setPublicKey(const std::string &pubKey);
};

#endif