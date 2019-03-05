#ifndef _DNS_RECORD_RRSIG_H_
#define _DNS_RECORD_RRSIG_H_

#include <iostream>
#include "dns_answer.h"

class DnsRecordRRSIG : public DnsAnswer
{
	uint16_t typeCovered;
	uint8_t algorithm;
	uint8_t labels;
	uint32_t originalTtl;
	uint32_t signatureExpiration;
	uint32_t signatureInception;
	uint16_t keyTag;
	std::string signersName;
	std::string signature;

	public:
		DnsRecordRRSIG();
		~DnsRecordRRSIG();

		virtual std::string getData(void) const override;
		virtual std::string getType(void) const override;

		uint16_t getTypeCovered(void) const;
		uint8_t getAlgorithm(void) const;
		uint8_t getLabels(void) const;
		uint32_t getOriginalTtl(void) const;
		uint32_t getSignatureExpiration(void) const;
		uint32_t getSignatureInception(void) const;
		uint16_t getKeyTag(void) const;
		const std::string &getSignersName(void) const;
		const std::string &getSignature(void) const;

		void setTypeCovered(uint16_t type);
		void setAlgorithm(uint8_t al);
		void setLabels(uint8_t lab);
		void setOriginalTtl(uint32_t ttl);
		void setSignatureExpiration(uint32_t expiration);
		void setSignatureInception(uint32_t inception);
		void setKeyTag(uint16_t tag);
		void setSignersName(const std::string &name);
		void setSignature(const std::string &signat);
};

#endif