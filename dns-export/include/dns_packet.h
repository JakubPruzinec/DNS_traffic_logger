#ifndef _DNS_PACKET_H_
#define _DNS_PACKET_H_

#include <vector>
#include <memory>

#include "dns.h"
#include "dns_question.h"
#include "dns_answer.h"

class DnsPacket
{
	private:
		struct dnshdr header;
		std::vector<std::unique_ptr<DnsQuestion>> questions;
		std::vector<std::unique_ptr<DnsAnswer>> answers;

	public:
		DnsPacket();
		~DnsPacket();

		const struct dnshdr &getHeader(void) const;
		const std::vector<std::unique_ptr<DnsQuestion>> &getQuestions(void) const;
		const std::vector<std::unique_ptr<DnsAnswer>> &getAnswers(void) const;

		void setHeader(const struct dnshdr &hdr);

		void addQuestion(std::unique_ptr<DnsQuestion>&& question);
		void addAnswer(std::unique_ptr<DnsAnswer>&& answer);

		void dump(void) const;
};

#endif