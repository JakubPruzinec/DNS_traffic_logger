#ifndef _DNS_H_
#define _DNS_H_

/*
	Source: https://0x00sec.org/t/dns-header-for-c/618
*/
#include <stdint.h>
#include <endian.h>
#include <string>
#include <vector>

struct dnshdr
{
	uint16_t id;
# if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t zero:3;
	uint16_t rcode:4;
# elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t zero:3;
	uint16_t ra:1;
# else
#  error "Adjust your <bits/endian.h> defines"
# endif
	uint16_t qcount;	/* question count */
	uint16_t ancount;	/* Answer record count */
	uint16_t nscount;	/* Name Server (Autority Record) Count */ 
	uint16_t adcount;	/* Additional Record Count */
} __attribute__((__packed__));


#define DNS_QTYPE_A				1
#define DNS_QTYPE_NS			2
#define DNS_QTYPE_CNAME			5
#define DNS_QTYPE_SOA			6
#define DNS_QTYPE_PTR			12
#define DNS_QTYPE_MX			15
#define DNS_QTYPE_TXT			16
#define DNS_QTYPE_RP			17
#define DNS_QTYPE_AFSDB			18
#define DNS_QTYPE_SIG			24
#define DNS_QTYPE_KEY			25
#define DNS_QTYPE_AAAA			28
#define DNS_QTYPE_LOC			29
#define DNS_QTYPE_SRV			33
#define DNS_QTYPE_NAPTR			35
#define DNS_QTYPE_KX			36
#define DNS_QTYPE_CERT			37
#define DNS_QTYPE_DNAME			39
#define DNS_QTYPE_OPT			41
#define DNS_QTYPE_APL			42
#define DNS_QTYPE_DS			43
#define DNS_QTYPE_SSHFP			44
#define DNS_QTYPE_IPSECKEY		45
#define DNS_QTYPE_RRSIG			46
#define DNS_QTYPE_NSEC			47
#define DNS_QTYPE_DNSKEY		48
#define DNS_QTYPE_DHCID			49
#define DNS_QTYPE_NSEC3			50
#define DNS_QTYPE_NSEC3PARAM	51
#define DNS_QTYPE_TLSA			52
#define DNS_QTYPE_HIP			55
#define DNS_QTYPE_CDS			59
#define DNS_QTYPE_CDNSKEY		60
#define DNS_QTYPE_TKEY			249
#define DNS_QTYPE_TSIG			250
#define DNS_QTYPE_IXFR			251
#define DNS_QTYPE_AXFR			252
#define DNS_QTYPE_ALL			255 /* AKA: * QTYPE */
#define DNS_QTYPE_URI			256
#define DNS_QTYPE_CAA			257
#define DNS_QTYPE_TA			32768
#define DNS_QTYPE_DLV			32769

/* DNS QCLASS */
#define DNS_QCLASS_RESERVED		0
#define DNS_QCLASS_IN			1
#define DNS_QCLASS_CH			3
#define DNS_QCLASS_HS			4
#define DNS_QCLASS_NONE			254
#define DNS_QCLASS_ANY			255

/* DNS QR */
#define DNS_QR_QUERY			0
#define DNS_QR_RESPONSE			1

/* DNS security extention algorithms */
#define DNS_DNSSEC_AL_RSAMD5		1
#define DNS_DNSSEC_AL_DH			2
#define DNS_DNSSEC_AL_DSA			3
#define DNS_DNSSEC_AL_ECC			4
#define DNS_DNSSEC_AL_RSASHA1		5
#define DNS_DNSSEC_AL_INDIRECT		252
#define DNS_DNSSEC_AL_PRIVATEDNS	253
#define DNS_DNSSEC_AL_PRIVATEOID	254

/* DNS name as a poiner */
#define DNS_IS_POINTER(n)			(static_cast<uint8_t>(n) & 0xC0)
#define DNS_OFFSET_FROM_POINTER(n)	(static_cast<uint16_t>(n) & 0x3FFF)

#endif