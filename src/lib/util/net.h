#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Structures and functions for parsing raw network packets
 *
 * @file src/lib/util/net.h
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2014 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(net_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_LIBPCAP
#  include <pcap.h>
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/ethernet/ethernet.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/table.h>

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>

/*
 *	If we don't have libpcap, we still need an enumeration of link layers.
 */
#ifndef HAVE_LIBPCAP
typedef enum {
	DLT_RAW,
	DLT_NULL,
	DLT_LOOP,
	DLT_EN10MB,
	DLT_LINUX_SLL,
	DLT_PFLOG
} fr_dlt;
#endif

/*
 *	The number of bytes in an ethernet (MAC) address.
 */
#define ETHER_ADDR_LEN 	6

/*
 *	Length of a DEC/Intel/Xerox or 802.3 Ethernet header.
 *	Note that some compilers may pad "struct ether_header" to
 *	a multiple of 4 *bytes, for example, so "sizeof (struct
 *	ether_header)" may not give the right answer.
 *
 *	6 Byte SRC, 6 Byte DST, 2 Byte Ether type, 4 Byte CVID, 4 Byte SVID
 */
#define ETHER_HDR_LEN	22
#define IP_HDR_LEN	60

/*
 *	The number of bytes in a RADIUS packet header.
 */
#define RADIUS_HEADER_LENGTH	20

/*
 *	RADIUS packet length.
 *	RFC 2865, Section 3., subsection 'length' says:
 *	" ... and maximum length is 4096."
 */
#define MAX_RADIUS_LEN	4096
#define MIN_RADIUS_LEN	20
#define RADIUS_AUTH_VECTOR_LENGTH	16


#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)       (((ip)->ip_vhl & 0x0f) << 2)

#define IP_VHL(v, hl) ((v & 0x0f) << 4) | (hl & 0x0f)

#define	I_DF		0x4000		//!< Dont fragment flag.
#define IP_MF		0x2000		//!< More fragments flag.
#define IP_OFFMASK	0x1fff		//!< Mask for fragmenting bits.

/*
 *	Structure of an internet header, naked of options.
 */
typedef struct CC_HINT(__packed__) {
	uint8_t		ip_vhl;		//!< Header length, version.

	uint8_t		ip_tos;		//!< Type of service.
	uint16_t	ip_len;		//!< Total length.
	uint16_t	ip_id;		//!< identification.
	uint16_t	ip_off;		//!< Fragment offset field.

	uint8_t		ip_ttl;		//!< Time To Live.
	uint8_t		ip_p;		//!< Protocol.
	uint16_t	ip_sum;		//!< Checksum.
	struct in_addr	ip_src, ip_dst;	//!< Src and Dst address
} ip_header_t;

typedef struct CC_HINT(__packed__) {
	uint32_t	ip_vtcfl;	//!< Version, traffic class, flow label.
	uint16_t	ip_len;		//!< Payload length

	uint8_t		ip_next;	//!< Next header (protocol)
	uint8_t		ip_hopl;	//!< IP Hop Limit

	struct in6_addr ip_src, ip_dst;	//!< Src and Dst address
} ip_header6_t;

typedef struct CC_HINT(__packed__) {
	struct in6_addr ip_src, ip_dst;	//!< Src and Dst address
	uint32_t	ip_len;		//!< length
	uint32_t	ip_next;	//!< upper 24 bits must be zero
} ip_pseudo_header6_t;

/*
 *	UDP protocol header.
 *	Per RFC 768, September, 1981.
 */
typedef struct CC_HINT(__packed__) {
	uint16_t	src;		//!< Source port.
	uint16_t	dst;		//!< Destination port.
	uint16_t	len;		//!< UDP length.
	uint16_t	checksum;	//!< UDP checksum.
} udp_header_t;

extern fr_table_num_sorted_t const fr_net_ip_proto_table[];
extern size_t fr_net_ip_proto_table_len;
extern fr_table_num_sorted_t const fr_net_sock_type_table[];
extern size_t fr_net_sock_type_table_len;
extern fr_table_num_sorted_t const fr_net_af_table[];
extern size_t fr_net_af_table_len;

uint16_t	fr_udp_checksum(uint8_t const *data, uint16_t len, uint16_t checksum,
			 	struct in_addr const src_addr, struct in_addr const dst_addr);
int		fr_udp_header_check(uint8_t const *data, uint16_t remaining, ip_header_t const *ip);
uint16_t	fr_ip_header_checksum(uint8_t const *data, uint8_t ihl);
uint16_t	fr_ip6_pesudo_header_checksum(struct in6_addr const *src, struct in6_addr const *dst, uint16_t ip_len, uint8_t ip_next);

#ifdef __cplusplus
}
#endif
