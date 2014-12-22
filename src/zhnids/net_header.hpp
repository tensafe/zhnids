#ifndef NET_HEADERS_HPP
#define NET_HEADERS_HPP
//#include <winsock.h>

namespace xzh
{
#define ETHER_ADDR_LEN 0x6
#define XZHNET_LIL_ENDIAN 1


	typedef unsigned char uint8_t;
	typedef unsigned short int uint16_t;
	typedef unsigned int uint32_t;
	typedef unsigned int uint;

#define XZHNET_ETH_H            0x0e    /**< Ethernet header:     14 bytes */
#define XZHNET_IPV4_H           0x14    /**< IPv4 header:         20 bytes */
#define XZHNET_TCP_H            0x14    /**< TCP header:          20 bytes */
#define XZHNET_UDP_H            0x08    /**< UDP header:           8 bytes */
	/*
	*  Ethernet II header
	*  Static header size: 14 bytes
	*/
	struct xzhnet_ethernet_hdr
	{
		uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
		uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
		uint16_t ether_type;                 /* protocol */
	};

#ifndef ETHERTYPE_PUP
#define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#define ETHERTYPE_IPV6          0x86dd  /* IPv6 protocol */
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
#endif
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_EAP
#define ETHERTYPE_EAP           0x888e  /* IEEE 802.1X EAP authentication */
#endif
#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS          0x8847  /* MPLS */
#endif
#ifndef ETHERTYPE_LOOPBACK
#define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */
#endif

	struct xzhnet_ether_addr
	{
		uint8_t  ether_addr_octet[6];        /* Ethernet address */
	};


	/*
	*  IPv4 header
	*  Internet Protocol, version 4
	*  Static header size: 20 bytes
	*/
	struct xzhnet_ipv4_hdr
	{
		uint8_t ip_hl:4,      /* header length */
ip_v:4;         /* version */
		uint8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
		uint16_t ip_len;         /* total length */
		uint16_t ip_id;          /* identification */
		uint16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
		uint8_t ip_ttl;          /* time to live */
		uint8_t ip_p;            /* protocol */
		uint16_t ip_sum;         /* checksum */
		struct in_addr ip_src, ip_dst; /* source and dest address */
	};

	/*
	*  IP options
	*/
#ifndef IPOPT_EOL
#define IPOPT_EOL       0   /* end of option list */
#endif
#ifndef IPOPT_NOP
#define IPOPT_NOP       1   /* no operation */
#endif   
#ifndef IPOPT_RR
#define IPOPT_RR        7   /* record packet route */
#endif
#ifndef IPOPT_TS
#define IPOPT_TS        68  /* timestamp */
#endif
#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY  130 /* provide s,c,h,tcc */   
#endif
#ifndef IPOPT_LSRR
#define IPOPT_LSRR      131 /* loose source route */
#endif
#ifndef IPOPT_SATID
#define IPOPT_SATID     136 /* satnet id */
#endif
#ifndef IPOPT_SSRR
#define IPOPT_SSRR      137 /* strict source route */
#endif

	/*
	*  TCP header
	*  Transmission Control Protocol
	*  Static header size: 20 bytes
	*/
	struct xzhnet_tcp_hdr
	{
		uint16_t th_sport;       /* source port */
		uint16_t th_dport;       /* destination port */
		uint32_t th_seq;          /* sequence number */
		uint32_t th_ack;          /* acknowledgement number */
		uint8_t  th_x2:4,         /* (unused) */
th_off:4;        /* data offset */
		uint8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
		uint16_t th_win;         /* window */
		uint16_t th_sum;         /* checksum */
		uint16_t th_urp;         /* urgent pointer */
	};


	/*
	*  UDP header
	*  User Data Protocol
	*  Static header size: 8 bytes
	*/
	struct xzhnet_udp_hdr
	{
		uint16_t uh_sport;       /* source port */
		uint16_t uh_dport;       /* destination port */
		uint16_t uh_ulen;        /* length */
		uint16_t uh_sum;         /* checksum */
	};
};
#endif
