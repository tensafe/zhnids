#ifndef UDP_PACKET_HPP
#define UDP_PACKET_HPP

#include <vector>
#include <string>

#include <zhnids/packet_header.hpp> 
#include <zhnids/stage/outdebug.hpp> 

using namespace std;

namespace xzh
{
	class udppacket
	{
	public:
		struct psuedo_hdr
		{
			u_int saddr;      
			u_int daddr;      
			u_char zero;        
			u_char protocol;    
			u_short len;        
		};
	public:
		bool udp_handler(vector<unsigned char> &data_, int len, string &devname_)
		{
			bool bretvalue = false;

			do 
			{
				xzhnet_ipv4_hdr* iphdr_ = (xzhnet_ipv4_hdr*)&data_[0];
				xzhnet_udp_hdr*  udphdr_ = (xzhnet_udp_hdr*)&data_[iphdr_->ip_hl << 2];
				u_short uipdatalen = ntohs(iphdr_->ip_len);
				u_short uudp_len = ntohs(udphdr_->uh_ulen);

				if (uipdatalen - uudp_len < sizeof(xzhnet_udp_hdr))
				{
					debughelp::safe_debugstr(200, "udp len error!");
					break;
				}

				if (udphdr_->uh_sum != 0)
				{
					if(udp_checmsum(udphdr_, uudp_len, iphdr_->ip_src.S_un.S_addr, iphdr_->ip_dst.S_un.S_addr) != 0)
					{
						debughelp::safe_debugstr(200, "udp check sum error");
						break;
					}
				}

				//ip id
				u_short ip_id = ntohs(iphdr_->ip_id);
				//ip
				u_int isrc_ip = ntohl(iphdr_->ip_src.S_un.S_addr);
				u_int idst_ip = ntohl(iphdr_->ip_dst.S_un.S_addr);
				//port
				u_short isrc_port = ntohs(udphdr_->uh_sport);
				u_short idst_port = ntohs(udphdr_->uh_dport);

				vector<unsigned char> udp_data;
				std::copy((unsigned char*)udphdr_ + sizeof(xzhnet_udp_hdr), (unsigned char*)udphdr_ + uudp_len, inserter(udp_data, udp_data.begin()));

				debughelp::safe_debugstr(200, "ipid:[%d] srcip:0x%08x sport:%d dstip:0x%08x dport:%d, datasize:%d", ip_id, isrc_ip, isrc_port, idst_ip, idst_port, udp_data.size());

				bretvalue = true;

			} while (false);

			return bretvalue;
		}
	private:
		u_short udp_checmsum(void *u, int len, u_int saddr, u_int daddr)
		{
			unsigned int i;
			int sum = 0;
			psuedo_hdr hdr;

			hdr.saddr = saddr;
			hdr.daddr = daddr;
			hdr.zero = 0;
			hdr.protocol = IPPROTO_UDP;
			hdr.len = htons(len);
			for (i = 0; i < sizeof(hdr); i += 2)
			{
				sum += *(u_short *)((char *)(&hdr) + i);
			}

			return (checksum((u_short *)u, len, sum));
		}
		u_short checksum(void* data_, u_short len, int iaddon)
		{
			register int nleft = len;
			register u_short *w = (u_short*)data_;
			register int sum = iaddon;
			u_short answer = 0;

			/*
			*  Our algorithm is simple, using a 32 bit accumulator (sum),
			*  we add sequential 16 bit words to it, and at the end, fold
			*  back all the carry bits from the top 16 bits into the lower
			*  16 bits.
			*/
			while (nleft > 1) 
			{
				sum += *w++;
				nleft -= 2;
			}
			/* mop up an odd byte, if necessary */
			if (nleft == 1)
			{
				*(u_char *)(&answer) = *(u_char *)w;
				sum += answer;
			}  
			/* add back carry outs from top 16 bits to low 16 bits */
			sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
			sum += (sum >> 16);                     /* add carry */
			answer = ~sum;                          /* truncate to 16 bits */
			return (answer);
		}
	};
};

#endif