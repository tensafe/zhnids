#ifndef UDP_PACKET_HPP
#define UDP_PACKET_HPP

#include <vector>
#include <string>

#include <zhnids/packet_header.hpp> 
#include <zhnids/stage/outdebug.hpp> 
#include <zhnids/stage/pcap_hub.hpp>

using namespace std;

namespace xzh
{
	typedef pcap_hub_impl<string, bool (udp_packet_node_ptr)> udp_repacket_hub;

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
		template <typename TFun>
		bool add_repacket_handler(string key_, TFun callfun_)
		{
			return udp_repacket_hub_.add_handler(key_, callfun_);
		}

	public:
		bool udp_handler(vector<unsigned char> &data_, int len, netdevice_ptr l_netdevice_ptr)
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

				if (udp_repacket_hub_.size() <= 0)
				{
					break;
				}
				
				udp_packet_node_ptr l_udp_packet_ptr_ = udp_packet_node_ptr(new udp_packet_node(
					ntohl(iphdr_->ip_src.S_un.S_addr),
					ntohl(iphdr_->ip_dst.S_un.S_addr),
					ntohs(udphdr_->uh_sport),
					ntohs(udphdr_->uh_dport),
					uudp_len));

				if (!l_udp_packet_ptr_)
				{
					break;
				}

				if(l_udp_packet_ptr_->set_netdevice_ptr(l_netdevice_ptr))
				{

				}
				std::copy((unsigned char*)udphdr_ + sizeof(xzhnet_udp_hdr), (unsigned char*)udphdr_ + uudp_len, inserter(l_udp_packet_ptr_->set_tcp_packet_data(), l_udp_packet_ptr_->set_tcp_packet_data().end()));

				notify_udppacket(l_udp_packet_ptr_);

				bretvalue = true;

			} while (false);

			return bretvalue;
		}
	private:
		bool notify_udppacket(udp_packet_node_ptr udp_packet_ptr_)
		{
			bool bretvalue = false;

			for (size_t index_ = 0; index_ < udp_repacket_hub_.size(); index_ ++)
			{
				udp_repacket_hub::return_type_ptr temp_ = udp_repacket_hub_[index_];
				if (!temp_)
				{
					continue;
				}

				if((*temp_)(udp_packet_ptr_))
				{
				}
				else
				{
				}
			}

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
		private:
			udp_repacket_hub udp_repacket_hub_;
	};
};

#endif