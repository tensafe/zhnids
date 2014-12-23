#ifndef TCP_PACKET_HPP
#define TCP_PACKET_HPP

#include <string>
#include <vector>
#include <map>

#include <boost/thread.hpp>
#include <boost/timer.hpp>

#include <zhnids/packet_header.hpp>
#include <zhnids/stage/pcap_hub.hpp>

using namespace std;
namespace xzh
{
	class tcppacket
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

#define tcp_max_time_out 10

		enum tcp_state
		{
			TCP_ESTABLISHED = 1,
			TCP_SYN_SENT,
			TCP_SYN_RECV,
			TCP_FIN_WAIT1,
			TCP_FIN_WAIT2,
			TCP_TIME_WAIT,
			TCP_CLOSE,
			TCP_CLOSE_WAIT,
			TCP_LAST_ACK,
			TCP_LISTEN,
			TCP_CLOSING			/* now a valid state */
		};

#define FIN_SENT 120
#define FIN_CONFIRMED 121

		struct tcp_key
		{
			u_int src_ip;
			u_int dst_ip;
			u_short src_port;
			u_short dst_port;
		};

		struct tcp_half_stream
		{
			int tcp_state_;
			u_int seq;
			u_int ack_seq;
		};

		struct tcp_stream
		{
			tcp_key tcp_key_;
			boost::timer timer_;
			tcp_half_stream client_;
			tcp_half_stream server_;
		};


		struct tcp_key_compare
		{
			template <typename key>
			bool operator() (const key &key_l, const key &key_r) const
			{
				bool bretvalue = false;
				int iret = memcmp(&key_l, &key_r, sizeof(key));
				if (iret < 0)
				{
					bretvalue = true;
				}

				return bretvalue;
			}

		};

		typedef map<tcp_key, tcp_stream, tcp_key_compare> tcp_stream_map;
		typedef pcap_hub_impl<string,bool (tcp_packet_node_ptr) > tcp_data_hub;

	public:
		bool tcp_handler(vector<unsigned char> &data_, int len, netdevice_ptr l_netdevice_ptr)
		{
			bool bretvalue = false;

			do
			{
				clear_timeout(l_netdevice_ptr);
			}
			while(false);

			do 
			{
				xzhnet_ipv4_hdr *iphdr_ = (xzhnet_ipv4_hdr*)&data_[0];
				xzhnet_tcp_hdr	*tcphdr_ = (xzhnet_tcp_hdr*)&data_[iphdr_->ip_hl << 2];

				if ((iphdr_->ip_src.s_addr == 0) || (iphdr_->ip_dst.s_addr == 0))
				{
					debughelp::safe_debugstr(200, "ip addr error!");
					break;
				}

				u_short uipdatalen = ntohs(iphdr_->ip_len);
				u_short uiphdrlen = iphdr_->ip_hl << 2;

			/*	netdevice::netaddr_vector::iterator pos = std::find_if(l_netdevice_ptr->set_netaddr_vector().begin(), l_netdevice_ptr->set_netaddr_vector().end(), boost::bind(&tcppacket::isfind_device_info, this, iphdr_->ip_src.s_addr, _1));

				if (pos != l_netdevice_ptr->set_netaddr_vector().end())
				{
					
				}
				else
				{
					if (tcp_checmsum(tcphdr_, uipdatalen - uiphdrlen, iphdr_->ip_src.s_addr, iphdr_->ip_dst.s_addr) != 0)
					{
						debughelp::safe_debugstr(200, "tcp check sum error!");
						break;
					}
				}*/
			

				//ip
				u_int isrc_ip = ntohl(iphdr_->ip_src.s_addr);
				u_int idst_ip = ntohl(iphdr_->ip_dst.s_addr);

				//port
				u_short isrc_port = ntohs(tcphdr_->th_sport);
				u_short idst_port = ntohs(tcphdr_->th_dport);

				tcp_key l_tcp_key;
				l_tcp_key.src_ip = isrc_ip;
				l_tcp_key.dst_ip = idst_ip;
				l_tcp_key.src_port = isrc_port;
				l_tcp_key.dst_port = idst_port;

				bool bfromclient = false;
				tcp_stream_map::iterator find_tcp_stream_it_;
				bool bfind = find_stream(l_tcp_key, bfromclient, find_tcp_stream_it_);

				if (!bfind)
				{
					if ((tcphdr_->th_flags & TH_SYN) 
						&& !(tcphdr_->th_flags & TH_ACK)
						&& !(tcphdr_->th_flags & TH_RST))
					{
						//debughelp::safe_debugstr(200, "1s syn start...");
						//add new tcp stream....
						tcp_stream l_tcp_stream;
						l_tcp_stream.tcp_key_ = l_tcp_key;
						l_tcp_stream.client_.tcp_state_ = TCP_SYN_SENT;
						l_tcp_stream.client_.seq = ntohl(tcphdr_->th_seq) + 1;

						l_tcp_stream.server_.tcp_state_ = TCP_CLOSE;
						//l_tcp_stream.devname_ = devname_;

						if(insert_stream(l_tcp_key, l_tcp_stream))
						{
							//debughelp::safe_debugstr(200, "new tcp connect insert ok   ..[si:%08x,sp:%d,di:%08x,dp:%d]", l_tcp_key.src_ip, l_tcp_key.src_port, l_tcp_key.dst_ip, l_tcp_key.dst_port);
						}
						else
						{
							debughelp::safe_debugstr(200, "new tcp connect insert error..[si:%08x,sp:%d,di:%08x,dp:%d]", l_tcp_key.src_ip, l_tcp_key.src_port, l_tcp_key.dst_ip, l_tcp_key.dst_port);
						}
					}
					else
					{
						//debughelp::safe_debugstr(200, "error not find...");
					}

					break;
				}


				int datalen = 0;

				if (uipdatalen != 0)
				{
					if (uipdatalen < (uiphdrlen + sizeof(xzhnet_tcp_hdr)))
					{
						debughelp::safe_debugstr(200, "tcp len error!");
						break;
					}

					datalen = uipdatalen - uiphdrlen - (tcphdr_->th_off << 2);
					if (datalen < 0)
					{
						debughelp::safe_debugstr(200, "tcp data len error!");
						break;
					}
				}
				else
				{
					datalen = len - (iphdr_->ip_hl << 2) - (tcphdr_->th_off << 2);
				}

				tcp_half_stream *snd, *rcv;

				tcp_stream *tcp_stream_find_ = &find_tcp_stream_it_->second;

				if (bfromclient)
				{
					snd = &(find_tcp_stream_it_->second.client_);
					rcv = &(find_tcp_stream_it_->second.server_);
				}
				else
				{
					snd = &(find_tcp_stream_it_->second.server_);
					rcv = &(find_tcp_stream_it_->second.client_);
				}

				if ((tcphdr_->th_flags & TH_SYN))
				{
					//debughelp::safe_debugstr(200, "2s syn&ack start...");
					do 
					{
						if (bfromclient)
						{
							//debughelp::safe_debugstr(200, "cant not from client");
							break;
						}

						if (tcp_stream_find_->client_.tcp_state_ != TCP_SYN_SENT)
						{
							debughelp::safe_debugstr(200, "client tcp state error");
							break;
						}

						if (tcp_stream_find_->server_.tcp_state_ != TCP_CLOSE)
						{
							debughelp::safe_debugstr(200, "server tcp state error");
							break;
						}

						if (!(tcphdr_->th_flags & TH_ACK))
						{
							debughelp::safe_debugstr(200, "tcp flags state error");
							break;
						}

						if(tcp_stream_find_->client_.seq != ntohl(tcphdr_->th_ack))
						{
							debughelp::safe_debugstr(200, "stream seq and tcp ack not same");
							break;
						}

						tcp_stream_find_->server_.tcp_state_ = TCP_SYN_RECV;
						tcp_stream_find_->server_.seq = ntohl(tcphdr_->th_seq) + 1;

						//debughelp::safe_debugstr(200, "change tcp stream server state....");

					} while (false);

					break;
				}

				if ((tcphdr_->th_flags & TH_ACK))
				{
					if (bfromclient
						&& tcp_stream_find_->client_.tcp_state_ == TCP_SYN_SENT
						&& tcp_stream_find_->server_.tcp_state_ == TCP_SYN_RECV
						)
					{
						if(tcp_stream_find_->server_.seq == ntohl(tcphdr_->th_ack))
						{
							//debughelp::safe_debugstr(200, "3s ack ok...");

							tcp_stream_find_->client_.tcp_state_ = TCP_ESTABLISHED;
							tcp_stream_find_->client_.ack_seq = ntohl(tcphdr_->th_ack);

							tcp_stream_find_->server_.tcp_state_ = TCP_ESTABLISHED;
							tcp_stream_find_->server_.ack_seq = ntohl(tcphdr_->th_seq) + 1;

							tcp_packet_node_ptr l_tcp_queue_node_ptr = tcp_packet_node_ptr(new tcp_packet_node(tcp_stream_find_->tcp_key_.src_ip,
								tcp_stream_find_->tcp_key_.dst_ip,
								tcp_stream_find_->tcp_key_.src_port,
								tcp_stream_find_->tcp_key_.dst_port,
								bfromclient,
								snd->seq,
								snd->ack_seq,
								tcp_connect,
								0));
							
							if(l_tcp_queue_node_ptr->set_netdevice_ptr(l_netdevice_ptr))
							{

							}

							notify_handler(l_tcp_queue_node_ptr);
						}
						else
						{
							debughelp::safe_debugstr(200, "3s ack error...");
						}

						break;
					}
				}


				if ((tcphdr_->th_flags & TH_RST))
				{
					debughelp::safe_debugstr(200, "rcv rst data...,delete tcp stream..");

					tcp_packet_node_ptr l_tcp_queue_node_ptr = tcp_packet_node_ptr(new tcp_packet_node(tcp_stream_find_->tcp_key_.src_ip,
						tcp_stream_find_->tcp_key_.dst_ip,
						tcp_stream_find_->tcp_key_.src_port,
						tcp_stream_find_->tcp_key_.dst_port,
						bfromclient,
						snd->seq,
						snd->ack_seq,
						tcp_end,
						0));

					if(l_tcp_queue_node_ptr->set_netdevice_ptr(l_netdevice_ptr))
					{

					}
					notify_handler(l_tcp_queue_node_ptr);

					delete_stream(l_tcp_key);
					break;
				}

				if (tcphdr_->th_flags & TH_FIN)
				{
					//debughelp::safe_debugstr(200, "rcv fin packet...");
					snd->tcp_state_ = FIN_SENT;
					find_tcp_stream_it_->second.timer_.restart();

					tcp_packet_node_ptr l_tcp_queue_node_ptr = tcp_packet_node_ptr(new tcp_packet_node(tcp_stream_find_->tcp_key_.src_ip,
						tcp_stream_find_->tcp_key_.dst_ip,
						tcp_stream_find_->tcp_key_.src_port,
						tcp_stream_find_->tcp_key_.dst_port,
						bfromclient,
						snd->seq,
						snd->ack_seq,
						tcp_ending,
						0));

					if(l_tcp_queue_node_ptr->set_netdevice_ptr(l_netdevice_ptr))
					{

					}
					notify_handler(l_tcp_queue_node_ptr);

					//break;
				}

				bool biskeep_alive = false;

				if ((tcphdr_->th_flags & TH_ACK))
				{
					if ((datalen == 1) && (*(data_.rbegin()) == 0x00) && ((ntohl(tcphdr_->th_seq) + 1) == snd->seq))
					{
						debughelp::safe_debugstr(200, "keep alive packet...ignore");
						biskeep_alive = true;
					}
					else
					{
						//snd->ack_seq = max(snd->ack_seq, ntohl(tcphdr_->th_ack));
						//snd->seq = max(snd->seq, ntohl(tcphdr_->th_seq));

						snd->ack_seq = ntohl(tcphdr_->th_ack);
						snd->seq = ntohl(tcphdr_->th_seq);
					}

					if (biskeep_alive)
					{
						break;
					}

					if (rcv->tcp_state_ == FIN_SENT)
					{
						//debughelp::safe_debugstr(200, "fin ... close pre");
						rcv->tcp_state_ = FIN_CONFIRMED;
					}

					if (rcv->tcp_state_ == FIN_CONFIRMED && snd->tcp_state_ == FIN_CONFIRMED)
					{
						tcp_packet_node_ptr l_tcp_queue_node_ptr = tcp_packet_node_ptr(new tcp_packet_node(tcp_stream_find_->tcp_key_.src_ip,
							tcp_stream_find_->tcp_key_.dst_ip,
							tcp_stream_find_->tcp_key_.src_port,
							tcp_stream_find_->tcp_key_.dst_port,
							bfromclient,
							snd->seq,
							snd->ack_seq,
							tcp_end,
							0));

						if(l_tcp_queue_node_ptr->set_netdevice_ptr(l_netdevice_ptr))
						{

						}
						notify_handler(l_tcp_queue_node_ptr);

						delete_stream(l_tcp_key);

						break;
					}
				}


				if (biskeep_alive)
				{
					break;
				}

				if (datalen > 0)
				{
					tcp_packet_node_ptr l_tcp_queue_node_ptr = tcp_packet_node_ptr(new tcp_packet_node(tcp_stream_find_->tcp_key_.src_ip,
						tcp_stream_find_->tcp_key_.dst_ip,
						tcp_stream_find_->tcp_key_.src_port,
						tcp_stream_find_->tcp_key_.dst_port,
						bfromclient,
						snd->seq,
						snd->ack_seq,
						tcp_data,
						datalen));

					if(l_tcp_queue_node_ptr->set_netdevice_ptr(l_netdevice_ptr))
					{

					}

					std::copy((unsigned char*)tcphdr_ + (tcphdr_->th_off << 2), (unsigned char*)tcphdr_ +  datalen + (tcphdr_->th_off << 2), inserter(l_tcp_queue_node_ptr->set_tcp_packet_data(), l_tcp_queue_node_ptr->set_tcp_packet_data().begin()));

					notify_handler(l_tcp_queue_node_ptr);
				}

				bretvalue = true;

			} while (false);
			return false;
		}
		template <typename TFun>
		bool add_tcp_data_handler(string strkey, TFun callfun_)
		{
			return tcp_data_hub_.add_handler(strkey, callfun_);
		}

		bool isfind_device_info(unsigned long src_ip, netdevice::netaddr_vector::value_type &netaddr_pos)
		{
			return (netaddr_pos.netaddr & netaddr_pos.netmask) == (src_ip & netaddr_pos.netmask);
		}

	private:
		bool notify_handler(tcp_packet_node_ptr tcp_queue_node_ptr_)
		{
			bool bretvalue = false;

			for (size_t index_ = 0; index_ < tcp_data_hub_.size(); index_ ++)
			{
				tcp_data_hub::return_type_ptr temp_ = tcp_data_hub_[index_];
				if (!temp_)
				{
					continue;
				}

				if((*temp_)(tcp_queue_node_ptr_))
				{
				}
				else
				{
				}
			}

			return bretvalue;
		}
	private:
		u_short tcp_checmsum(void *u, int len, u_int saddr, u_int daddr)
		{
			unsigned int i;
			int sum = 0;
			psuedo_hdr hdr;

			hdr.saddr = saddr;
			hdr.daddr = daddr;
			hdr.zero = 0;
			hdr.protocol = IPPROTO_TCP;
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
		bool find_stream(tcp_key & tcp_key_, bool &bisclient, tcp_stream_map::iterator &tcp_stream_it_)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock l_lock(tcp_stream_map_mutex_);
				tcp_stream_it_ = tcp_stream_map_.find(tcp_key_);

				if (tcp_stream_it_ != tcp_stream_map_.end())
				{
					bisclient = true;
					break;
				}

				tcp_key l_reverse_tcp_key;
				l_reverse_tcp_key.dst_ip = tcp_key_.src_ip;
				l_reverse_tcp_key.dst_port = tcp_key_.src_port;
				l_reverse_tcp_key.src_ip = tcp_key_.dst_ip;
				l_reverse_tcp_key.src_port = tcp_key_.dst_port;

				tcp_stream_it_ = tcp_stream_map_.find(l_reverse_tcp_key);

			} while (false);

			return tcp_stream_it_ != tcp_stream_map_.end();
		}
		bool insert_stream(tcp_key& tcp_key_, tcp_stream & tcp_stream_)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock l_lock(tcp_stream_map_mutex_);

				std::pair<tcp_stream_map::iterator, bool> ret = tcp_stream_map_.insert(make_pair(tcp_key_, tcp_stream_));

				bretvalue = ret.second;
			} while (false);

			return bretvalue;
		}
		bool delete_stream(tcp_key& tcp_key_)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock l_lock(tcp_stream_map_mutex_);

				tcp_stream_map_.erase(tcp_key_);

				bretvalue = true;
			} while (false);

			return bretvalue;
		}
		bool clear_timeout(netdevice_ptr l_netdevice_ptr)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock l_lock(tcp_stream_map_mutex_);

				for (tcp_stream_map::iterator pos = tcp_stream_map_.begin(); pos != tcp_stream_map_.end(); )
				{
					if(((pos->second.client_.tcp_state_ == FIN_SENT) || (pos->second.server_.tcp_state_ == FIN_SENT) || (pos->second.client_.tcp_state_ == FIN_CONFIRMED) || (pos->second.server_.tcp_state_ == FIN_CONFIRMED)) && (pos->second.timer_.elapsed() > (double)tcp_max_time_out))
					{
						tcp_packet_node_ptr l_tcp_queue_node_ptr = tcp_packet_node_ptr(new tcp_packet_node(pos->second.tcp_key_.src_ip,
							pos->second.tcp_key_.dst_ip,
							pos->second.tcp_key_.src_port,
							pos->second.tcp_key_.dst_port,
							true,
							pos->second.client_.seq,
							pos->second.client_.ack_seq,
							tcp_end,
							0));

						if(l_tcp_queue_node_ptr->set_netdevice_ptr(l_netdevice_ptr))
						{

						}

						notify_handler(l_tcp_queue_node_ptr);

						tcp_stream_map_.erase(pos++);
					}
					else
					{
						pos ++;
					}
				}

				bretvalue = true;
			} while (false);

			return bretvalue;
		}


	private:
		boost::mutex	tcp_stream_map_mutex_;
		tcp_stream_map tcp_stream_map_;
		tcp_data_hub	tcp_data_hub_;
	};
}

#endif