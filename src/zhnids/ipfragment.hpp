#ifndef IP_FRAGMENT_HPP
#define IP_FRAGMENT_HPP

#include <vector>
#include <string>
#include <map>

#include <zhnids/net_header.hpp>
#include <zhnids/stage/pcap_hub.hpp>

using namespace std;

namespace xzh
{
	class process_ipfragment
	{
	public:
		struct ip_key
		{
			u_short ip_id;
			u_long ip_src;
			u_long ip_dst;
			u_short ip_op;

			u_short ip_len;
		};

		enum end_flag
		{
			s_frag = 0,
			e_frag
		};

#define max_time_out 60

		struct ip_key_compare
		{
			template <typename key>
			bool operator() (const key &key_l, const key &key_r) const
			{
				bool bretvalue = false;
				int iret = memcmp(&key_l, &key_r, sizeof(key) - sizeof(u_short));
				if (iret < 0)
				{
					bretvalue = true;
				}

				return bretvalue;
			}

		};

		typedef vector<unsigned char> ip_fragment_data;
		typedef map<u_short, ip_fragment_data> ip_fragment_group_data;
		struct ip_fragment_s
		{
			u_short flag;
			boost::posix_time::ptime time_;

			ip_fragment_group_data ip_fragment_group_data_;
		};

		typedef map<ip_key, ip_fragment_s, ip_key_compare> ip_key_fragment_group;

	public:
		bool insert(ip_key &ip_key_, u_short uoffset, u_short uflag, ip_fragment_data &data_, bool &isdone)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock l_lock(ip_key_fragment_group_mutex_);

				//todo: check is timeout, if true, clear.......
				clear_timeout();

				ip_key_fragment_group::iterator pos = ip_key_fragment_group_.find(ip_key_);
				if (pos == ip_key_fragment_group_.end())
				{
					ip_fragment_s ip_fragment_s_;
					ip_fragment_s_.flag = s_frag;
					//todo:add time...
					ip_fragment_s_.time_ = boost::posix_time::second_clock::local_time();
					ip_fragment_s_.ip_fragment_group_data_.insert(make_pair(uoffset, data_));
					ip_key_fragment_group_.insert(make_pair(ip_key_, ip_fragment_s_));
					bretvalue = true;
					break;
				}


				if (pos->second.flag == s_frag)
				{
					pos->second.flag = uflag;
				}
				//todo: reset time...
				pos->second.time_ = boost::posix_time::second_clock::local_time();
				pos->second.ip_fragment_group_data_.insert(make_pair(uoffset, data_));

				if (pos->second.flag == e_frag)
				{
					//todo: check is done....
					isdone = done(pos->second.ip_fragment_group_data_, pos->first.ip_len);
					//check done...,set done para..
				}

				bretvalue = true;

			} while (false);

			return bretvalue;
		}

		bool get(ip_key &ip_key_, ip_fragment_data &data_)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock l_lock(ip_key_fragment_group_mutex_);
				ip_key_fragment_group::iterator pos = ip_key_fragment_group_.find(ip_key_);
				if (pos == ip_key_fragment_group_.end())
				{
					break;
				}

				for(ip_fragment_group_data::iterator pos_ = pos->second.ip_fragment_group_data_.begin(); pos_ != pos->second.ip_fragment_group_data_.end(); pos_ ++)
				{
					copy(pos_->second.begin(), pos_->second.end(), inserter(data_, data_.end()));
				}

			} while (false);

			return !data_.empty();
		}

	private:
		bool done(ip_fragment_group_data &group_data, u_short ip_hl)
		{
			bool bretvalue = false;

			do 
			{
				if (group_data.empty())
				{
					break;
				}

				if(group_data.empty())
				{
					break;
				}

				size_t l_total_size = 0;
				for(ip_fragment_group_data::iterator pos = group_data.begin(); pos != group_data.end(); pos ++)
				{
					l_total_size += pos->second.size();
				}

				if (l_total_size > 65535)
				{
					break;
				}

				ip_fragment_group_data::iterator re_pos = group_data.end();
				advance(re_pos, -1);

				size_t l_data_size = re_pos->second.size();
				size_t l_offset_total = re_pos->first + l_data_size + (size_t)ip_hl;

				if (l_total_size != l_offset_total)
				{
					break;
				}

				bretvalue = true;

			} while (false);

			return bretvalue;
		}

		bool clear_timeout()
		{
			bool bretvalue = false;

			typedef vector<ip_key> erase_ip_key;
			erase_ip_key l_erase_ip_key;

			ip_key_fragment_group::iterator pos = ip_key_fragment_group_.begin();
			while(pos != ip_key_fragment_group_.end())
			{
				boost::posix_time::time_duration l_delta = boost::posix_time::second_clock::local_time() - pos->second.time_;
				int idelta_second = l_delta.seconds();
				if (idelta_second > max_time_out)
				{
					l_erase_ip_key.push_back(pos->first);
				}

				pos ++;
			}

			for (erase_ip_key::iterator pos_e = l_erase_ip_key.begin(); pos_e != l_erase_ip_key.end(); pos_e ++)
			{
				ip_key_fragment_group_.erase(*pos_e);
			}

			return true;
		}

	private:
		boost::mutex ip_key_fragment_group_mutex_;
		ip_key_fragment_group ip_key_fragment_group_;
	};

	class ipfragment
	{
		typedef pcap_hub_impl<string, bool (vector<unsigned char>&, int, netdevice_ptr) > ippacket_hub;
	public:
		template <typename TFun>
		bool add_ippacket_handler(string strkey, TFun callfun_)
		{
			return ippacket_hub_.add_handler(strkey, callfun_);
		}

		bool ipfrag_handler(std::vector<unsigned char> &data_, int len, netdevice_ptr netdevice_info_)
		{
			do 
			{
				if (len < sizeof(xzhnet_ipv4_hdr))
				{
					break;
				}
				xzhnet_ipv4_hdr* iphdr_ = (xzhnet_ipv4_hdr*)&data_[0];

				if (iphdr_->ip_hl < 5)
				{
					break;
				}

				if (iphdr_->ip_v != 4)
				{
					break;
				}

				u_short ip_r_len = ntohs(iphdr_->ip_len);

				if(ip_r_len != 0)
				{
					if (len < ip_r_len)
					{
						break;
					}

					if(ip_r_len < iphdr_->ip_hl << 2)
					{
						break;
					}
				}

				//check sum
				if (iphdr_->ip_sum != 0)
				{
					if (checksum(&data_[0], iphdr_->ip_hl << 2) != 0)
					{
						break;
					}
				}
				else
				{
					//skip check sum
				}

				//验证ip 扩展数据
				if (iphdr_->ip_hl > 5)
				{
					//todo: check ext data
				}

				u_short uip_id = ntohs(iphdr_->ip_id);
				u_short uoffset = ntohs(iphdr_->ip_off);
				u_short uflag = uoffset & ~IP_OFFMASK;
				uoffset &= IP_OFFMASK;

				//debughelp::safe_debugstr(200, "ip_id[%d] flag %d and uoffset:%d", uip_id, uflag, uoffset << 3);

				if (((uflag & IP_MF) == 0) && (uoffset == 0))
				{
					//debughelp::safe_debugstr(200, "mf:0 and uoffset:0", uip_id);

					for (size_t index_ = 0; index_ < ippacket_hub_.size(); index_ ++)
					{
						ippacket_hub::return_type_ptr temp_ = ippacket_hub_[index_];
						if (!temp_)
						{
							continue;
						}

						if((*temp_)(data_, len, netdevice_info_))
						{
						}
						else
						{
						}
					}

					break;
				}

				if (((uflag & IP_MF) == 0) && (uoffset != 0))
				{
					process_ipfragment::ip_key ip_key_;
					ip_key_.ip_id = ntohs(iphdr_->ip_id);
					ip_key_.ip_op = ntohs(iphdr_->ip_p);
					ip_key_.ip_dst = (iphdr_->ip_dst.S_un.S_addr);
					ip_key_.ip_src = (iphdr_->ip_src.S_un.S_addr);

					process_ipfragment::ip_fragment_data ip_frag_data_;
					copy(data_.begin() + iphdr_->ip_hl * 4, data_.end(), inserter(ip_frag_data_, ip_frag_data_.end()));

					bool isdone = false;
					process_ipfragment_.insert(ip_key_, ((uoffset << 3)), process_ipfragment::e_frag, ip_frag_data_, isdone);

					if (isdone)
					{
						process_ipfragment::ip_fragment_data l_ippacket_data;
						process_ipfragment_.get(ip_key_, l_ippacket_data);

						if (l_ippacket_data.size())
						{
							for (size_t index_ = 0; index_ < ippacket_hub_.size(); index_ ++)
							{
								ippacket_hub::return_type_ptr temp_ = ippacket_hub_[index_];
								if (!temp_)
								{
									continue;
								}

								if((*temp_)(l_ippacket_data, l_ippacket_data.size(), netdevice_info_))
								{
								}
								else
								{

								}
							}
						}
					}
					break;
				}

				if (((uflag & IP_MF) != 0) && (uoffset == 0))
				{
					process_ipfragment::ip_key ip_key_;
					ip_key_.ip_id = ntohs(iphdr_->ip_id);
					ip_key_.ip_op = ntohs(iphdr_->ip_p);
					ip_key_.ip_dst = (iphdr_->ip_dst.S_un.S_addr);
					ip_key_.ip_src = (iphdr_->ip_src.S_un.S_addr);
					ip_key_.ip_len = iphdr_->ip_hl * 4;

					bool isdone = false;
					process_ipfragment_.insert(ip_key_, 0, process_ipfragment::s_frag, data_, isdone);

					if (isdone)
					{
						process_ipfragment::ip_fragment_data l_ippacket_data;
						process_ipfragment_.get(ip_key_, l_ippacket_data);

						if (l_ippacket_data.size())
						{
							for (size_t index_ = 0; index_ < ippacket_hub_.size(); index_ ++)
							{
								ippacket_hub::return_type_ptr temp_ = ippacket_hub_[index_];
								if (!temp_)
								{
									continue;
								}

								if((*temp_)(l_ippacket_data, l_ippacket_data.size(), netdevice_info_))
								{
								}
								else
								{
								}
							}
						}

					}
					break;
				}

				if (((uflag & IP_MF) != 0) && (uoffset != 0))
				{
					process_ipfragment::ip_key ip_key_;
					ip_key_.ip_id = ntohs(iphdr_->ip_id);
					ip_key_.ip_op = ntohs(iphdr_->ip_p);
					ip_key_.ip_dst = (iphdr_->ip_dst.S_un.S_addr);
					ip_key_.ip_src = (iphdr_->ip_src.S_un.S_addr);

					process_ipfragment::ip_fragment_data ip_frag_data_;
					copy(data_.begin() + iphdr_->ip_hl * 4, data_.end(), inserter(ip_frag_data_, ip_frag_data_.end()));

					bool isdone = false;
					process_ipfragment_.insert(ip_key_, ((uoffset << 3)), process_ipfragment::s_frag, ip_frag_data_, isdone);

					if (isdone)
					{
						process_ipfragment::ip_fragment_data l_ippacket_data;
						process_ipfragment_.get(ip_key_, l_ippacket_data);

						if (l_ippacket_data.size())
						{
							for (size_t index_ = 0; index_ < ippacket_hub_.size(); index_ ++)
							{
								ippacket_hub::return_type_ptr temp_ = ippacket_hub_[index_];
								if (!temp_)
								{
									continue;
								}

								if((*temp_)(l_ippacket_data, l_ippacket_data.size(), netdevice_info_))
								{
								}
								else
								{
								}
							}
						}
					}
					break;
				}

			} while (false);
			return false;
		}

		u_short checksum(void* data_, u_short len )
		{
		register int nleft = len;
		register u_short *w = (u_short*)data_;
		register int sum = 0;
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
		process_ipfragment process_ipfragment_;
		ippacket_hub	   ippacket_hub_;
	};


	class ippacket
	{
		typedef pcap_hub_impl<string, bool (vector<unsigned char>&, int, netdevice_ptr) > tcppacket_hub;
		typedef pcap_hub_impl<string, bool (vector<unsigned char>&, int, netdevice_ptr) > udppacket_hub;
		typedef pcap_hub_impl<string, bool (vector<unsigned char>&, int, netdevice_ptr) > icmppacket_hub;
	public:
		template <typename TFun>
		bool add_tcp_handler(string strkey, TFun callfun_)
		{
			return tcppacket_hub_.add_handler(strkey, callfun_);
		}

		template <typename TFun>
		bool add_udp_handler(string strkey, TFun callfun_)
		{
			return udppacket_hub_.add_handler(strkey, callfun_);
		}

		template <typename TFun>
		bool add_icmp_handler(string strkey, TFun callfun_)
		{
			return icmppacket_hub_.add_handler(strkey, callfun_);
		}

		bool ippacket_handler(std::vector<unsigned char> &data_, int len, netdevice_ptr netdeice_info_)
		{
			bool bretvalue = false;

			do 
			{
				xzhnet_ipv4_hdr* iphdr_ = (xzhnet_ipv4_hdr*)&data_[0];
				if (iphdr_->ip_p == IPPROTO_ICMP)
				{
					for (size_t index_ = 0; index_ < icmppacket_hub_.size(); index_ ++)
					{
						icmppacket_hub::return_type_ptr temp_ = icmppacket_hub_[index_];
						if (!temp_)
						{
							continue;
						}

						if((*temp_)(data_, data_.size(), netdeice_info_))
						{
						}
						else
						{
						}
					}
					break;
				}

				if (iphdr_->ip_p == IPPROTO_TCP)
				{
					for (size_t index_ = 0; index_ < tcppacket_hub_.size(); index_ ++)
					{
						tcppacket_hub::return_type_ptr temp_ = tcppacket_hub_[index_];
						if (!temp_)
						{
							continue;
						}

						if((*temp_)(data_, data_.size(), netdeice_info_))
						{
						}
						else
						{
						}
					}
					break;
				}


				if (iphdr_->ip_p == IPPROTO_UDP)
				{
					for (size_t index_ = 0; index_ < udppacket_hub_.size(); index_ ++)
					{
						udppacket_hub::return_type_ptr temp_ = udppacket_hub_[index_];
						if (!temp_)
						{
							continue;
						}

						if((*temp_)(data_, data_.size(), netdeice_info_))
						{
						}
						else
						{
						}
					}
					break;
				}


			} while (false);

			return bretvalue;
		}
	private:
		process_ipfragment process_ipfragment_;
		tcppacket_hub	   tcppacket_hub_;
		udppacket_hub	   udppacket_hub_;
		icmppacket_hub	   icmppacket_hub_;
	};
};
#endif