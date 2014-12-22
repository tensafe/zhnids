#ifndef PCAP_UTILS_HPP
#define PCAP_UTILS_HPP
#include <string>
#include <vector>
#define HAVE_REMOTE
#include <pcap.h>

#include <boost/thread.hpp>
#include <zhnids/packet_header.hpp>
#include <zhnids/stage/pcap_hub.hpp>
#include <zhnids/stage/outdebug.hpp>

using namespace std;

namespace xzh
{
	class xzhnids
	{
		typedef vector<pair<string, netdevice_ptr> > device_list;
		typedef vector<pcap_t* > device_pcap_list;
		typedef pcap_hub_impl<string, bool (vector<unsigned char>&, int, netdevice_ptr) > ipfragment_hub;

		typedef struct _user_data
		{
			unsigned long	innser_ptr;
			netdevice_ptr	net_device_ptr;
		}user_data, *puser_data;

	public:
		bool start(const string strfilter, int buffer_size = 10, int time_out = 0)
		{
			pcap_if_t *all_devs = NULL;
			do 
			{
				string strerror;
				strerror.resize(PCAP_ERRBUF_SIZE);
				int iret = pcap_findalldevs(&all_devs,
					(char*)strerror.c_str());

				if (iret != 0)
				{
					debughelp::safe_debugstr(200 + PCAP_ERRBUF_SIZE, "pcap find all devs error[%d],errormsg:", iret, strerror.c_str());
					break;
				}

				device_list device_list_;
				for (pcap_if_t * index_ = all_devs; index_ != NULL; index_ = index_->next)
				{
					netdevice_ptr l_netdevice_ptr = netdevice_ptr(new netdevice());
					if (l_netdevice_ptr)
					{
						getnetdevice_info(index_, l_netdevice_ptr);

						device_list_.push_back(make_pair(string(index_->name), l_netdevice_ptr));
						debughelp::safe_debugstr(1024, "name:%s,des:%s", index_->name, index_->description);
					}
				}

				if (device_list_.empty())
				{
					debughelp::safe_debugstr(200, "device list empty");
					break;
				}

				strerror.resize(PCAP_ERRBUF_SIZE);
				for (device_list::iterator pos = device_list_.begin(); pos != device_list_.end(); pos ++)
				{
					string strdevname(pos->first);
					thread_group_.create_thread(boost::bind(&xzhnids::pcapt_thread, this, strdevname, strfilter, pos->second, buffer_size, time_out));
				}

			} while (false);

			if (all_devs != NULL)
			{
				pcap_freealldevs(all_devs);
			}

			return true;
		}
		bool stop()
		{
			{
				boost::mutex::scoped_lock l_mutex(mutex_);

				for(device_pcap_list::iterator pos = device_pcap_list_.begin(); pos != device_pcap_list_.end(); pos ++)
				{
					if (*pos != NULL)
					{
						pcap_breakloop(*pos);
						pcap_close(*pos);
					}
				}

				device_pcap_list_.clear();
			}
			thread_group_.interrupt_all();
			return true;
		}
		template <typename TFun>
		bool add_ipfrag_handler(string strkey, TFun callfun_)
		{
			return ipfragment_hub_.add_handler(strkey, callfun_);
		}
	public:
		void pcapt_thread(string strpcap_name, string &strfilter, netdevice_ptr l_net_device_ptr, int buffer_size, int time_out)
		{
			bool bisloop = true;

			while(bisloop)
			{
				int iret = 0;
				do 
				{
					string strerror;
					strerror.resize(PCAP_ERRBUF_SIZE);
					pcap_t* l_pcap_t = pcap_open(strpcap_name.c_str(),
						65536,
						PCAP_OPENFLAG_PROMISCUOUS,
						time_out,
						NULL,
						(char*)strerror.c_str());

					if (l_pcap_t == NULL)
					{
						debughelp::safe_debugstr(200 + PCAP_ERRBUF_SIZE, "pcap open [%s] error:%s", strpcap_name.c_str(), strerror.c_str());
						break;
					}

					int ilinktype = pcap_datalink(l_pcap_t);
					if (ilinktype != DLT_EN10MB)
					{
						debughelp::safe_debugstr(200, "skip not ent dev:%d", ilinktype);
						break;
					}

					iret = pcap_setbuff(l_pcap_t, (max(buffer_size, 1) * 1024 * 1024));
					if (iret == -1)
					{
						debughelp::safe_debugstr(200, "set buffer error!");
					}

					bpf_program fcode;

					unsigned long netmask = 0xffffff;
					if (!l_net_device_ptr->get_netaddr_vector().empty())
					{
						netmask = l_net_device_ptr->get_netaddr_vector()[0].netmask;
					}

					int iret = pcap_compile(l_pcap_t, &fcode, strfilter.c_str(), 1, netmask);
					if (iret < 0)
					{
						debughelp::safe_debugstr(200, "pcap compile error:[%d][%s]", iret, strfilter.c_str());
						break;
					}

					iret = pcap_setfilter(l_pcap_t, &fcode);
					if (iret < 0)
					{
						debughelp::safe_debugstr(200, "pcap set filter error [%d]", iret);
						break;
					}

					{
						boost::mutex::scoped_lock l_mutex(mutex_);
						device_pcap_list_.push_back(l_pcap_t);
					}

					puser_data l_user_data = new user_data();

					l_user_data->net_device_ptr = l_net_device_ptr;
					l_user_data->innser_ptr = (unsigned long)this;
					iret = pcap_loop(l_pcap_t, 0, xzhnids::pcap_handler, (u_char*)l_user_data);

					delete l_user_data;
					if (l_pcap_t != NULL)
					{
						pcap_close(l_pcap_t);
						boost::mutex::scoped_lock l_mutex(mutex_);
						device_pcap_list::iterator pos_find = std::find(device_pcap_list_.begin(), device_pcap_list_.end(), l_pcap_t);
						if (pos_find != device_pcap_list_.end())
						{
							device_pcap_list_.erase(pos_find);
						}
					}
				} while (false);

				if (iret != -2)
				{
					debughelp::safe_debugstr(200, "not normal break, rebegin..");
					boost::this_thread::interruptible_wait(5000);
				}
				else
				{
					break;
				}
			}
		}
		void inner_handler_(const struct pcap_pkthdr *pkt_header, const u_char *pkt_data, netdevice_ptr l_netdevice_ptr)
		{
			try
			{
				do 
				{
					if (pkt_header == NULL)
					{
						debughelp::safe_debugstr(200, "pkt_header nil");
						break;
					}

					if (pkt_data == NULL)
					{
						debughelp::safe_debugstr(200, "pkt_data nil");
						break;
					}

					if (pkt_header->caplen < 14)
					{
						debughelp::safe_debugstr(200, "pkt_data len less 14");
						break;
					}

					if(pkt_data[12] != 8 && pkt_data[13] != 0)
					{
						debughelp::safe_debugstr(200, "12 not 8 13 not 0");
						break;
					}

					int idatalen = pkt_header->caplen - 14;
					vector<unsigned char> data_vector;
					copy(pkt_data + 14, pkt_data + pkt_header->caplen, inserter(data_vector, data_vector.begin()));

					if (data_vector.empty())
					{
						debughelp::safe_debugstr(200, "copy data error, len: %d", idatalen);
						break;
					}

					for (size_t index_ = 0; index_ < ipfragment_hub_.size(); index_ ++)
					{
						ipfragment_hub::return_type_ptr temp_ = ipfragment_hub_[index_];
						if (!temp_)
						{
							continue;
						}

						if((*temp_)(data_vector, idatalen, l_netdevice_ptr))
						{
						}
						else
						{
						}
					}

				} while (false);
			}
			catch(...)
			{

			}
		}
		static void pcap_handler (u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
		{
			try
			{
				do 
				{
					if (user == NULL)
					{
						debughelp::safe_debugstr(200, "user nil");
						break;
					}

					puser_data l_user_data = (puser_data)user;

					xzhnids* xzhnids_ = (xzhnids*)l_user_data->innser_ptr;
					//string strdevname(l_user_data->devname);
					xzhnids_->inner_handler_( pkt_header, pkt_data, l_user_data->net_device_ptr);
				} while (false);
			}
			catch(...)
			{

			}
		}
	private:
		bool getnetdevice_info(pcap_if_t *device, netdevice_ptr l_netdevice_ptr)
		{
			bool bislookback = device->flags & PCAP_IF_LOOPBACK;
			l_netdevice_ptr->set_lookback() = bislookback;
			l_netdevice_ptr->set_device_name() = string(device->name);

			for(pcap_addr_t *a = device->addresses; a ; a = a->next)
			{
				netaddr_info netaddr_info_;
				switch(a->addr->sa_family)
				{
				case AF_INET:
					{
						if (a->addr)
						{
							netaddr_info_.netaddr = ((struct sockaddr_in *)(a->addr))->sin_addr.s_addr;
						}

						if (a->netmask)
						{
							netaddr_info_.netmask = ((struct sockaddr_in *)(a->netmask))->sin_addr.s_addr;
						}

						if (a->broadaddr)
						{
							netaddr_info_.netmask = ((struct sockaddr_in *)(a->broadaddr))->sin_addr.s_addr;
						}

						if (a->dstaddr)
						{
							netaddr_info_.netmask = ((struct sockaddr_in *)(a->dstaddr))->sin_addr.s_addr;
						}

						netaddr_info_.sa_family = AF_INET;

						l_netdevice_ptr->set_netaddr_vector().push_back(netaddr_info_);
					}
					break;

				case AF_INET6:
					{
						if (a->addr)
						{

						}
					}
					break;
				default:
					break;
				}
			}
			return true;
		}
	private:
		boost::mutex mutex_;
		device_pcap_list device_pcap_list_;
		boost::thread_group thread_group_;
		ipfragment_hub ipfragment_hub_;
	};
};
#endif