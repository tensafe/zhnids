#ifndef PCAP_UTILS_HPP
#define PCAP_UTILS_HPP
#include <string>
#include <vector>
#include <list>
#define HAVE_REMOTE
#include <pcap.h>

#include <boost/timer.hpp>
#include <boost/thread.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/bind.hpp>
#include <boost/thread/condition.hpp>
#include <boost/thread/thread.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>


#include <zhnids/packet_header.hpp>
#include <zhnids/stage/pcap_hub.hpp>
#include <zhnids/stage/outdebug.hpp>
#include <boost/thread/detail/thread.hpp>

using namespace std;

namespace xzh
{
	template <class T>
	class bounded_buffer {
	public:

		typedef boost::circular_buffer<T> container_type;
		typedef typename container_type::size_type size_type;
		typedef typename container_type::value_type value_type;
		typedef typename boost::call_traits<value_type>::param_type param_type;

		explicit bounded_buffer(size_type capacity) : m_unread(0), m_container(capacity) {}

		void push_front(param_type item) {
			boost::mutex::scoped_lock lock(m_mutex);
			m_not_full.wait(lock, boost::bind(&bounded_buffer<value_type>::is_not_full, this));
			m_container.push_front(item);
			++m_unread;
			lock.unlock();
			m_not_empty.notify_one();
		}

		void pop_back(value_type* pItem) {
			boost::mutex::scoped_lock lock(m_mutex);
			m_not_empty.wait(lock, boost::bind(&bounded_buffer<value_type>::is_not_empty, this));
			*pItem = m_container[--m_unread];
			lock.unlock();
			m_not_full.notify_one();
		}

	private:
		bounded_buffer(const bounded_buffer&);              // Disabled copy constructor
		bounded_buffer& operator = (const bounded_buffer&); // Disabled assign operator

		bool is_not_empty() const { return m_unread > 0; }
		bool is_not_full() const { return m_unread < m_container.capacity(); }

		size_type m_unread;
		container_type m_container;
		boost::mutex m_mutex;
		boost::condition m_not_empty;
		boost::condition m_not_full;
	};

	template <class T>
	class bounded_buffer_space_optimized {
	public:

		typedef boost::circular_buffer_space_optimized<T> container_type;
		typedef typename container_type::size_type size_type;
		typedef typename container_type::value_type value_type;
		typedef typename boost::call_traits<value_type>::param_type param_type;

		explicit bounded_buffer_space_optimized(size_type capacity) : m_container(capacity) {}

		void push_front(param_type item) {
			boost::mutex::scoped_lock lock(m_mutex);
			m_not_full.wait(lock, boost::bind(&bounded_buffer_space_optimized<value_type>::is_not_full, this));
			m_container.push_front(item);
			lock.unlock();
			m_not_empty.notify_one();
		}

		void pop_back(value_type* pItem) {
			boost::mutex::scoped_lock lock(m_mutex);
			m_not_empty.wait(lock, boost::bind(&bounded_buffer_space_optimized<value_type>::is_not_empty, this));
			*pItem = m_container.back();
			m_container.pop_back();
			lock.unlock();
			m_not_full.notify_one();
		}

	private:

		bounded_buffer_space_optimized(const bounded_buffer_space_optimized&);              // Disabled copy constructor
		bounded_buffer_space_optimized& operator = (const bounded_buffer_space_optimized&); // Disabled assign operator

		bool is_not_empty() const { return m_container.size() > 0; }
		bool is_not_full() const { return m_container.size() < m_container.capacity(); }

		container_type m_container;
		boost::mutex m_mutex;
		boost::condition m_not_empty;
		boost::condition m_not_full;
	};

	class xzhnids
	{
		typedef vector<pair<string, netdevice_ptr> > device_list;
		typedef vector<pcap_t* > device_pcap_list;
		typedef pcap_hub_impl<string, bool (ip_packet_node_ptr, int, netdevice_ptr) > ipfragment_hub;
		typedef bounded_buffer_space_optimized<ip_packet_node_ptr> bounded_ip_packet_buffer;
		typedef boost::shared_ptr<boost::thread> boost_thread_ptr;

		typedef struct _user_data
		{
			_user_data()
			{
				innser_ptr = 0;
				pcap_dump_ptr = NULL;
				isdump = false;
			}
			unsigned long	innser_ptr;
			netdevice_ptr	net_device_ptr;
			pcap_dumper_t*  pcap_dump_ptr;
			bool			isdump;
		}user_data, *puser_data;

	public:
		explicit xzhnids(size_t capacity)
			//:bounded_ip_packet_buffer_(capacity)
		{

		}

		bool start(const string strfilter, int buffer_size = 10, int time_out = 0, int consumer_size = 1, bool isdump = false)
		{
			try
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
						debughelp::safe_debugstr(1024, "name:%s,des:%s", index_->name, index_->description);
						netdevice_ptr l_netdevice_ptr = netdevice_ptr(new netdevice());
						if (l_netdevice_ptr)
						{
							getnetdevice_info(index_, l_netdevice_ptr);
							device_list_.push_back(make_pair(string(index_->name), l_netdevice_ptr));
						}
						else
						{
							debughelp::safe_debugstr(200, "new netdevice error!");
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
						thread_group_.create_thread(boost::bind(&xzhnids::pcapt_thread, this, strdevname, strfilter, pos->second, buffer_size, time_out, isdump));
					}

					/*for (int i = 0; i < consumer_size; i ++)
					{
						thread_group_consumer_.create_thread(boost::bind(&xzhnids::inner_consumer_handler, this));
					}*/
					_sleep(2000);

				} while (false);

				if (all_devs != NULL)
				{
					pcap_freealldevs(all_devs);
				}

			}
			catch(...)
			{
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
						//pcap_close(*pos);
					}
				}

				device_pcap_list_.clear();
			}
			thread_group_.interrupt_all();
			thread_group_.join_all();

			return true;
		}

		bool start_offline(string strfile_path)
		{
			bool bretvalue = false;
			pcap_t *fp = NULL;

			do 
			{
				if (strfile_path.empty())
				{
					break;
				}

				string strerror;
				strerror.resize(PCAP_ERRBUF_SIZE);

				fp = pcap_open_offline(strfile_path.c_str(), (char*)strerror.c_str());

				if (fp == NULL)
				{
					debughelp::safe_debugstr(200, "open file error!");
					break;
				}

				puser_data l_user_data = new user_data();

				l_user_data->net_device_ptr.reset();
				l_user_data->innser_ptr = (unsigned long)this;

				int iret = pcap_loop(fp, 0, xzhnids::pcap_handler, (u_char*)l_user_data);
				if (iret < 0)
				{
					debughelp::safe_debugstr(200, "pcap_loop error!");
					break;
				}

				bretvalue = true;
			} while (false);

			if (fp != NULL)
			{
				pcap_close(fp);
			}

			return bretvalue;
		}
	public:
		template <typename TFun>
		bool add_ipfrag_handler(string strkey, TFun callfun_)
		{
			return ipfragment_hub_.add_handler(strkey, callfun_);
		}
	public:
		void pcapt_thread(string strpcap_name, string &strfilter, netdevice_ptr l_net_device_ptr, int buffer_size, int time_out, bool isdump)
		{
			bool bisloop = true;

			while(bisloop)
			{
				int iret = 0;
				do 
				{
					string strerror;
					strerror.resize(PCAP_ERRBUF_SIZE);
					pcap_t* l_pcap_t = pcap_open_live(strpcap_name.c_str(),
						65536,
						PCAP_OPENFLAG_PROMISCUOUS,
						time_out,
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

					iret = pcap_compile(l_pcap_t, &fcode, strfilter.c_str(), 1, netmask);
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


					pcap_dumper_t *dump_file = NULL;
					if (isdump)
					{
						boost::uuids::uuid a_uuid = boost::uuids::random_generator()();
						string strfullpath = boost::uuids::to_string(a_uuid) + ".pcap";
						dump_file = pcap_dump_open(l_pcap_t, strfullpath.c_str());

						if(dump_file == NULL)
						{
							debughelp::safe_debugstr(200, "pcap dump file error");
						}
					}

					puser_data l_user_data = new user_data();

					l_user_data->net_device_ptr = l_net_device_ptr;
					l_user_data->innser_ptr = (unsigned long)this;
					l_user_data->pcap_dump_ptr = dump_file;
					l_user_data->isdump = isdump;
					iret = pcap_loop(l_pcap_t, -1, xzhnids::pcap_handler, (u_char*)l_user_data);

					delete l_user_data;

					if (dump_file != NULL)
					{
						pcap_dump_close(dump_file);
					}

					if (l_pcap_t != NULL)
					{
						pcap_close(l_pcap_t);
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
						//debughelp::safe_debugstr(200, "12 not 8 13 not 0");
						break;
					}

					int idatalen = pkt_header->caplen - 14;

					ip_packet_node_ptr l_ip_packet_node_pt = ip_packet_node_ptr(new ip_packet_node());

					l_ip_packet_node_pt->set_packet_data().resize(idatalen);
				
					//memcpy(&data_vector[0], (char*)(pkt_data + 14), idatalen);
					copy(pkt_data + 14, pkt_data + pkt_header->caplen, l_ip_packet_node_pt->set_packet_data().begin());

					if (l_ip_packet_node_pt->set_packet_data().empty())
					{
						debughelp::safe_debugstr(200, "copy data error, len: %d", idatalen);
						break;
					}

					l_ip_packet_node_pt->set_net_device() = l_netdevice_ptr;

					//bounded_ip_packet_buffer_.push_front(l_ip_packet_node_pt);

					for (size_t index_ = 0; index_ < ipfragment_hub_.size(); index_ ++)
					{
						ipfragment_hub::return_type_ptr temp_ = ipfragment_hub_[index_];
						if (!temp_)
						{
							continue;
						}

						try
						{
							if((*temp_)(l_ip_packet_node_pt, l_ip_packet_node_pt->get_packet_data().size(), l_ip_packet_node_pt->set_net_device()))
							{
							}
							else
							{
							}
						}
						catch(...)
						{
						}
					}
					//{
					//	//lock
					//	boost::mutex::scoped_lock lock_(mutex_circular_);
					//	bounded_ip_packet_buffer_.push_front(l_ip_packet_node_pt);
					//	//unlock
					//}

				} while (false);
			}
			catch(...)
			{
			}
		}

		/*bool inner_consumer_handler()
		{
			while(true)
			{
				ip_packet_node_ptr l_ip_packet_node_pt;
				bounded_ip_packet_buffer_.pop_back(&l_ip_packet_node_pt);

				for (size_t index_ = 0; index_ < ipfragment_hub_.size(); index_ ++)
				{
					ipfragment_hub::return_type_ptr temp_ = ipfragment_hub_[index_];
					if (!temp_)
					{
						continue;
					}

					try
					{
						if((*temp_)(l_ip_packet_node_pt, l_ip_packet_node_pt->get_packet_data().size(), l_ip_packet_node_pt->set_net_device()))
						{
						}
						else
						{
						}
					}
					catch(...)
					{
					}
				}
			}
			
			return true;
		}*/

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

					if (l_user_data->isdump)
					{
						if (l_user_data->pcap_dump_ptr != NULL)
						{
							pcap_dump((u_char*)l_user_data->pcap_dump_ptr, pkt_header, pkt_data);
						}
					}

					xzhnids* xzhnids_ = (xzhnids*)l_user_data->innser_ptr;

					if (xzhnids_ == NULL)
					{
						break;
					}
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
		//bounded_ip_packet_buffer bounded_ip_packet_buffer_;
		//boost::thread_group thread_group_consumer_;
	};
};
#endif