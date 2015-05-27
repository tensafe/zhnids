#ifndef PACKET_HEADER_HPP
#define PACKET_HEADER_HPP

#include <vector>
#include <string>
#include <boost/range.hpp>

#include <boost/functional/hash.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/logic/tribool.hpp>
using namespace std;

namespace xzh
{
	//////////////////////////////////////////////////////////////////////////
	struct netaddr_info
	{
		netaddr_info()
		{
			netaddr = 0xffffff;
			netmask = 0xffffff;
			broadaddr = 0xffffff;
			dstaddr = 0xffffff;
		}
		unsigned long netaddr;
		unsigned long netmask;
		unsigned long broadaddr;
		unsigned long dstaddr;
		unsigned short sa_family;

	};

	class netdevice
	{
	public:
		typedef vector<netaddr_info> netaddr_vector;
	public:
		string& set_device_name()
		{
			return device_name;
		}
		const string &get_device_name()
		{
			return device_name;
		}

		netaddr_vector &set_netaddr_vector()
		{
			return netaddr_vector_;
		}
		const netaddr_vector &get_netaddr_vector()
		{
			return netaddr_vector_;
		}

		bool& set_lookback()
		{
			return isloopback;
		}

		const bool& get_lookback()
		{
			return isloopback;
		}
	private:
		netaddr_vector netaddr_vector_;
		string device_name;
		bool isloopback;		
	};
	typedef boost::shared_ptr<netdevice> netdevice_ptr;


	typedef vector<unsigned char> ip_packet_data;

	typedef vector<unsigned char> ether_addr_data;

	class ip_packet_node
	{
	public:
		const ip_packet_data& get_packet_data()
		{
			return ip_packet_data_;
		}

		ip_packet_data& set_packet_data()
		{
			return ip_packet_data_;
		}

		const netdevice_ptr& get_net_device()
		{
			return netdevice_ptr_;
		}
		
		netdevice_ptr &set_net_device()
		{
			return netdevice_ptr_;
		}

		const ether_addr_data& get_dst_ether_addr()
		{
			return dst_ether;
		}

		ether_addr_data &set_dst_ether_addr()
		{
			return dst_ether;
		}

		const ether_addr_data& get_src_ether_addr()
		{
			return src_ether;
		}

		ether_addr_data &set_src_ether_addr()
		{
			return src_ether;
		}

	private:
		ip_packet_data ip_packet_data_;
		netdevice_ptr  netdevice_ptr_;
		ether_addr_data dst_ether;
		ether_addr_data src_ether;
	};
	typedef boost::shared_ptr<ip_packet_node> ip_packet_node_ptr;

	enum xzh_tcp_state
	{
		tcp_connect = 0x10,
		tcp_data,
		tcp_ending,//need flush data...
		tcp_end
	};

	class tcp_packet_node
	{
	public:
		//typedef vector<unsigned char>	tcp_packet_data;
		typedef boost::iterator_range<ip_packet_data::iterator>	tcp_packet_data;
		typedef vector<unsigned int>	tcp_tuple_data;

	private:
		enum vector_offset
		{
			srcip = 1,
			dstip,
			srcport,
			dstport,
			client,
			seq,
			ack_seq,
			state,
			len,
		};

	public:
		explicit tcp_packet_node(unsigned int s_ip,
			unsigned int d_ip,
			unsigned int s_port,
			unsigned int d_port,
			unsigned int bclient,
			unsigned int d_seq,
			unsigned int d_ack_seq,
			unsigned int tcp_state,
			unsigned int data_len)
		{
			tcp_tuple_data_.push_back(0);
			tcp_tuple_data_.push_back(s_ip);
			tcp_tuple_data_.push_back(d_ip);
			tcp_tuple_data_.push_back(s_port);
			tcp_tuple_data_.push_back(d_port);
			tcp_tuple_data_.push_back(bclient);
			tcp_tuple_data_.push_back(d_seq);
			tcp_tuple_data_.push_back(d_ack_seq);
			tcp_tuple_data_.push_back(tcp_state);
			tcp_tuple_data_.push_back(data_len);
		}
		~tcp_packet_node()
		{
			tcp_tuple_data_.clear();
		}
	public:
		template <typename data>
		bool add_data(data &data_)
		{
			int ioffset = tcp_pakcet_data_.size();
			tcp_pakcet_data_.resize(ioffset + data_.size());
			copy(data_.begin(), data_.end(), tcp_pakcet_data_.begin() + ioffset);

			return !tcp_pakcet_data_.empty();
		}

		template <typename data>
		bool copy_data(data &data_)
		{
			copy(tcp_pakcet_data_.begin(), tcp_pakcet_data_.end(), inserter(data_, data_.end()));
			return !data_.empty();
		}

		const tcp_packet_data &get_tcp_packet_data()
		{
			return tcp_pakcet_data_;
		}

		tcp_packet_data &set_tcp_packet_data()
		{
			return tcp_pakcet_data_;
		}

		bool remove_data(unsigned int iremove_len)
		{
			bool bretvalue = false;

			do 
			{
				if (iremove_len > tcp_pakcet_data_.size())
				{
					bretvalue = true;
					break;
				}

				//tcp_pakcet_data_.erase(tcp_pakcet_data_.begin(), tcp_pakcet_data_.begin() + iremove_len);
				tcp_pakcet_data_ = boost::make_iterator_range(tcp_pakcet_data_.begin() + iremove_len, tcp_pakcet_data_.end());

				tcp_tuple_data_[len] = tcp_pakcet_data_.size();

				bretvalue = true;

			} while (false);

			return bretvalue;
		}

		ip_packet_node_ptr &set_ip_packet_data()
		{
			return ip_packet_node_;
		}

		const ip_packet_node_ptr &get_ip_packet_data()
		{
			return ip_packet_node_;
		}

	public:
		unsigned int get_tuple_hash()
		{
			return boost::hash_range(tcp_tuple_data_.begin(), tcp_tuple_data_.begin() + dstport);
		}

		unsigned int get_client_hash()
		{
			return boost::hash_range(tcp_tuple_data_.begin(), tcp_tuple_data_.begin() + client);
		}

		unsigned int getseq()
		{
			return tcp_tuple_data_[seq];
		}

		unsigned int getackseq()
		{
			return tcp_tuple_data_[ack_seq];
		}

		unsigned int getstate()
		{
			return tcp_tuple_data_[state];
		}

		unsigned int getdatalen()
		{
			return tcp_tuple_data_[len];
		}

		unsigned int gets_ip()
		{
			return tcp_tuple_data_[srcip];
		}

		unsigned int getd_ip()
		{
			return tcp_tuple_data_[dstip];
		}

		unsigned short gets_port()
		{
			return (unsigned short)tcp_tuple_data_[srcport];
		}

		unsigned short getd_port()
		{
			return (unsigned short)tcp_tuple_data_[dstport];
		}

		bool isclient()
		{
			return (tcp_tuple_data_[client] == 0) ? false : true;
		}
	public:
		netdevice_ptr get_netdevice_ptr()
		{
			return netdevice_ptr_;
		}

		bool set_netdevice_ptr(netdevice_ptr _netdevice_ptr)
		{
			bool bretvalue = false;
			do 
			{
				if (!_netdevice_ptr)
				{
					break;
				}
				netdevice_ptr_ = _netdevice_ptr;
			} while (false);
			return bretvalue;
		}
	private:
		tcp_packet_data tcp_pakcet_data_;
		tcp_tuple_data tcp_tuple_data_;
		ip_packet_node_ptr ip_packet_node_;
		netdevice_ptr	netdevice_ptr_;
	};
	typedef boost::shared_ptr<tcp_packet_node> tcp_packet_node_ptr;


	class udp_packet_node
	{
	public:
		typedef boost::iterator_range<ip_packet_data::iterator>	 udp_packet_data;
		typedef vector<unsigned int>  udp_tuple_data;

	private:
		enum vector_offset
		{
			srcip = 1,
			dstip,
			srcport,
			dstport,
			len,
		};

	public:
		explicit udp_packet_node(unsigned int s_ip,
			unsigned int d_ip,
			unsigned int s_port,
			unsigned int d_port,
			unsigned int data_len)
		{
			udp_tuple_data_.push_back(0);
			udp_tuple_data_.push_back(s_ip);
			udp_tuple_data_.push_back(d_ip);
			udp_tuple_data_.push_back(s_port);
			udp_tuple_data_.push_back(d_port);
			udp_tuple_data_.push_back(data_len);
		}
		~udp_packet_node()
		{
			udp_tuple_data_.clear();
		}
	public:
		template <typename data>
		bool add_data(data &data_)
		{
			copy(data_.begin(), data_.end(), inserter(udp_packet_data_, udp_packet_data_.end()));
			return !udp_packet_data_.empty();
		}

		template <typename data>
		bool copy_data(data &data_)
		{
			copy(udp_packet_data_.begin(), udp_packet_data_.end(), inserter(data_, data_.end()));
			return !data_.empty();
		}

		const udp_packet_data &get_udp_packet_data()
		{
			return udp_packet_data_;
		}

		udp_packet_data &set_udp_packet_data()
		{
			return udp_packet_data_;
		}

		bool remove_data(unsigned int iremove_len)
		{
			bool bretvalue = false;
			do 
			{
				if (iremove_len > udp_packet_data_.size())
				{
					bretvalue = true;
					break;
				}
				//udp_packet_data_.erase(udp_packet_data_.begin(), udp_packet_data_.begin() + iremove_len);
				udp_packet_data_ = boost::make_iterator_range(udp_packet_data_.begin() + iremove_len, udp_packet_data_.end());

				bretvalue = true;
			} while (false);

			return bretvalue;
		}

	public:
		unsigned int get_tuple_hash()
		{
			return boost::hash_range(udp_tuple_data_.begin(), udp_tuple_data_.begin() + dstport);
		}

		unsigned int getdatalen()
		{
			return udp_tuple_data_[len];
		}

		unsigned int gets_ip()
		{
			return udp_tuple_data_[srcip];
		}

		unsigned int getd_ip()
		{
			return udp_tuple_data_[dstip];
		}

		unsigned short gets_port()
		{
			return (unsigned short)udp_tuple_data_[srcport];
		}

		unsigned short getd_port()
		{
			return (unsigned short)udp_tuple_data_[dstport];
		}

		ip_packet_node_ptr &set_ip_packet_data()
		{
			return ip_packet_node_;
		}

		const ip_packet_node_ptr &get_ip_packet_data()
		{
			return ip_packet_node_;
		}

	public:
		netdevice_ptr get_netdevice_ptr()
		{
			return netdevice_ptr_;
		}

		bool set_netdevice_ptr(netdevice_ptr _netdevice_ptr)
		{
			bool bretvalue = false;
			do 
			{
				if (!_netdevice_ptr)
				{
					break;
				}
				netdevice_ptr_ = _netdevice_ptr;
			} while (false);
			return bretvalue;
		}
	private:
		udp_tuple_data	udp_tuple_data_;
		udp_packet_data	udp_packet_data_;
		ip_packet_node_ptr ip_packet_node_;
		netdevice_ptr   netdevice_ptr_;
	};
	typedef boost::shared_ptr<udp_packet_node> udp_packet_node_ptr;
	
		struct header
	{
		std::string name;
		std::string value;
	};

	struct http_request
	{
		/// The request method, e.g. "GET", "POST".
		std::string method;

		/// The requested URI, such as a path to a file.
		std::string uri;

		/// Major version number, usually 1.
		int http_version_major;

		/// Minor version number, usually 0 or 1.
		int http_version_minor;

		/// The headers included with the request.
		std::vector<header> headers;

		/// The optional content sent with the request.
		std::string content;
	};

//#define content_max_cache (1 * 1024 * 1024)

	struct http_response
	{
		/// return status code
		int status_code;

		/// OK ....
		string status;

		/// Major version number, usually 1.
		int http_version_major;

		/// Minor version number, usually 0 or 1.
		int http_version_minor;

		/// The headers included with the request.
		std::vector<header> headers;

		/// The optional content sent with the request.
		std::string content;

		/// total length...
		int total_length;
		
		/// recv length...
		int recv_length;

		boost::tribool repares_status;

		http_response()
		{
			//content.reserve(content_max_cache + 100);
			total_length = -1;
			recv_length = 0;
		}
	};

	class http_packet_data
	{
	public:
		enum http_packet_type
		{
			http_request_type = 0,
			http_response_type,
		};
	public:
		const http_response &get_http_response()
		{
			return http_response_;
		}

		http_response &set_http_response()
		{
			return http_response_;
		}

		const http_request &get_http_request()
		{
			return http_request_;
		}

		http_request &set_http_request()
		{
			return http_request_;
		}

		const int &get_http_data_type()
		{
			return http_data_type_;
		}

		int &set_http_data_type()
		{
			return http_data_type_;
		}
	private:
		int http_data_type_;
		http_response http_response_;
		http_request  http_request_;
	};

	typedef boost::shared_ptr<http_packet_data> http_packet_data_ptr;
};

#endif