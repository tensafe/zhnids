#ifndef PACKET_HEADER_HPP
#define PACKET_HEADER_HPP

#include <vector>
#include <string>

#include <boost/functional/hash.hpp>
#include <boost/shared_ptr.hpp>
using namespace std;

namespace xzh
{
	//////////////////////////////////////////////////////////////////////////
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
		typedef vector<unsigned char>	tcp_packet_data;
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
			tcp_pakcet_data_.clear();
		}
	public:
		template <typename data>
		bool add_data(data &data_)
		{
			copy(data_.begin(), data_.end(), inserter(tcp_pakcet_data_, tcp_pakcet_data_.begin()));
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

				tcp_pakcet_data_.erase(tcp_pakcet_data_.begin(), tcp_pakcet_data_.begin() + iremove_len);

				bretvalue = true;

			} while (false);

			return bretvalue;
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
	private:
		tcp_packet_data tcp_pakcet_data_;
		tcp_tuple_data tcp_tuple_data_;
	};

	typedef boost::shared_ptr<tcp_packet_node> tcp_packet_node_ptr;


	class udp_packet_node
	{
	public:
		typedef vector<unsigned char> udp_packet_data;
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
			udp_packet_data_.clear();
		}
	public:
		template <typename data>
		bool add_data(data &data_)
		{
			copy(data_.begin(), data_.end(), inserter(udp_packet_data_, udp_packet_data_.begin()));
			return !udp_packet_data_.empty();
		}

		template <typename data>
		bool copy_data(data &data_)
		{
			copy(udp_packet_data_.begin(), udp_packet_data_.end(), inserter(data_, data_.end()));
			return !data_.empty();
		}

		const udp_packet_data &get_tcp_packet_data()
		{
			return udp_packet_data_;
		}

		udp_packet_data &set_tcp_packet_data()
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

				udp_packet_data_.erase(udp_packet_data_.begin(), udp_packet_data_.begin() + iremove_len);

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
	private:
		udp_tuple_data	udp_tuple_data_;
		udp_packet_data	udp_packet_data_;
	};

	typedef boost::shared_ptr<udp_packet_node> udp_packet_node_ptr;
};

#endif