#ifndef TCP_REPACKET_HPP
#define TCP_REPACKET_HPP 

#include <string>
#include <list>

#include <zhnids/packet_header.hpp>
#include <zhnids/stage/outdebug.hpp>
#include <zhnids/stage/pcap_hub.hpp>
#include <zhnids/stage/map_ptr_manager.hpp>

using namespace std;

namespace xzh
{
	typedef pcap_hub_impl<string, bool (tcp_packet_node_ptr)> tcp_repacket_hub;

	class tcp_queue
	{
	public:
		typedef map<unsigned int, tcp_packet_node_ptr> map_tcp_queue_data;
	public:
		explicit tcp_queue(tcp_repacket_hub& _tcp_retrans_hub)
			:seq_next_s(0),
			seq_next_r(0),
			tcp_repacket_hub_(_tcp_retrans_hub)
		{

		}
	public:
		bool add(tcp_packet_node_ptr tcp_node_ptr)
		{
			bool bretvalue = false;

			do 
			{
				if (!tcp_node_ptr)
				{
					break;
				}

				if (tcp_node_ptr->getstate() == tcp_connect)
				{
					//设置初始SEQ..
					seq_next_s = tcp_node_ptr->getseq();
					seq_next_r = tcp_node_ptr->getackseq();
					notify_tcppacket(tcp_node_ptr);
					bretvalue = true;
					break;
				}

				if (tcp_node_ptr->getstate() == tcp_data)
				{
					unsigned int ipacket_seq = tcp_node_ptr->getseq();
					if (tcp_node_ptr->isclient())
					{
						do 
						{
							if (ipacket_seq == seq_next_s)
							{
								notify_tcppacket(tcp_node_ptr);

								seq_next_s = ipacket_seq + tcp_node_ptr->getdatalen();

								boost::mutex::scoped_lock lock(map_tcp_queue_data_s_mutex);

								for (map_tcp_queue_data::iterator pos = map_tcp_queue_data_s.begin(); pos != map_tcp_queue_data_s.end(); )
								{
									if (pos->first < seq_next_s)
									{
										//直接从MAP中移除
										do 
										{
											tcp_packet_node_ptr l_tcp_node_ptr = pos->second;
											if (seq_next_s >= pos->first + l_tcp_node_ptr->getdatalen())
											{
												break;
											}

											unsigned int ioffset = seq_next_s - pos->first;
											if(!l_tcp_node_ptr->remove_data(ioffset))
											{
												break;
											}

											seq_next_s = seq_next_s + l_tcp_node_ptr->getdatalen();

											notify_tcppacket(l_tcp_node_ptr);

										} while (false);

										map_tcp_queue_data_s.erase(pos ++);
									}
									else if (pos->first == seq_next_s)
									{
										//更新next_seq..
										tcp_packet_node_ptr l_node_ptr = pos->second;
										seq_next_s = seq_next_s + l_node_ptr->getdatalen();
										//回调数据,从map中移除
										//todo:
										//call back....
										notify_tcppacket(l_node_ptr);
										map_tcp_queue_data_s.erase(pos ++);
									}
									else if (pos->first > seq_next_s)
									{
										//next ...break..
										break;
									}
								}
								break;
							}

							if (ipacket_seq < seq_next_s)
							{
								do 
								{
									if (seq_next_s >= ipacket_seq + tcp_node_ptr->getdatalen())
									{
										break;
									}

									unsigned int ioffset = seq_next_s - ipacket_seq;
									if(!tcp_node_ptr->remove_data(ioffset))
									{
										break;
									}

									//seq_next_s = tcp_node_ptr->getseq() + tcp_node_ptr->getdatalen();
									seq_next_s = seq_next_s + tcp_node_ptr->getdatalen();

									notify_tcppacket(tcp_node_ptr);

								} while (false);


								break;
							}

							if (ipacket_seq > seq_next_s)
							{
								boost::mutex::scoped_lock lock(map_tcp_queue_data_s_mutex);
								map_tcp_queue_data_s[ipacket_seq] = tcp_node_ptr;
							}
						} while (false);
					}
					else if (!tcp_node_ptr->isclient())
					{
						do 
						{
							if (ipacket_seq == seq_next_r)
							{
								seq_next_r = ipacket_seq + tcp_node_ptr->getdatalen();

								notify_tcppacket(tcp_node_ptr);

								boost::mutex::scoped_lock lock(map_tcp_queue_data_r_mutex);

								for (map_tcp_queue_data::iterator pos = map_tcp_queue_data_r.begin(); pos != map_tcp_queue_data_r.end(); )
								{
									if (pos->first < seq_next_r)
									{
										//直接从MAP中移除
										do 
										{
											tcp_packet_node_ptr l_tcp_node_ptr = pos->second;
											if (seq_next_r >= pos->first + l_tcp_node_ptr->getdatalen())
											{
												break;
											}

											unsigned int ioffset = seq_next_r - pos->first;
											if(!l_tcp_node_ptr->remove_data(ioffset))
											{
												break;
											}

											seq_next_r = l_tcp_node_ptr->getseq() + l_tcp_node_ptr->getdatalen();

											notify_tcppacket(l_tcp_node_ptr);

										} while (false);

										map_tcp_queue_data_r.erase(pos ++);
									}
									else if (pos->first == seq_next_r)
									{
										//更新next_seq..
										tcp_packet_node_ptr l_node_ptr = pos->second;
										seq_next_r = seq_next_r + l_node_ptr->getdatalen();
										//回调数据,从map中移除
										//call next data...
										notify_tcppacket(l_node_ptr);
										map_tcp_queue_data_r.erase(pos ++);
									}
									else if (pos->first > seq_next_r)
									{
										//next ...break..
										break;
									}
								}
								break;
							}

							if (ipacket_seq < seq_next_r)
							{
								do 
								{
									if (seq_next_r >= ipacket_seq + tcp_node_ptr->getdatalen())
									{
										break;
									}

									unsigned int ioffset = seq_next_r - ipacket_seq;
									if(!tcp_node_ptr->remove_data(ioffset))
									{
										break;
									}

									seq_next_r = tcp_node_ptr->getseq() + tcp_node_ptr->getdatalen();

									notify_tcppacket(tcp_node_ptr);
									
								} while (false);

								break;
							}

							if (ipacket_seq > seq_next_r)
							{
								boost::mutex::scoped_lock lock(map_tcp_queue_data_r_mutex);
								map_tcp_queue_data_r[ipacket_seq] = tcp_node_ptr;
							}
						} while (false);
					}

					bretvalue = true;
					break;
				}

				if ((tcp_node_ptr->getstate() == tcp_ending)
					||(tcp_node_ptr->getstate() == tcp_end))
				{
					notify_tcppacket(tcp_node_ptr);
					bretvalue = true;
					break;
				}
				
			} while (false);

			return bretvalue;
		}

		bool notify_tcppacket(tcp_packet_node_ptr tcp_packet_ptr_)
		{
			bool bretvalue = false;

			if (!tcp_packet_ptr_)
			{
				return false;
			}

			for (size_t index_ = 0; index_ < tcp_repacket_hub_.size(); index_ ++)
			{
				tcp_repacket_hub::return_type_ptr temp_ = tcp_repacket_hub_[index_];
				if (!temp_)
				{
					continue;
				}

				if((*temp_)(tcp_packet_ptr_))
				{
				}
				else
				{
				}
			}

			return bretvalue;
		}
	private:
		map_tcp_queue_data map_tcp_queue_data_s;
		map_tcp_queue_data map_tcp_queue_data_r;
		boost::mutex		map_tcp_queue_data_s_mutex;
		boost::mutex		map_tcp_queue_data_r_mutex;
		unsigned int seq_next_s;
		unsigned int seq_next_r;

		tcp_repacket_hub	&tcp_repacket_hub_;
	};


	class tcp_queue_manager
	{
	public:
		typedef map_ptr_manager<int, tcp_queue> tcp_queue_mn;
	public:
		explicit tcp_queue_manager(tcp_repacket_hub &_tcp_retrans_hub)
			:tcp_retrans_hub_(_tcp_retrans_hub)
		{

		}
	public:
		bool dispatch(tcp_packet_node_ptr tcp_queue_node_)
		{
			bool bretvalue = false;

			do 
			{
				if (!tcp_queue_node_)
				{
					break;
				}

				bretvalue = innser_add(tcp_queue_node_);

				if (!bretvalue)
				{
					break;
				}


				if ((tcp_queue_node_->getstate() == tcp_end))
				{
					bretvalue = tcp_queue_mn_.del(tcp_queue_node_->get_tuple_hash());
					if (!bretvalue)
					{
					}
					break;
				}

			} while (false);

			return bretvalue;
		}

	private:
		bool innser_add(tcp_packet_node_ptr tcp_queue_node_)
		{
			bool bretvalue = false;

			do 
			{
				if (!tcp_queue_node_)
				{
					break;
				}

				unsigned int ituple_hash = tcp_queue_node_->get_tuple_hash();

				tcp_queue_mn::shared_impl_ptr l_tcp_queue_ptr_ = tcp_queue_mn_.get(ituple_hash);
				if (!l_tcp_queue_ptr_)
				{
					l_tcp_queue_ptr_ = tcp_queue_mn::shared_impl_ptr(new tcp_queue(tcp_retrans_hub_));
					tcp_queue_mn_.add(ituple_hash, l_tcp_queue_ptr_);
				}

				if (!l_tcp_queue_ptr_)
				{
					break;
				}

				bretvalue = l_tcp_queue_ptr_->add(tcp_queue_node_);

			} while (false);
			return bretvalue;
		}
	private:
		tcp_queue_mn tcp_queue_mn_;
		tcp_repacket_hub &tcp_retrans_hub_;
	};

	typedef boost::shared_ptr<tcp_queue_manager> tcp_queue_manager_ptr;

	//////////////////////////////////////////////////////////////////////////
	class tcp_repacket
	{
	public:
		template <typename TFun>
		bool add_repacket_handler(string key_, TFun callfun_)
		{
			return tcp_retrans_hub_.add_handler(key_, callfun_);
		}
	public:
		tcp_repacket()
		{
			tcp_queue_mn_ptr = tcp_queue_manager_ptr(new tcp_queue_manager(tcp_retrans_hub_));
		}
		~tcp_repacket()
		{

		}
		bool repacket_handler(tcp_packet_node_ptr tcp_queue_node_ptr_)
		{
			bool bretvalue = false;

			do 
			{
				if (!tcp_queue_mn_ptr)
				{
					break;
				}
				if (!tcp_queue_node_ptr_)
				{
					break;
				}

				if(tcp_queue_mn_ptr->dispatch(tcp_queue_node_ptr_))
				{
				}
				else
				{
				}

			} while (false);

			return bretvalue;
		}
	private:
		tcp_repacket_hub tcp_retrans_hub_;
		tcp_queue_manager_ptr tcp_queue_mn_ptr;
	};
};
#endif