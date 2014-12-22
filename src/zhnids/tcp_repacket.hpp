#ifndef TCP_REPACKET_HPP
#define TCP_REPACKET_HPP 

#include <string>
#include <list>

//#include <boost/threadpool.hpp>

#include <zhnids/packet_header.hpp>
#include <zhnids/stage/outdebug.hpp>
#include <zhnids/stage/pcap_hub.hpp>
#include <zhnids/stage/map_ptr_manager.hpp>

using namespace std;

namespace xzh
{
	typedef pcap_hub_impl<string, bool (tcp_queue_node_ptr)> tcp_retrans_hub;

	class tcp_queue
	{
	public:
		typedef map<unsigned int, tcp_queue_node_ptr> map_tcp_queue_data;
	public:
		explicit tcp_queue(tcp_retrans_hub& _tcp_retrans_hub)
			:seq_next_s(0),
			seq_next_r(0),
			tcp_retrans_hub_(_tcp_retrans_hub)
		{

		}
	public:
		bool add(tcp_queue_node_ptr tcp_node_ptr)
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
					bretvalue = true;
					break;
				}

				if (tcp_node_ptr->getstate() == tcp_data)
				{
					unsigned int ipacket_seq = tcp_node_ptr->getseq();
					if (tcp_node_ptr->isclient())
					{
						//debughelp::safe_debugstr(200, "client: want->seq[%x], data->seq[%x]", seq_next_s, tcp_node_ptr->getseq());
						do 
						{
							if (ipacket_seq == seq_next_s)
							{
								//debughelp::safe_debugstr(200, "ipacket:%x, seq_next_s:%x", ipacket_seq, seq_next_s);
								//debughelp::safe_debugstr(200, "hit seq ...,call back data ...");

								//todo ...
								//call back.....
								notify_tcppacket(tcp_node_ptr);

								seq_next_s = ipacket_seq + tcp_node_ptr->getdatalen();
								//debughelp::safe_debugstr(200, "call next data...%x", seq_next_s);

								boost::mutex::scoped_lock lock(map_tcp_queue_data_s_mutex);

								for (map_tcp_queue_data::iterator pos = map_tcp_queue_data_s.begin(); pos != map_tcp_queue_data_s.end(); )
								{
									if (pos->first < seq_next_s)
									{
										debughelp::safe_debugstr(200, "in list [%x] < want: [%x]", pos->first, seq_next_s);
										//直接从MAP中移除
										do 
										{
											tcp_queue_node_ptr l_tcp_node_ptr = pos->second;
											if (seq_next_s >= pos->first + l_tcp_node_ptr->getdatalen())
											{
												break;
											}

											debughelp::safe_debugstr(200, "remove data ....");
											unsigned int ioffset = seq_next_s - pos->first;
											if(!l_tcp_node_ptr->remove_data(ioffset))
											{
												debughelp::safe_debugstr(200, "remove data %d error!", ioffset);
												break;
											}

											seq_next_s = l_tcp_node_ptr->getseq() + l_tcp_node_ptr->getdatalen();

											notify_tcppacket(l_tcp_node_ptr);

										} while (false);

										map_tcp_queue_data_s.erase(pos ++);
									}
									else if (pos->first == seq_next_s)
									{
										debughelp::safe_debugstr(200, "in list [%x] = want: [%x]", pos->first, seq_next_s);
										//更新next_seq..
										tcp_queue_node_ptr l_node_ptr = pos->second;
										seq_next_s = seq_next_s + l_node_ptr->getdatalen();
										//回调数据,从map中移除
										//todo:
										//call back....
										notify_tcppacket(l_node_ptr);
										debughelp::safe_debugstr(200, "call next data...%x", seq_next_s);
										map_tcp_queue_data_s.erase(pos ++);
									}
									else if (pos->first > seq_next_s)
									{
										debughelp::safe_debugstr(200, "in list [%x] > want: [%x]", pos->first, seq_next_s);
										//next ...break..
										break;
									}
								}
								break;
							}

							if (ipacket_seq < seq_next_s)
							{
								debughelp::safe_debugstr(200, "packet less than seq_next_s, ignore? resend?? .....");
								debughelp::safe_debugstr(200, "ipacket:%x, seq_next_s:%x", ipacket_seq, seq_next_s);

								do 
								{
									if (seq_next_s >= ipacket_seq + tcp_node_ptr->getdatalen())
									{
										break;
									}

									debughelp::safe_debugstr(200, "remove data ....");
									unsigned int ioffset = seq_next_s - ipacket_seq;
									if(!tcp_node_ptr->remove_data(ioffset))
									{
										debughelp::safe_debugstr(200, "remove data %d error!", ioffset);
										break;
									}

									seq_next_s = tcp_node_ptr->getseq() + tcp_node_ptr->getdatalen();
									//boost::mutex::scoped_lock lock(map_tcp_queue_data_r_mutex);
									//map_tcp_queue_data_r.clear();
									notify_tcppacket(tcp_node_ptr);

								} while (false);


								break;
							}

							if (ipacket_seq > seq_next_s)
							{
								debughelp::safe_debugstr(200, "packet greate than seq_next_s ....need cache data ..");
								debughelp::safe_debugstr(200, "ipacket:%x, seq_next_s:%x", ipacket_seq, seq_next_s);
								boost::mutex::scoped_lock lock(map_tcp_queue_data_s_mutex);
								map_tcp_queue_data_s[ipacket_seq] = tcp_node_ptr;
							}
						} while (false);
					}
					else if (!tcp_node_ptr->isclient())
					{
						//debughelp::safe_debugstr(200, "server: want->seq[%x], data->seq[%x]", seq_next_r, tcp_node_ptr->getseq());
						do 
						{
							if (ipacket_seq == seq_next_r)
							{
								//debughelp::safe_debugstr(200, "ipacket:%x, seq_next_s:%x", ipacket_seq, seq_next_r);
								//debughelp::safe_debugstr(200, "r hit seq ...,call back data ...");

								seq_next_r = ipacket_seq + tcp_node_ptr->getdatalen();

								notify_tcppacket(tcp_node_ptr);

								//debughelp::safe_debugstr(200, "call next data...%x", seq_next_r);

								boost::mutex::scoped_lock lock(map_tcp_queue_data_r_mutex);

								for (map_tcp_queue_data::iterator pos = map_tcp_queue_data_r.begin(); pos != map_tcp_queue_data_r.end(); )
								{
									if (pos->first < seq_next_r)
									{
										debughelp::safe_debugstr(200, "r in list [%x] < want: [%x]", pos->first, seq_next_r);
										//直接从MAP中移除
										do 
										{
											tcp_queue_node_ptr l_tcp_node_ptr = pos->second;
											if (seq_next_r >= pos->first + l_tcp_node_ptr->getdatalen())
											{
												break;
											}

											debughelp::safe_debugstr(200, "r remove data ....");
											unsigned int ioffset = seq_next_r - pos->first;
											if(!l_tcp_node_ptr->remove_data(ioffset))
											{
												debughelp::safe_debugstr(200, "r remove data %d error!", ioffset);
												break;
											}

											//seq_next_r = seq_next_r + l_tcp_node_ptr->getdatalen();
											seq_next_r = l_tcp_node_ptr->getseq() + l_tcp_node_ptr->getdatalen();

											notify_tcppacket(l_tcp_node_ptr);

										} while (false);

										map_tcp_queue_data_r.erase(pos ++);
									}
									else if (pos->first == seq_next_r)
									{
										debughelp::safe_debugstr(200, "r in list [%x] = want: [%x]", pos->first, seq_next_r);
										//更新next_seq..
										tcp_queue_node_ptr l_node_ptr = pos->second;
										seq_next_r = seq_next_r + l_node_ptr->getdatalen();
										//回调数据,从map中移除
										//call next data...
										debughelp::safe_debugstr(200, "call next data...%x", seq_next_r);
										notify_tcppacket(l_node_ptr);
										map_tcp_queue_data_r.erase(pos ++);
									}
									else if (pos->first > seq_next_r)
									{
										debughelp::safe_debugstr(200, "r in list [%x] > want: [%x]", pos->first, seq_next_r);
										//next ...break..
										break;
									}
								}
								break;
							}

							if (ipacket_seq < seq_next_r)
							{
								debughelp::safe_debugstr(200, "r packet less than seq_next_r, ignore? resend?? .....");
								debughelp::safe_debugstr(200, "ipacket:%x, seq_next_s:%x", ipacket_seq, seq_next_r);

								do 
								{
									if (seq_next_r >= ipacket_seq + tcp_node_ptr->getdatalen())
									{
										break;
									}

									unsigned int ioffset = seq_next_r - ipacket_seq;
									if(!tcp_node_ptr->remove_data(ioffset))
									{
										debughelp::safe_debugstr(200, "remove data %d error!", ioffset);
										break;
									}

									//seq_next_r = seq_next_r + tcp_node_ptr->getdatalen();
									seq_next_r = tcp_node_ptr->getseq() + tcp_node_ptr->getdatalen();
									//boost::mutex::scoped_lock lock(map_tcp_queue_data_r_mutex);
									//map_tcp_queue_data_r.clear();

									notify_tcppacket(tcp_node_ptr);
									
								} while (false);

								break;
							}

							if (ipacket_seq > seq_next_r)
							{
								debughelp::safe_debugstr(200, "r packet greate than seq_next_r ....need cache data ..");
								debughelp::safe_debugstr(200, "ipacket:%x, seq_next_s:%x", ipacket_seq, seq_next_r);
								boost::mutex::scoped_lock lock(map_tcp_queue_data_r_mutex);
								map_tcp_queue_data_r[ipacket_seq] = tcp_node_ptr;
							}
						} while (false);
					}

					bretvalue = true;
					break;
				}

				if (tcp_node_ptr->getstate() == tcp_ending)
				{
					bretvalue = true;
					break;
				}
			} while (false);

			return bretvalue;
		}

		bool notify_tcppacket(tcp_queue_node_ptr tcp_queue_node_ptr_)
		{
			bool bretvalue = false;

			for (size_t index_ = 0; index_ < tcp_retrans_hub_.size(); index_ ++)
			{
				tcp_retrans_hub::return_type_ptr temp_ = tcp_retrans_hub_[index_];
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
		map_tcp_queue_data map_tcp_queue_data_s;
		map_tcp_queue_data map_tcp_queue_data_r;
		boost::mutex		map_tcp_queue_data_s_mutex;
		boost::mutex		map_tcp_queue_data_r_mutex;
		unsigned int seq_next_s;
		unsigned int seq_next_r;

		tcp_retrans_hub	&tcp_retrans_hub_;
	};


	class tcp_queue_manager
	{
	public:
		typedef map_ptr_manager<int, tcp_queue> tcp_queue_mn;
	public:
		explicit tcp_queue_manager(tcp_retrans_hub &_tcp_retrans_hub)
			:tcp_retrans_hub_(_tcp_retrans_hub)
		{

		}
	public:
		bool dispatch(tcp_queue_node_ptr tcp_queue_node_)
		{
			bool bretvalue = false;

			do 
			{
				if (!tcp_queue_node_)
				{
					debughelp::safe_debugstr(200, "tcp_queue_node nil");
					break;
				}

				if ((tcp_queue_node_->getstate() == tcp_end))
				{
					bretvalue = tcp_queue_mn_.del(tcp_queue_node_->get_tuple_hash());
					if (!bretvalue)
					{
						debughelp::safe_debugstr(200, "del error!");
					}
					break;
				}

				if ((tcp_queue_node_->getstate() == tcp_connect)
					||(tcp_queue_node_->getstate() == tcp_data)
					||(tcp_queue_node_->getstate() == tcp_ending))
				{
					bretvalue = innser_add(tcp_queue_node_);

					if (!bretvalue)
					{
						debughelp::safe_debugstr(200, "add error!");
					}
					break;
				}

				debughelp::safe_debugstr(200, "un... error!");
				bretvalue = false;

			} while (false);

			return bretvalue;
		}

	private:
		bool innser_add(tcp_queue_node_ptr tcp_queue_node_)
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
		tcp_retrans_hub &tcp_retrans_hub_;
	};

	typedef boost::shared_ptr<tcp_queue_manager> tcp_queue_manager_ptr;

	//////////////////////////////////////////////////////////////////////////
	class tcp_repacket
	{
	public:
		template <typename TFun>
		bool add_retrans_handler(string key_, TFun callfun_)
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
		bool retrans_handler(tcp_queue_node_ptr tcp_queue_node_ptr_)
		{
			bool bretvalue = false;

			do 
			{
				if (!tcp_queue_mn_ptr)
				{
					debughelp::safe_debugstr(200, "tcp_queue_mn_ptr nil");
					break;
				}
				if (!tcp_queue_node_ptr_)
				{
					debughelp::safe_debugstr(200, "tcp_queue_node_ptr nil");
					break;
				}

				if(tcp_queue_mn_ptr->dispatch(tcp_queue_node_ptr_))
				{
					//debughelp::safe_debugstr(200, "queue mn dispatch ok!");
				}
				else
				{
					debughelp::safe_debugstr(200, "queue mn dispatch error!");
				}

			} while (false);

			return bretvalue;
		}
	private:
		tcp_retrans_hub tcp_retrans_hub_;
		tcp_queue_manager_ptr tcp_queue_mn_ptr;
	};
};
#endif