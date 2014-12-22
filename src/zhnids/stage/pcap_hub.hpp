#ifndef _message_hub_hpp__
#define _message_hub_hpp__
#pragma once
#include <boost/signals2.hpp>
#include <boost/shared_ptr.hpp>
#include <map>

namespace xzh
{
	template <class TKey, class TFunType>
	class pcap_hub_impl
	{
	public:
		typedef TFunType return_type;
		typedef TKey	 key_type;
		typedef boost::signals2::signal<return_type > boost_signal;
		typedef boost::shared_ptr<boost_signal> boost_signal_ptr;
		typedef std::map<key_type, boost_signal_ptr> handler;
		typedef boost_signal_ptr return_type_ptr;
		typedef const boost_signal_ptr const_return_type_ptr;

	public:
		template <typename Func_>
		bool add_handler(key_type key_,  Func_ f)
		{
			bool bretvalue = false;
			do 
			{
				boost_signal_ptr l_signal_fun_ptr = boost_signal_ptr(new boost_signal());
				l_signal_fun_ptr->connect(f);
				std::pair<handler::iterator, bool>l_insert_ret = handler_.insert(make_pair(key_, l_signal_fun_ptr));
				bretvalue = l_insert_ret.second;
			} while (false);
			return bretvalue;
		}

		void del_handler(key_type key_)
		{
			handler_.erase(key_);
		}

		const_return_type_ptr get(key_type key_) const
		{
			return_type_ptr l_ret_value_ptr;
			do
			{
				handler::const_iterator pos = handler_.find(key_);
				if (pos == handler_.end())
				{
					break;
				}
				l_ret_value_ptr = pos->second;
			}
			while(false);
			return l_ret_value_ptr;
		}

		const_return_type_ptr operator[] (int offset_) const
		{
			return_type_ptr l_ret_value_ptr;
			do
			{
				
				handler::const_iterator pos = handler_.begin();
				advance(pos, offset_);
				if (pos == handler_.end())
				{
					break;
				}
				l_ret_value_ptr = pos->second;
			}
			while(false);
			return l_ret_value_ptr;
		}

		key_type getkey(int offset_)
		{
			key_type key_value_;
			do
			{

				handler::const_iterator pos = handler_.begin();
				advance(pos, offset_);
				if (pos == handler_.end())
				{
					break;
				}
				key_value_ = pos->first;
			}
			while(false);

			return key_value_;
		}

		bool check(key_type key_)
		{
			handler::iterator pos_find = handler_.find(key_);
			return (pos_find != handler_.end());
		}

		size_t size()
		{
			return handler_.size();
		}
	private:
		handler handler_;
	};
}

#endif