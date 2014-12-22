#ifndef _map_ptr_manager_hpp__
#define _map_ptr_manager_hpp__
#pragma once
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <map>
namespace xzh
{
	template<class key, class session_impl>
	class map_ptr_manager
	{
	public:
		typedef boost::shared_ptr<session_impl> shared_impl_ptr;
		typedef std::map<key, shared_impl_ptr> map_ptr;
	public:
		bool add(key strkey,  shared_impl_ptr sesson_impl_ptr_)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock lock(map_mutex_);
				map_session_.insert(make_pair(strkey, sesson_impl_ptr_));

				bretvalue = true;
			} while (false);

			return bretvalue;
		}

		shared_impl_ptr get(key strkey)
		{
			shared_impl_ptr smtp_session_ret;

			do 
			{
				boost::mutex::scoped_lock lock(map_mutex_);

				map_ptr::iterator pos = map_session_.find(strkey);
				if (pos == map_session_.end())
				{
					break;
				}
				smtp_session_ret = pos->second;

			} while (false);

			return smtp_session_ret;
		}

		bool del(key strkey)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock lock(map_mutex_);
				map_session_.erase(strkey);
				bretvalue = true;

			} while (false);

			return bretvalue;
		}

		bool clear()
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock lock(map_mutex_);
				map_session_.clear();
				bretvalue = true;

			} while (false);

			return bretvalue;
		}

		bool check(key strkey)
		{
			bool bretvalue = false;

			do 
			{
				boost::mutex::scoped_lock lock(map_mutex_);
				map_ptr::iterator pos = map_session_.find(strkey);
				if (pos == map_session_.end())
				{
					bretvalue = false;
					break;
				}
				bretvalue = true;

			} while (false);

			return bretvalue;
		}
	private:
		boost::mutex map_mutex_;
		map_ptr map_session_;
	};
};
#endif
