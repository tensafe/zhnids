#ifndef KVSPLIT_HPP
#define KVSPLIT_HPP

#include <boost/algorithm/string.hpp>
#include <vector>
#include <map>
#include <string>

namespace xzh
{
	// for map,multmap....
	template<typename Data, typename Result>
	bool kvsplit(/*[in]*/Data &data_, /*[in]*/std::string split_1, /*[in]*/std::string split_2, /*[out]*/Result &kvmap_)
	{
		bool bretvalue = false;
		typedef boost::split_iterator<typename Data::iterator> data_split_iterator;
		typedef std::vector<boost::iterator_range<Data::iterator> > find_vector_type;

		do 
		{
			find_vector_type find_vector_type_;

			data_split_iterator head_it = boost::make_split_iterator(data_, boost::first_finder(split_1, boost::is_iequal()));
			for (; head_it != data_split_iterator(); head_it ++)
			{
				find_vector_type_.push_back(*head_it);
			}

			if (find_vector_type_.empty())
			{
				break;
			}

			for (find_vector_type::iterator pos_ = find_vector_type_.begin();pos_ != find_vector_type_.end(); pos_ ++)
			{
				do 
				{
					data_split_iterator key_value_pos = boost::make_split_iterator(*pos_, boost::first_finder(split_2, boost::is_iequal()));
					if (key_value_pos == data_split_iterator())
					{
						break;
					}

					std::string key_ = boost::copy_range<std::string>(*key_value_pos);

					key_value_pos ++;

					if (key_value_pos == data_split_iterator())
					{
						break;
					}

					std::string value_ = boost::copy_range<std::string>(*key_value_pos);

					kvmap_.insert(std::make_pair(key_, value_));
				} while (false);
			}
		} while (false);

		return !kvmap_.empty();
	}
};
#endif

/*
string strva = "aaaa=1&bbbb=2";
map<string, string> kv_map;
xzh::kvsplit<string>(strva, "&", "=", kv_map);

for(map<string, string>::iterator pos = kv_map.begin(); pos != kv_map.end(); pos ++)
{
cout << pos->first << "::::::" << pos->second << endl;
}
return 0;

aaaa::::::1
bbbb::::::2
*/