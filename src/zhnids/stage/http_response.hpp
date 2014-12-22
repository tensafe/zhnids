#ifndef HTTP_RESPONSE_HPP
#define HTTP_RESPONSE_HPP

#include <boost/algorithm/string.hpp>
#include <map>
#include <string>
#include <vector>

namespace xzh
{
	template <class response>
	class http_response
	{
	public:
		typedef std::multimap<std::string, std::string> http_headdic;
		typedef boost::split_iterator<typename response::iterator> httpdata_split_iterator;
	public:
		http_response(response &http_raw_data)
			:http_raw_data_(http_raw_data)
		{
			parse();
		}

	public:
		std::string gethead(const std::string strkey)
		{
			return http_head_dic_[strkey];
		}

		std::string getstatus()
		{
			return http_status_;
		}

		std::string getvertion()
		{
			return http_vertion;
		}

		std::string getphrase()
		{
			return http_phrase;
		}

		template<typename Body>
		bool getbody(Body &body_)
		{
			bool bretvalue = false;

			do 
			{
				httpdata_split_iterator It = boost::make_split_iterator(http_raw_data_, boost::first_finder("\r\n\r\n", boost::is_iequal()));

				if (It == httpdata_split_iterator())
				{
					break;
				}

				advance(It, 1);

				if (It == httpdata_split_iterator())
				{
					break;
				}

				copy(boost::begin(*It), http_raw_data_.end(), inserter(body_, body_.begin()));
			} while (false);

			return !body_.empty();
		}

	private:
		bool parse()
		{
			do 
			{
				httpdata_split_iterator It = boost::make_split_iterator(http_raw_data_, boost::first_finder("\r\n\r\n", boost::is_iequal()));

				if (It == httpdata_split_iterator())
				{
					break;
				}

				typedef std::vector<boost::iterator_range<response::iterator> > find_vector_type;
				find_vector_type find_vector_type_;

				httpdata_split_iterator head_it = boost::make_split_iterator(*It, boost::first_finder("\r\n", boost::is_iequal()));
				for (; head_it != httpdata_split_iterator(); head_it ++)
				{
					find_vector_type_.push_back(*head_it);
				}

				if (find_vector_type_.size() <= 1)
				{
					break;
				}

				httpdata_split_iterator method_pos = boost::make_split_iterator(find_vector_type_[0], boost::first_finder(" ", boost::is_iequal()));
				if (method_pos == httpdata_split_iterator())
				{
					break;
				}

				http_vertion = boost::copy_range<std::string>(*method_pos);

				method_pos ++;
				if (method_pos == httpdata_split_iterator())
				{
					break;
				}
				http_status_ = boost::copy_range<std::string>(*method_pos);

				method_pos ++;
				if (method_pos == httpdata_split_iterator())
				{
					break;
				}
				http_phrase = boost::copy_range<std::string>(*method_pos);

				find_vector_type::iterator pos_ = find_vector_type_.begin();
				advance(pos_, 1);

				for (;pos_ != find_vector_type_.end(); pos_ ++)
				{
					do 
					{
						httpdata_split_iterator key_value_pos = boost::make_split_iterator(*pos_, boost::first_finder(": ", boost::is_iequal()));
						if (key_value_pos == httpdata_split_iterator())
						{
							break;
						}

						std::string strkey = boost::copy_range<std::string>(*key_value_pos);

						key_value_pos ++;

						if (key_value_pos == httpdata_split_iterator())
						{
							break;
						}

						std::string strvalue = boost::copy_range<std::string>(*key_value_pos);

						http_head_dic_.insert(std::make_pair(strkey, strvalue));
					} while (false);
				}
			} while (false);

			return true;
		}
	private:
		response	&http_raw_data_;
		http_headdic http_head_dic_;
		std::string  http_vertion;
		std::string  http_status_;
		std::string  http_phrase;
	};
}

#endif

//string strdata = "HTTP/1.1 200 OK\r\nContent-Type: text/octet\r\nContent-Length: 25\r\n\r\naaaaaaaaaaaaaaa";
//
//xzh::http_response<string> l_http_response(strdata);
//
//cout << l_http_response.getvertion() << endl;
//cout << l_http_response.getstatus() << endl;
//cout << l_http_response.getphrase() << endl;
//
//string strbody;
//cout << l_http_response.getbody(strbody) << endl;
//cout << strbody.c_str() << endl;

//HTTP/1.1
//200
//OK
//1
//aaaaaaaaaaaaaaa