#ifndef HTTP_REQUEST_HPP
#define HTTP_REQUEST_HPP
#include <boost/algorithm/string.hpp>
#include <map>
#include <string>
#include <vector>

namespace xzh
{
	template <class request>
	class http_request
	{
	public:
		typedef std::map<std::string, std::string> http_headdic;
		typedef boost::split_iterator<typename request::iterator> httpdata_split_iterator;
		enum parse_status
		{
			body_tag_notfound = 0,
			body_tag_found,
			header_newline_error,
			method_url_error,
			header_kv_error,
			header_kv_ok,
		};
	public:
		http_request(request &http_raw_data)
			:http_raw_data_(http_raw_data)
		{
			//parse();
		}
	public:
		std::string gethead(const std::string strkey)
		{
			return http_head_dic_[strkey];
		}

		std::string getmethod()
		{
			return http_method_;
		}

		std::string geturl()
		{
			return http_url_;
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

				copy(boost::begin(*It), http_raw_data_.end(), inserter(body_, body_.end()));
				//body_ = boost::copy_range<Body>(boost::iterator_range<request::iterator>(boost::begin(*It), boost::end(http_raw_data_.end())));
			} while (false);

			return !body_.empty();
		}

		size_t get_body_size()
		{
			size_t isize = 0;

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

				isize = distance(boost::begin(*It), http_raw_data_.end());
				//body_ = boost::copy_range<Body>(boost::iterator_range<request::iterator>(boost::begin(*It), boost::end(http_raw_data_.end())));
			} while (false);

			return isize;
		}

		int parse()
		{
			int iretvalue = body_tag_notfound;

			do 
			{
				httpdata_split_iterator It = boost::make_split_iterator(http_raw_data_, boost::first_finder("\r\n\r\n", boost::is_iequal()));
				httpdata_split_iterator ItBody = It;
				advance(ItBody, 1);

				if (ItBody == httpdata_split_iterator())
				{
					//not find \r\n\r\n
					iretvalue = body_tag_notfound;
					break;
				}

				iretvalue = body_tag_found;

				typedef std::vector<boost::iterator_range<request::iterator> > find_vector_type;
				find_vector_type find_vector_type_;

				httpdata_split_iterator head_it = boost::make_split_iterator(*It, boost::first_finder("\r\n", boost::is_iequal()));
				for (; head_it != httpdata_split_iterator(); head_it ++)
				{
					find_vector_type_.push_back(*head_it);
				}

				if (find_vector_type_.size() <= 1)
				{
					iretvalue = header_newline_error;
					break;
				}

				//get method & url
				httpdata_split_iterator method_pos = boost::make_split_iterator(find_vector_type_[0], boost::first_finder(" ", boost::is_iequal()));
				if (method_pos == httpdata_split_iterator())
				{
					iretvalue = method_url_error;
					break;
				}

				http_method_ = boost::copy_range<std::string>(*method_pos);

				method_pos ++;

				if (method_pos == httpdata_split_iterator())
				{
					iretvalue = method_url_error;
					break;
				}

				http_url_ = boost::copy_range<std::string>(*method_pos);

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


					if (http_head_dic_.empty())
					{
						iretvalue = header_kv_error;
						break;
					}

					iretvalue = header_kv_ok;

				}
			} while (false);

			return iretvalue;
		}

	private:
		request	&http_raw_data_;
		http_headdic http_head_dic_;
		std::string  http_method_;
		std::string  http_url_;
	};
}

#endif

/*
//POST /asfas
//Host: mail.xxx.com
//Connection: keep-alive
//Content-Length: 20
//Accept: text/javascript
//Origin: http://mail.xxx.com
//User-Agent: xxxxxxxxxxxxxxx
//Content-type: application/x-www-form-urlencoded
//Referer: http://mail.xxxx.com/js6/main.jsp?sid=UCIcxikhjkkgJWhKJBhhUnUaaQuVEMhW&df=unknow
//Accept-Encoding: gzip,deflate
//Accept-Language: zh-CN,zh;q=0.8
//Cookie: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

//bafadsfadfdfdsfadfdfdsdsfadsfa
//

xzh::http_request<vector_test> http_new(vector_test_);

cout <<"Method>> " << http_new.getmethod() << endl;
cout <<"Url>> " << http_new.geturl() << endl;
cout <<"Host>> " << http_new.gethead("Host") << endl;
cout <<"Connection>> " << http_new.gethead("Connection") << endl;
cout <<"Content-Length>> " << http_new.gethead("Content-Length") << endl;
cout <<"Cookie>> " << http_new.gethead("Cookie") << endl;

string strbody;
http_new.getbody(strbody);
cout <<"Body>> " << strbody.c_str() << endl;

vector_test strbody_;
http_new.getbody(strbody_);

*/