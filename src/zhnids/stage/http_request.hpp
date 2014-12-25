#ifndef HTTP_REQUEST_HPP
#define HTTP_REQUEST_HPP
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/searching/knuth_morris_pratt.hpp>
#include <zhnids/stage/outdebug.hpp>
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
		typedef request request_data;
		typedef vector<unsigned char> substr_data;
		typedef boost::split_iterator<typename request_data::iterator> httpdata_split_iterator;
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
		http_request(request_data &http_raw_data)
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
				vector<unsigned char> vector_newlines;
				std::string str_newlines("\r\n\r\n");
				std::copy(str_newlines.begin(), str_newlines.end(), inserter(vector_newlines, vector_newlines.end()));
				typename request_data::iterator pos_find = boost::algorithm::knuth_morris_pratt_search(http_raw_data_.begin(), http_raw_data_.end(), vector_newlines.begin(), vector_newlines.end());

				if (pos_find == http_raw_data_.end())
				{
					break;
				}

				copy(pos_find + 4, http_raw_data_.end(), inserter(body_, body_.end()));

			} while (false);

			return !body_.empty();
		}

		size_t get_body_size()
		{
			size_t isize = 0;

			do 
			{
				vector<unsigned char> vector_newlines;
				std::string str_newlines("\r\n\r\n");
				std::copy(str_newlines.begin(), str_newlines.end(), inserter(vector_newlines, vector_newlines.end()));
				typename request_data::iterator pos_find = boost::algorithm::knuth_morris_pratt_search(http_raw_data_.begin(), http_raw_data_.end(), vector_newlines.begin(), vector_newlines.end());
				
				if (pos_find == http_raw_data_.end())
				{
					break;
				}

				isize = distance(pos_find, http_raw_data_.end());

			} while (false);

			return isize;
		}

		int parse()
		{
			int iretvalue = body_tag_notfound;

			do 
			{
				vector<unsigned char> vector_newlines;
				std::string str_newlines("\r\n\r\n");
				std::copy(str_newlines.begin(), str_newlines.end(), inserter(vector_newlines, vector_newlines.end()));
				request_data::iterator pos_find = boost::algorithm::knuth_morris_pratt_search(http_raw_data_.begin(), http_raw_data_.end(), vector_newlines.begin(), vector_newlines.end());

				if (pos_find == http_raw_data_.end())
				{
					//not find \r\n\r\n
					iretvalue = body_tag_notfound;
					break;
				}

				iretvalue = body_tag_found;

				substr_data substr_data_;
				substr_data_.push_back('\r');
				substr_data_.push_back('\n');

				typedef std::vector<std::pair<request_data::iterator, request_data::iterator> > find_vector_type;
				find_vector_type find_vector_type_;

				request_data::iterator sub_pos = http_raw_data_.begin();

				do
				{
					request_data::iterator pre_pos = sub_pos;
					sub_pos = boost::algorithm::knuth_morris_pratt_search(pre_pos, pos_find, substr_data_.begin(), substr_data_.end());

					if (sub_pos == pos_find)
					{
						break;
					}

					find_vector_type_.push_back(make_pair(pre_pos, sub_pos));

					advance(sub_pos, substr_data_.size());
				}
				while(true);

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
		request_data	&http_raw_data_;
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