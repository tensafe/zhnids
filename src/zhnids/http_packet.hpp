#ifndef HTTP_PACKET_HPP
#define HTTP_PACKET_HPP

#include <vector>
#include <string>
#include <boost/shared_ptr.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/logic/tribool.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/lexical_cast.hpp>
#include <zhnids/stage/map_ptr_manager.hpp>
#include <zhnids/stage/pcap_hub.hpp>

#include <boost/asio/yield.hpp>
using namespace std;

namespace xzh
{
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


	class http_parse : public boost::asio::coroutine
	{
	public:
		virtual ~http_parse()
		{

		}
	public:
		bool is_char(int c)
		{
			return c >= 0 && c <= 127;
		}

		bool is_ctl(int c)
		{
			return (c >= 0 && c <= 31) || (c == 127);
		}

		bool is_tspecial(int c)
		{
			switch (c)
			{
			case '(': case ')': case '<': case '>': case '@':
			case ',': case ';': case ':': case '\\': case '"':
			case '/': case '[': case ']': case '?': case '=':
			case '{': case '}': case ' ': case '\t':
				return true;
			default:
				return false;
			}
		}

		bool is_digit(int c)
		{
			return c >= '0' && c <= '9';
		}

		static bool tolower_compare(char a, char b)
		{
			return std::tolower(a) == std::tolower(b);
		}

		bool headers_equal(const std::string& a, const std::string& b)
		{
			if (a.length() != b.length())
				return false;

			return std::equal(a.begin(), a.end(), b.begin(),
				&http_parse::tolower_compare);
		}
	};

	class http_response_parse : public http_parse
	{
	public:
		template <typename InputIterator>
		boost::tuple<boost::tribool, InputIterator> parse(http_response& response_, InputIterator _begin, InputIterator _end)
		{
			while(_begin != _end)
			{
				boost::tribool result = consume(response_, *_begin ++);
				if (result || !result)
				{
					return boost::make_tuple(result, _begin);
				}
			}

			boost::tribool result = boost::indeterminate;
			return boost::make_tuple(result, _begin);
		}
	public:
		boost::tribool consume(http_response &res, char c)
		{
			reenter(this)
			{
				while(true)
				{

					res.status_code = 0;
					res.status.clear();
					res.http_version_major = 0;
					res.http_version_minor = 0;
					res.content.clear();
					res.headers.clear();

					content_length_ = 0;
					content_length_name_ = "Content-Length";
					ishave_content_length = false;
					transfer_encoding = "Transfer-Encoding";

					if (c != 'H') return false;
					yield return boost::indeterminate;
					if (c != 'T') return false;
					yield return boost::indeterminate;
					if (c != 'T') return false;
					yield return boost::indeterminate;
					if (c != 'P') return false;
					yield return boost::indeterminate;

					// Slash.
					if (c != '/') return false;
					yield return boost::indeterminate;

					// Major version number.
					if (!is_digit(c)) return false;
					while (is_digit(c))
					{
						res.http_version_major = res.http_version_major * 10 + c - '0';
						yield return boost::indeterminate;
					}

					// Dot.
					if (c != '.') return false;
					yield return boost::indeterminate;

					// Minor version number.
					if (!is_digit(c)) return false;
					while (is_digit(c))
					{
						res.http_version_minor = res.http_version_minor * 10 + c - '0';
						yield return boost::indeterminate;
					}

					if (c != ' ') return false;
					yield return boost::indeterminate;

					if (!is_digit(c)) return false;
					while (is_digit(c))
					{
						res.status_code = res.status_code * 10 + c - '0';
						yield return boost::indeterminate;
					}

					if (c != ' ') return false;
					yield return boost::indeterminate;

					while (is_char(c) && !is_ctl(c) && !is_tspecial(c) && c != '\r')
					{
						res.status.push_back(c);
						yield return boost::indeterminate;
					}
					if (res.status.empty())
						return false;

					// CRLF.
					if (c != '\r') return false;
					yield return boost::indeterminate;
					if (c != '\n') return false;
					yield return boost::indeterminate;

					// Headers.
					while ((is_char(c) && !is_ctl(c) && !is_tspecial(c) && c != '\r')
						|| (c == ' ' || c == '\t'))
					{
						if (c == ' ' || c == '\t')
						{
							// Leading whitespace. Must be continuation of previous header's value.
							if (res.headers.empty()) return false;
							while (c == ' ' || c == '\t')
								yield return boost::indeterminate;
						}
						else
						{
							// Start the next header.
							res.headers.push_back(header());

							// Header name.
							while (is_char(c) && !is_ctl(c) && !is_tspecial(c) && c != ':')
							{
								res.headers.back().name.push_back(c);
								yield return boost::indeterminate;
							}

							// Colon and space separates the header name from the header value.
							if (c != ':') return false;
							yield return boost::indeterminate;
							if (c != ' ') return false;
							yield return boost::indeterminate;
						}

						// Header value.
						while (is_char(c) && !is_ctl(c) && c != '\r')
						{
							res.headers.back().value.push_back(c);
							yield return boost::indeterminate;
						}

						// CRLF.
						if (c != '\r') return false;
						yield return boost::indeterminate;
						if (c != '\n') return false;
						yield return boost::indeterminate;
					}

					// CRLF.
					if (c != '\r') return false;
					yield return boost::indeterminate;
					if (c != '\n') return false;

					for (std::size_t i = 0; i < res.headers.size(); ++i)
					{
						if (headers_equal(res.headers[i].name, content_length_name_))
						{
							ishave_content_length = true;

							try
							{
								content_length_ = boost::lexical_cast<std::size_t>(res.headers[i].value);
							}
							catch (boost::bad_lexical_cast&)
							{
								return false;
							}
							break;
						}

						if (headers_equal(res.headers[i].name, transfer_encoding))
						{
							ishave_content_length = false;
							break;
						}
					}

					// Content.
					if (ishave_content_length)
					{
						while (res.content.size() < content_length_)
						{
							yield return boost::indeterminate;
							res.content.push_back(c);
						}
					}
					else
					{
						yield return boost::indeterminate;
						while(true)
						{
							chunk_len.clear();
							while (is_char(c) && !is_ctl(c) && c != '\r')
							{
								chunk_len.push_back(c);
								yield return boost::indeterminate;
							}

							try
							{
								std::string strhex_value;
								boost::algorithm::unhex(chunk_len.begin(), chunk_len.end(), inserter(strhex_value, strhex_value.end()));
								content_length_ = 0;
								memcpy(&content_length_, strhex_value.c_str(), min(strhex_value.size(), sizeof(int)));
							}
							catch (...)
							{
								content_length_ = 0;
							}

							if(content_length_ == 0)
							{
								break;
							}

							content_length_ += res.content.size();


							if (c != '\r') return false;
							yield return boost::indeterminate;
							if (c != '\n') return false;
							yield return boost::indeterminate;

							while (res.content.size() < content_length_)
							{
								res.content.push_back(c);
								yield return boost::indeterminate;
							}

							if (c != '\r') return false;
							yield return boost::indeterminate;
							if (c != '\n') return false;
							yield return boost::indeterminate;
						}
					}

					yield return true;
				}
			}
			return true;
		}
	private:
		size_t content_length_;
		bool ishave_content_length;
		std::string content_length_name_;// = "Content-Length";
		std::string transfer_encoding; // Transfer-Encoding
		std::string chunk_len;
	};

	class http_request_parse : public http_parse
	{
	public:
		template <typename InputIterator>
		boost::tuple<boost::tribool, InputIterator> parse(http_request& request_, InputIterator _begin, InputIterator _end)
		{
			while(_begin != _end)
			{
				boost::tribool result = consume(request_, *_begin ++);
				if (result || !result)
				{
					return boost::make_tuple(result, _begin);
				}
			}

			boost::tribool result = boost::indeterminate;
			return boost::make_tuple(result, _begin);
		}
	public:
		boost::tribool consume(http_request &req, char c)
		{
			reenter (this)
			{
				while(true)
				{
					req.method.clear();
					req.uri.clear();
					req.http_version_major = 0;
					req.http_version_minor = 0;
					req.headers.clear();
					req.content.clear();
					content_length_ = 0;
					content_length_name_ = "Content-Length";

					// Request method.
					while (is_char(c) && !is_ctl(c) && !is_tspecial(c) && c != ' ')
					{
						req.method.push_back(c);
						yield return boost::indeterminate;
					}
					if (req.method.empty())
						return false;

					// Space.
					if (c != ' ') return false;
					yield return boost::indeterminate;

					// URI.
					while (!is_ctl(c) && c != ' ')
					{
						req.uri.push_back(c);
						yield return boost::indeterminate;
					}
					if (req.uri.empty()) return false;

					// Space.
					if (c != ' ') return false;
					yield return boost::indeterminate;

					// HTTP protocol identifier.
					if (c != 'H') return false;
					yield return boost::indeterminate;
					if (c != 'T') return false;
					yield return boost::indeterminate;
					if (c != 'T') return false;
					yield return boost::indeterminate;
					if (c != 'P') return false;
					yield return boost::indeterminate;

					// Slash.
					if (c != '/') return false;
					yield return boost::indeterminate;

					// Major version number.
					if (!is_digit(c)) return false;
					while (is_digit(c))
					{
						req.http_version_major = req.http_version_major * 10 + c - '0';
						yield return boost::indeterminate;
					}

					// Dot.
					if (c != '.') return false;
					yield return boost::indeterminate;

					// Minor version number.
					if (!is_digit(c)) return false;
					while (is_digit(c))
					{
						req.http_version_minor = req.http_version_minor * 10 + c - '0';
						yield return boost::indeterminate;
					}

					// CRLF.
					if (c != '\r') return false;
					yield return boost::indeterminate;
					if (c != '\n') return false;
					yield return boost::indeterminate;

					// Headers.
					while ((is_char(c) && !is_ctl(c) && !is_tspecial(c) && c != '\r')
						|| (c == ' ' || c == '\t'))
					{
						if (c == ' ' || c == '\t')
						{
							// Leading whitespace. Must be continuation of previous header's value.
							if (req.headers.empty()) return false;
							while (c == ' ' || c == '\t')
								yield return boost::indeterminate;
						}
						else
						{
							// Start the next header.
							req.headers.push_back(header());

							// Header name.
							while (is_char(c) && !is_ctl(c) && !is_tspecial(c) && c != ':')
							{
								req.headers.back().name.push_back(c);
								yield return boost::indeterminate;
							}

							// Colon and space separates the header name from the header value.
							if (c != ':') return false;
							yield return boost::indeterminate;
							if (c != ' ') return false;
							yield return boost::indeterminate;
						}

						// Header value.
						while (is_char(c) && !is_ctl(c) && c != '\r')
						{
							req.headers.back().value.push_back(c);
							yield return boost::indeterminate;
						}

						// CRLF.
						if (c != '\r') return false;
						yield return boost::indeterminate;
						if (c != '\n') return false;
						yield return boost::indeterminate;
					}

					// CRLF.
					if (c != '\r') return false;
					yield return boost::indeterminate;
					if (c != '\n') return false;

					// Check for optional Content-Length header.
					for (std::size_t i = 0; i < req.headers.size(); ++i)
					{
						if (headers_equal(req.headers[i].name, content_length_name_))
						{
							try
							{
								content_length_ =
									boost::lexical_cast<std::size_t>(req.headers[i].value);
							}
							catch (boost::bad_lexical_cast&)
							{
								return false;
							}
						}
					}

					// Content.
					while (req.content.size() < content_length_)
					{
						yield return boost::indeterminate;
						req.content.push_back(c);
					}

					yield return true;
				}

			}

			return true;
		}
	private:
		int content_length_;
		std::string content_length_name_;// = "Content-Length";
	};

	class session
	{
	public:
		virtual ~session() {};
	public:
		virtual boost::tribool switch_packet(xzh::tcp_packet_node_ptr l_tcp_packet_node_ptr) = 0;
	};

	typedef pcap_hub_impl<string, bool (tcp_packet_node_ptr, http_packet_data_ptr)> http_packet_data_hub;

	class http_session : public session,
		public boost::asio::coroutine
	{
	public:
		explicit http_session(http_packet_data_hub & _http_packet_data_hub_)
			:http_packet_data_hub_(_http_packet_data_hub_)
		{

		}
	public:
		boost::tribool switch_packet(xzh::tcp_packet_node_ptr l_tcp_packet_node_ptr)
		{
			reenter(this)
			{
				if (l_tcp_packet_node_ptr->getstate() == tcp_connect)
				{
					yield return boost::indeterminate;
				}

				while(l_tcp_packet_node_ptr->getstate() == tcp_data)
				{
					if (l_tcp_packet_node_ptr->isclient())
					{
						http_packet_data_ptr_ = http_packet_data_ptr(new http_packet_data());
						http_packet_data_ptr_->set_http_data_type() = http_packet_data::http_request_type;

						while(true)
						{
							boost::tie(valid_request_, boost::tuples::ignore) = http_request_parse_.parse(http_packet_data_ptr_->set_http_request(), l_tcp_packet_node_ptr->get_tcp_packet_data().begin(), l_tcp_packet_node_ptr->get_tcp_packet_data().end());

							if (!valid_request_)
							{
								return false;
							}

							if (boost::indeterminate(valid_request_))
							{
								yield return valid_request_;
							}

							if (valid_request_)
							{
								break;
							}
						}
					}

					notify_handler(l_tcp_packet_node_ptr, http_packet_data_ptr_);

					yield return true;

					if (!l_tcp_packet_node_ptr->isclient())
					{
						http_packet_data_ptr_->set_http_data_type() = http_packet_data::http_response_type;

						while(true)
						{
							boost::tie(valid_request_, boost::tuples::ignore) = http_response_parse_.parse(http_packet_data_ptr_->set_http_response(), l_tcp_packet_node_ptr->get_tcp_packet_data().begin(), l_tcp_packet_node_ptr->get_tcp_packet_data().end());

							if (!valid_request_)
							{
								return false;
							}

							if (boost::indeterminate(valid_request_))
							{
								yield return valid_request_;
							}

							if (valid_request_)
							{
								break;
							}
						}
					}

					notify_handler(l_tcp_packet_node_ptr, http_packet_data_ptr_);

					yield return true;
				}

				if ((l_tcp_packet_node_ptr->getstate() == tcp_end)
					|| (l_tcp_packet_node_ptr->getstate() == tcp_ending))
				{
					yield return false;
				}
			}
			return true;
		}
	private:
		bool notify_handler(tcp_packet_node_ptr l_tcp_packet_node_ptr, http_packet_data_ptr http_packet_data_ptr_)
		{
			bool bretvalue = false;

			for (size_t index_ = 0; index_ < http_packet_data_hub_.size(); index_ ++)
			{
				http_packet_data_hub::return_type_ptr temp_ = http_packet_data_hub_[index_];
				if (!temp_)
				{
					continue;
				}

				if((*temp_)(l_tcp_packet_node_ptr, http_packet_data_ptr_))
				{
				}
				else
				{
				}
			}

			return bretvalue;
		}

	private:
		http_packet_data_ptr http_packet_data_ptr_;
		http_request_parse http_request_parse_;
		http_response_parse http_response_parse_;
		boost::tribool valid_request_;
		http_packet_data_hub &http_packet_data_hub_;
	};

	typedef map_ptr_manager<unsigned long, http_session> http_map_session_ptr;


	class http_packet
	{
	public:
		bool http_handler(xzh::tcp_packet_node_ptr l_tcp_packet_node_ptr)
		{
			unsigned long ihash = l_tcp_packet_node_ptr->get_tuple_hash();

			http_map_session_ptr::shared_impl_ptr l_session_ptr = http_map_session_ptr_.get(l_tcp_packet_node_ptr->get_tuple_hash());

			if (!l_session_ptr)
			{
				l_session_ptr = http_map_session_ptr::shared_impl_ptr(new http_session(http_packet_data_hub_));
				http_map_session_ptr_.add(ihash, l_session_ptr);
			}

			boost::tribool bstatus;

			bstatus = l_session_ptr->switch_packet(l_tcp_packet_node_ptr);

			if (!bstatus)
			{
				http_map_session_ptr_.del(l_tcp_packet_node_ptr->get_tuple_hash());
			}

			return true;
		}

	public:
		template <typename TFun>
		bool add_http_packet_handler(string key_, TFun callfun_)
		{
			return http_packet_data_hub_.add_handler(key_, callfun_);
		}

		void del_http_packet_handler(string key_)
		{
			http_packet_data_hub_.del_handler(key_);
		}
	private:
		http_map_session_ptr http_map_session_ptr_;
		http_packet_data_hub http_packet_data_hub_;
	};


};

#include <boost/asio/unyield.hpp>

#endif