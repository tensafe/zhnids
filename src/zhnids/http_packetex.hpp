#ifndef http_packetex_h__
#define http_packetex_h__
//#include <zhnids.hpp>
#include "http_parser.h"
#include <zhnids/stage/map_ptr_manager.hpp>
#include <zhnids/stage/pcap_hub.hpp>
#include <zhnids/stage/outdebug.hpp>

namespace xzh
{
	typedef pcap_hub_impl<string, bool (tcp_packet_node_ptr, http_packet_data_ptr, bool &)> http_packet_data_hub;
	typedef pcap_hub_impl<string, bool (tcp_packet_node_ptr, http_packet_data_ptr, bool &)> http_packet_filter_hub_ex;
	typedef pcap_hub_impl<string, bool (tcp_packet_node_ptr, bool &)> http_packet_filter_hub;

	class http_session_ex 
	{
	public:
		explicit http_session_ex(http_packet_data_hub & _http_packet_data_hub_, 
			http_packet_filter_hub & _http_packet_filter_hub_, 
			http_packet_filter_hub_ex & _http_packet_filter_hub_ex_)
			:http_packet_data_hub_(_http_packet_data_hub_),
			http_packet_filter_hub_ex_(_http_packet_filter_hub_ex_),
			http_packet_filter_hub_(_http_packet_filter_hub_)

		{
			http_parser_settings_init(&request_settings_);
			request_settings_.on_message_begin = http_session_ex::on_message_begin_cb;
			request_settings_.on_message_complete = http_session_ex::on_message_complete_cb;
			request_settings_.on_headers_complete = http_session_ex::on_headers_complete_cb;
			request_settings_.on_header_field = http_session_ex::on_header_field_cb;
			request_settings_.on_header_value = http_session_ex::on_header_value_cb;
			request_settings_.on_body = http_session_ex::on_body_cb;
			request_settings_.on_url = http_session_ex::on_request_uri_cb;
			request_settings_.on_status = http_session_ex::on_status_cb;

			http_parser_settings_init(&response_settings_);
			response_settings_.on_message_begin = http_session_ex::on_message_begin_cb;
			response_settings_.on_message_complete = http_session_ex::on_message_complete_cb;
			response_settings_.on_headers_complete = http_session_ex::on_headers_complete_cb;
			response_settings_.on_header_field = http_session_ex::on_header_field_cb;
			response_settings_.on_header_value = http_session_ex::on_header_value_cb;
			response_settings_.on_body = http_session_ex::on_body_cb;
			response_settings_.on_url = http_session_ex::on_request_uri_cb;
			response_settings_.on_status = http_session_ex::on_status_cb;

			http_parser_init(&parser_request, HTTP_REQUEST);
			parser_request.data = (void*)this;


			http_parser_init(&parser_response, HTTP_RESPONSE);
			parser_response.data = (void*)this;
		}
	public:
		bool session_handler(xzh::tcp_packet_node_ptr l_tcp_packet_node_ptr)
		{
			bool bretvalue = false;
			bool isclient = l_tcp_packet_node_ptr->isclient();
			tcp_packet_node::tcp_packet_data l_tcp_packet_data = l_tcp_packet_node_ptr->get_tcp_packet_data();
			unsigned int idata_len = l_tcp_packet_node_ptr->getdatalen();

			tcp_packet_node_ptr_ = l_tcp_packet_node_ptr;

			if (l_tcp_packet_node_ptr->getstate() == tcp_end)
			{
				if (http_packet_data_ptr_)
				{
					if (http_packet_data_ptr_->get_http_data_type() == http_packet_data::http_request_type)
					{
						parser_request.state = 61;
						http_parser_execute(&parser_request, &request_settings_, NULL, 0);
					}
					else if (http_packet_data_ptr_->get_http_data_type() == http_packet_data::http_response_type)
					{
						parser_response.state = 61;
						http_parser_execute(&parser_response, &response_settings_, NULL, 0);
					}
				}
				else
				{

				}
				return true;
			}

			do 
			{
				size_t parser_ret = 0;
				int http_parser_err = 0;

				if (isclient)
				{
					parser_ret = http_parser_execute(&parser_request, &request_settings_, (const char*)&l_tcp_packet_data[0], idata_len);
					http_parser_err = HTTP_PARSER_ERRNO(&parser_request);
				}
				else
				{
					parser_ret = http_parser_execute(&parser_response, &response_settings_, (const char*)&l_tcp_packet_data[0], idata_len);
					http_parser_err = HTTP_PARSER_ERRNO(&parser_request);
				}

				if (http_parser_err != HPE_OK)
				{
					//debughelp::safe_debugstr(250, "http_parser error:%s",http_errno_description((http_errno)http_parser_err));
					bretvalue = false;
				}
				else
				{
					bretvalue = true;
				}

				bretvalue = true;

			} while (false);

			return bretvalue;
		}
	public:
		int  in_on_message_begin_cb(http_parser *parser)
		{
			int iretvalue = -1;

			if (parser->type == HTTP_REQUEST)
			{
				http_packet_data_ptr_ = http_packet_data_ptr(new http_packet_data());
				if(filter_handler(tcp_packet_node_ptr_))
				{
					iretvalue = 0;
				}
				else
				{
					
				}
			}
			else
			{
				iretvalue = 0;
			}

			return iretvalue;
		}

		int  in_on_message_complete_cb(http_parser *parser)
		{
			int iretvalue = -1;

			do 
			{
				if (!http_packet_data_ptr_)
				{
					break;
				}

				//
				if(!notify_handler(tcp_packet_node_ptr_, http_packet_data_ptr_))
				{
					iretvalue = -1;
					break;
				}

				if (parser->type == HTTP_RESPONSE)
				{
					http_packet_data_ptr_.reset();
				}

				iretvalue = 0;

			} while (false);

			return iretvalue;
		}

		int  in_on_headers_complete_cb(http_parser *parser)
		{
			int iretvalue = -1;

			do 
			{
				if (!http_packet_data_ptr_)
				{
					break;
				}

				if (parser->type == HTTP_REQUEST)
				{
					http_packet_data_ptr_->set_http_data_type() = http_packet_data::http_request_type;
					http_packet_data_ptr_->set_http_request().method = http_method_str((http_method)parser->method);
					http_packet_data_ptr_->set_http_request().http_version_major = parser->http_major;
					http_packet_data_ptr_->set_http_request().http_version_minor = parser->http_minor;
					
					iretvalue = !http_should_keep_alive(parser);

					if(!filter_handler_ex(tcp_packet_node_ptr_, http_packet_data_ptr_))
					{
						iretvalue = -1;
						break;
					}

					
				}
				else if (parser->type == HTTP_RESPONSE)
				{
					http_packet_data_ptr_->set_http_data_type() = http_packet_data::http_response_type;
					http_packet_data_ptr_->set_http_response().status_code = parser->status_code;
					http_packet_data_ptr_->set_http_response().http_version_major = parser->http_major;
					http_packet_data_ptr_->set_http_response().http_version_minor = parser->http_minor;
					
					iretvalue = !http_should_keep_alive(parser);

					if(!filter_handler_ex(tcp_packet_node_ptr_, http_packet_data_ptr_))
					{
						iretvalue = -1;
						break;
					}
				}
				else if (parser->type == HTTP_BOTH)
				{
					break;
				}
				else
				{
					break;
				}
			} while (false);

			return iretvalue;
		}

		int  in_on_body_cb (http_parser *parser, const char *p, size_t len)
		{
			int iretvalue = -1;

			do 
			{
				if (!http_packet_data_ptr_)
				{
					break;
				}

				if (parser->type == HTTP_REQUEST)
				{
					http_packet_data_ptr_->set_http_request().content.reserve(http_packet_data_ptr_->set_http_request().content.size() + len);
					http_packet_data_ptr_->set_http_request().content.append(p, len);

					if(!filter_handler_ex(tcp_packet_node_ptr_, http_packet_data_ptr_))
					{
						iretvalue = -1;
						break;
					}

					iretvalue = 0;
				}
				else if (parser->type == HTTP_RESPONSE)
				{
					http_packet_data_ptr_->set_http_response().content.reserve(http_packet_data_ptr_->set_http_request().content.size() + len);
					http_packet_data_ptr_->set_http_response().content.append(p, len);

					if(!filter_handler_ex(tcp_packet_node_ptr_, http_packet_data_ptr_))
					{
						iretvalue = -1;
						break;
					}

					iretvalue = 0;
				}
				else if (parser->type == HTTP_BOTH)
				{
					break;
				}
				else
				{
					break;
				}
			} while (false);

			return iretvalue;
		}

		int in_on_header_field_cb (http_parser *parser, const char *p, size_t len)
		{
			int iretvalue = -1;

			do 
			{
				if (!http_packet_data_ptr_)
				{
					break;
				}

				if (parser->type == HTTP_REQUEST)
				{
					http_packet_data_ptr_->set_http_request().headers.push_back(header());
					http_packet_data_ptr_->set_http_request().headers.back().name = string(p, len);
					iretvalue = 0;
				}
				else if (parser->type == HTTP_RESPONSE)
				{
					http_packet_data_ptr_->set_http_response().headers.push_back(header());
					http_packet_data_ptr_->set_http_response().headers.back().name = string(p, len);
					iretvalue = 0;
				}
				else if (parser->type == HTTP_BOTH)
				{
					break;
				}
				else
				{
					break;
				}
			} while (false);

			return 0;
		}

		int in_on_header_value_cb (http_parser *parser, const char *p, size_t len)
		{
			int iretvalue = -1;

			do 
			{
				if (!http_packet_data_ptr_)
				{
					break;
				}

				if (parser->type == HTTP_REQUEST)
				{
					http_packet_data_ptr_->set_http_request().headers.back().value = string(p, len);
					iretvalue = 0;
				}
				else if (parser->type == HTTP_RESPONSE)
				{
					http_packet_data_ptr_->set_http_response().headers.back().value = string(p, len);
					iretvalue = 0;
				}
				else if (parser->type == HTTP_BOTH)
				{
					break;
				}
				else
				{
					break;
				}
			} while (false);

			return iretvalue;
		}

		int in_on_request_uri_cb (http_parser *parser, const char *p, size_t len)
		{
			int iretvalue = -1;

			do 
			{
				if (!http_packet_data_ptr_)
				{
					break;
				}

				if (parser->type == HTTP_REQUEST)
				{
					http_packet_data_ptr_->set_http_request().uri = string(p, len);
					iretvalue = 0;
				}
				else if (parser->type == HTTP_RESPONSE)
				{
					iretvalue = 0;
				}
				else if (parser->type == HTTP_BOTH)
				{
					break;
				}
				else
				{
					break;
				}
			} while (false);

			return iretvalue;
		}

		int in_on_status_cb(http_parser *parser, const char *p, size_t len)
		{
			int iretvalue = -1;

			do 
			{
				if (!http_packet_data_ptr_)
				{
					break;
				}

				if (parser->type == HTTP_REQUEST)
				{
					iretvalue = 0;
				}
				else if (parser->type == HTTP_RESPONSE)
				{
					http_packet_data_ptr_->set_http_response().status = string(p, len);

					iretvalue = 0;
				}
				else if (parser->type == HTTP_BOTH)
				{
					break;
				}
				else
				{
					break;
				}
			} while (false);

			return iretvalue;
		}
	public:
		static int on_message_begin_cb (http_parser *parser)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_message_begin_cb(parser);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
		}

		static int on_message_complete_cb (http_parser *parser)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_message_complete_cb(parser);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
		}
		static int on_headers_complete_cb(http_parser *parser)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_headers_complete_cb(parser);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
		}
		static int on_body_cb(http_parser *parser, const char *p, size_t len)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_body_cb(parser, p, len);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
		}

		static int on_header_field_cb (http_parser *parser, const char *p, size_t len)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_header_field_cb(parser, p, len);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
		}

		static int on_header_value_cb (http_parser *parser, const char *p, size_t len)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_header_value_cb(parser, p, len);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
		}

		static int on_request_uri_cb (http_parser *parser, const char *p, size_t len)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_request_uri_cb(parser, p, len);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
		}
		static int on_status_cb(http_parser *parser, const char *p, size_t len)
		{
			int iret = -1;

			try
			{
				do 
				{
					if (parser == NULL)
					{
						break;
					}

					if (parser->data == NULL)
					{
						break;
					}

					http_session_ex* l_http_session_ex = (http_session_ex*)parser->data;
					iret = l_http_session_ex->in_on_status_cb(parser, p, len);

				} while (false);
			}
			catch(...)
			{

			}

			return iret;
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

				bool bisfilter = true;
				(*temp_)(l_tcp_packet_node_ptr, http_packet_data_ptr_, bisfilter);

				if(!bretvalue && bisfilter)
				{
					bretvalue = true;
				}
			}

			return bretvalue;
		}

		bool filter_handler_ex(tcp_packet_node_ptr l_tcp_packet_node_ptr, http_packet_data_ptr http_packet_data_ptr_)
		{
			bool bretvalue = false;

			if (http_packet_filter_hub_ex_.size() == 0)
			{
				return true;
			}

			for (size_t index_ = 0; index_ < http_packet_filter_hub_ex_.size(); index_ ++)
			{
				http_packet_filter_hub_ex::return_type_ptr temp_ = http_packet_filter_hub_ex_[index_];
				if (!temp_)
				{
					continue;
				}

				bool bisfilter = true;
				(*temp_)(l_tcp_packet_node_ptr, http_packet_data_ptr_, bisfilter);

				if (bisfilter)
				{
					bretvalue = true;
					break;
				}
			}

			return bretvalue;
		}

		bool filter_handler(tcp_packet_node_ptr l_tcp_packet_node_ptr)
		{
			bool bretvalue = false;

			if (http_packet_filter_hub_.size() == 0)
			{
				return true;
			}

			for (size_t index_ = 0; index_ < http_packet_filter_hub_.size(); index_ ++)
			{
				http_packet_filter_hub::return_type_ptr temp_ = http_packet_filter_hub_[index_];
				if (!temp_)
				{
					continue;
				}

				bool bisfilter = true;
				(*temp_)(l_tcp_packet_node_ptr, bisfilter);

				if (bisfilter)
				{
					bretvalue = true;
					//break;
				}
			}

			return bretvalue;
		}
	private:
		http_parser_settings request_settings_;
		http_parser parser_request;

		http_parser_settings response_settings_;
		http_parser parser_response;

		http_packet_data_ptr http_packet_data_ptr_;

		http_packet_data_hub http_packet_data_hub_;
		http_packet_filter_hub_ex http_packet_filter_hub_ex_;
		http_packet_filter_hub http_packet_filter_hub_;

		tcp_packet_node_ptr tcp_packet_node_ptr_;
	};

	typedef map_ptr_manager<unsigned int, http_session_ex> http_session_manager_ex;
	class http_packet_mn_ex
	{
	public:
		bool http_packet_mn_handler_ex(tcp_packet_node_ptr l_tcp_queue_node_ptr)
		{
			http_session_manager_ex::shared_impl_ptr l_http_sesson_ptr;
			bool bsession_handler_ret = false;
			unsigned int tuple_hash = 0;

			do 
			{
				if (!l_tcp_queue_node_ptr)
				{
					break;
				}

				if ((l_tcp_queue_node_ptr->getd_port() != 80) && (l_tcp_queue_node_ptr->getd_port() != 8080))
				{
					break;
				}

				tuple_hash = l_tcp_queue_node_ptr->get_tuple_hash();

				if (l_tcp_queue_node_ptr->getstate() == tcp_end)
				{
					l_http_sesson_ptr = http_session_manager_.get(tuple_hash);

					if (l_http_sesson_ptr)
					{
						bsession_handler_ret = l_http_sesson_ptr->session_handler(l_tcp_queue_node_ptr);
					}

					http_session_manager_.del(tuple_hash);
					break;
				}

				if (l_tcp_queue_node_ptr->getstate() == tcp_data)
				{
					l_http_sesson_ptr = http_session_manager_.get(tuple_hash);

					if (l_http_sesson_ptr)
					{
						bsession_handler_ret = l_http_sesson_ptr->session_handler(l_tcp_queue_node_ptr);
					}

					break;
				}

				if (l_tcp_queue_node_ptr->getstate() == tcp_connect)
				{
					do 
					{
						l_http_sesson_ptr = http_session_manager_ex::shared_impl_ptr(new http_session_ex(http_packet_data_hub_, http_packet_filter_hub_, http_packet_filter_hub_ex_));
					} while (false);

					if (!l_http_sesson_ptr)
					{
						break;
					}

					http_session_manager_.add(tuple_hash, l_http_sesson_ptr);
					bsession_handler_ret = true;
					break;
				}
			} while (false);

			if(l_http_sesson_ptr && !bsession_handler_ret && tuple_hash)
			{
				http_session_manager_.del(tuple_hash);
			}

			return true;
		}
	public:
		template <typename TFun>
		bool add_http_packet_handler(string key_, TFun callfun_)
		{
			return http_packet_data_hub_.add_handler(key_, callfun_);
		}

		template <typename TFun>
		bool add_http_filter_handler_ex(string key_, TFun filterfun_)
		{
			return http_packet_filter_hub_ex_.add_handler(key_, filterfun_);
		}

		template <typename TFun>
		bool add_http_filter_handler(string key_, TFun filterfun_)
		{
			return http_packet_filter_hub_.add_handler(key_, filterfun_);
		}
	private:
		http_session_manager_ex http_session_manager_;

		http_packet_data_hub http_packet_data_hub_;
		http_packet_filter_hub_ex http_packet_filter_hub_ex_;
		http_packet_filter_hub http_packet_filter_hub_;
	};
};

#endif // http_packetex_h__
