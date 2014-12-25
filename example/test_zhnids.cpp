#include <iostream>
//#include <zhnids.hpp>
#include <vector>
#include <list>
#include <string>

#include <boost/locale.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/typeof/typeof.hpp>

#include <map>

using namespace std;

//#include <boost/timer.hpp>
//
//using namespace std;
//
//typedef list<unsigned char> vector_data;
//
//vector_data vector_data_;
//
//
//bool tcp_rehandler(xzh::tcp_packet_node_ptr l_tcp_queue_node)
//{
//	
//
//	if (l_tcp_queue_node)
//	{
//		//cout << l_tcp_queue_node->gets_ip() << endl;
//		boost::timer timer_;
//		cout << "start..." << endl;
//		std::copy(l_tcp_queue_node->get_tcp_packet_data().begin(), l_tcp_queue_node->get_tcp_packet_data().end(), vector_data_.end());
//		cout << "endl..." <<timer_.elapsed()<<endl;
//	}
//	
//	return true;
//}
//
//bool udp_rehandler(xzh::udp_packet_node_ptr l_udp_packet)
//{
//	if (l_udp_packet)
//	{
//		cout << "udp ..." << l_udp_packet->getdatalen() << endl;
//	}
//	
//	return true;
//}

bool url_decode(const std::string& in, std::string& out)
{
	out.clear();
	out.reserve(in.size());
	for (std::size_t i = 0; i < in.size(); ++i)
	{
		if (in[i] == '%')
		{
			if (i + 3 <= in.size())
			{
				int value = 0;
				std::istringstream is(in.substr(i + 1, 2));
				if (is >> std::hex >> value)
				{
					out += static_cast<char>(value);
					i += 2;
				}
				else
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
		else if (in[i] == '+')
		{
			out += ' ';
		}
		else
		{
			out += in[i];
		}
	}
	return true;
}

void main()
{
	/*xzh::tcp_repacket l_tcp_repacket;
	l_tcp_repacket.add_repacket_handler("tcp_repacket", tcp_rehandler);

	xzh::udppacket l_udp_packet;
	l_udp_packet.add_repacket_handler("udp_re",  udp_rehandler);

	xzh::tcppacket l_tcp_packet;
	l_tcp_packet.add_tcp_data_handler("tcp_re", boost::bind(&xzh::tcp_repacket::repacket_handler, &l_tcp_repacket, _1));

	xzh::ippacket l_ip_packet;
	l_ip_packet.add_tcp_handler("tcp", boost::bind(&xzh::tcppacket::tcp_handler, &l_tcp_packet, _1, _2, _3));
	l_ip_packet.add_udp_handler("udp", boost::bind(&xzh::udppacket::udp_handler, &l_udp_packet, _1, _2, _3));

	xzh::ipfragment l_ipfragment;
	l_ipfragment.add_ippacket_handler("ip_packet", boost::bind(&xzh::ippacket::ippacket_handler, &l_ip_packet, _1, _2, _3));
	
	xzh::xzhnids l_test_nids;
	l_test_nids.add_ipfrag_handler("ip", boost::bind(&xzh::ipfragment::ipfrag_handler, &l_ipfragment, _1, _2, _3));
	l_test_nids.start("tcp port 80", 100, 10);*/
	std::string strurl = "http://set3.mail.qq.com/cgi-bin/ftnCreatefile?uin=&ef=js&resp_charset=UTF8&s=ftnCreate&sid=dRN5EJ39tPliBxpO&dirid=&path=C%3A%5CUsers%5CAdministrator%5CDesktop%5CTCP-IP%E6%8A%80%E6%9C%AF%E5%A4%A7%E5%85%A8%5C037.PDF&size=446546&md5=4dd15b76d4f3b442de1782da0cefe981&sha=65b33bfcc271ccdd15663183187ea2e152d2cbec&sha3=&appid=2&loc=ftnCreatefile,ftnCreatefile,ftnCreate,attach2";

	std::string strdurl;
	url_decode(strurl, strdurl);

	std::string stre = boost::locale::conv::from_utf(strdurl, "GBK");

	typedef map<string, string> string_map;
	string_map map_;

	vector<boost::iterator_range<string::iterator> > l;
	boost::algorithm::split(l, stre, boost::algorithm::is_any_of("&"));

	for (BOOST_AUTO(pos, l.begin()); pos != l.end(); pos++)
	{
		vector<boost::iterator_range<string::iterator> > l_k;
		boost::algorithm::split(l_k, *pos, boost::algorithm::is_any_of("="));
		for (BOOST_AUTO(pos_k, l_k.begin()); pos_k != l_k.end(); advance(pos_k, 2))
		{
			string strk = boost::copy_range<std::string>(*pos_k);
			string strv = boost::copy_range<std::string>(*(pos_k + 1));
			map_[strk] = strv;
		}
	}

	getchar();
}