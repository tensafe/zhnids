# zhnids project #

## desp ##
this project is developing...

## dev depend ##
1. c++
2. boost
3. stl
4. pcap

## build ##
from now, use on windows....

## how to use ##
```
#include <iostream>
#include <zhnids.hpp>

using namespace std;

bool tcp_rehandler(xzh::tcp_packet_node_ptr l_tcp_queue_node)
{
	if (l_tcp_queue_node)
	{
		cout << l_tcp_queue_node->gets_ip() << endl;
		cout << l_tcp_queue_node->getdatalen() << endl;
	}
	
	return true;
}

bool udp_rehandler(xzh::udp_packet_node_ptr l_udp_packet)
{
	if (l_udp_packet)
	{
		cout << "udp ..." << l_udp_packet->getdatalen() << endl;
	}
	
	return true;
}

void main()
{
	xzh::tcp_repacket l_tcp_repacket;
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
	l_test_nids.start("");

	getchar();
}
```