#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <string.h>
#include <string>
#include <iostream>
#include "PracticalSocket.h"      // For UDPSocket and SocketException
#include <cstdlib>

using namespace std;

string serv_address;
char* port_num;

const int TRANSFERMAX = 1800;


/*
 * workhorse function, we will be modifying this function
 */
void pcap_callback(u_char *userdata, const struct pcap_pkthdr *h, const u_char *p) {

	unsigned char* packet;			// ponter to packet binary
	unsigned char* l3_header;
	struct ip* ip_header;
	struct in_addr src_ip;
	struct in_addr dst_ip;
	struct timeval timestamp;


	PacketCnt *pcnt;
	SoRData *data;
	int data_size = sizeof(SoRData) + h->caplen;
	data = (SoRData *)malloc(data_size);
	memcpy(&(data->pcap_hdr), h, sizeof(struct pcap_pkthdr));
	memcpy(data->pcap_pkt, p, h->caplen);

//	timestamp = packet_cnt->pcap_hdr.ts;
	packet = (unsigned char *)malloc(data_size);
	memcpy(packet, data, data_size);

	l3_header = packet + sizeof(SoRSimHeader) + sizeof(struct ether_header); //IP header
	ip_header = (struct ip *)l3_header;
	src_ip = ip_header->ip_src;
	dst_ip = ip_header->ip_dst;


	cout << "caplen: " << data->pcap_hdr.caplen  << endl;
	cout << "src_ip: " << inet_ntoa(src_ip)  << endl;
	cout << "content: "<<  data->pcap_pkt << endl;


  unsigned short echoServPort = Socket::resolveService(port_num, "udp");


  try {
    UDPSocket *sock = new UDPSocket(52001);
	sock->getLocalAddress().copy(data->sourceIP,15);
	cout << sock->getLocalAddress() << endl;
	cout << sock->getLocalPort() << endl;
	data->sourcePort = sock->getLocalPort();


	cout << "src_ip sim: "<<  data->sourceIP << endl;
    // Send the string to the server
    sock->sendTo(data, data_size, serv_address, echoServPort);

    // Receive a response
    char echoBuffer[TRANSFERMAX + 1];       // Buffer for echoed string + \0
    int respStringLen;                  // Length of received response
    respStringLen = sock->recv(echoBuffer, TRANSFERMAX);
	/*
    if ((respStringLen = sock.recv(echoBuffer, TRANSFERMAX)) != echoStringLen) {
      cerr << "Unable to receive" << endl;
      exit(1);
    }
	*/

    echoBuffer[respStringLen] = '\0';             // Terminate the string!
    cout << "Received: " << echoBuffer << endl;   // Print the echoed arg

    // Destructor closes the socket

  } catch (SocketException &e) {
    cerr << e.what() << endl;
    exit(1);
  }

}


int main(int argc,char **argv)
{
	if(argc < 4 || argc > 4){
		cerr << "Usage: " << argv[0]
			<< "<Server> <Server Port> <Path to pcapfile>" << endl;
		exit(1);
	}

	serv_address = argv[1];
	port_num = argv[2];

    char *dev;
    //char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;


	static const int iterate = -1;
	char ebuf[PCAP_ERRBUF_SIZE];

	pcap_t *pd = NULL;
	cout << "goehogeh" << endl;
	cout << argv[1] << endl;
	pd = pcap_open_offline(argv[3], ebuf);

    if (pcap_loop(pd, iterate, pcap_callback, NULL) < 0) {
		(void)fprintf(stderr, "pcap_loop: error occurred\n");
	exit(1);
    }

    pcap_close(pd);




//
//    /* Options must be passed in as a string because I am lazy */
//    if(argc < 2){
//        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
//        return 0;
//    }
//
//    /* grab a device to peak into... */
//    dev = pcap_lookupdev(errbuf);
//    if(dev == NULL)
//    { printf("%s\n",errbuf); exit(1); }
//
//    /* ask pcap for the network address and mask of the device */
//    pcap_lookupnet(dev,&netp,&maskp,errbuf);
//
//    /* open device for reading. NOTE: defaulting to
//     * promiscuous mode*/
//    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
//    if(descr == NULL)
//    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }
//
//
//    if(argc > 2)
//    {
//        /* Lets try and compile the program.. non-optimized */
//        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
//        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }
//
//        /* set the compiled program as the filter */
//        if(pcap_setfilter(descr,&fp) == -1)
//        { fprintf(stderr,"Error setting filter\n"); exit(1); }
//    }
//
//    /* ... and loop */
//    pcap_loop(descr,atoi(argv[1]),my_callback,args);
//
//    fprintf(stdout,"\nfinished\n");
//    return 0;
}




