#include <click/element.hh>
#include <click/handler.hh>
#include <iostream>
#include <click/packet.hh>
#include <clicknet/ip.h>
#include "porttype.h"

class Camkes_proxy{
    private:
    Element * elem;
    message_t * buffer;
    public:
        Camkes_proxy(Element * elemm, message_t * bufferr);
        void push();
};

class Camkes_proxy_m{
public:
    using buf_func_t = void* (*)(int);
    Camkes_proxy_m(Element * elemm, buf_func_t  func,int nclient);
    void push();
private:
    Element * elem;
    buf_func_t func;
    int nclient;

};


class Camkes_config{
    public:
        static int connect_port(Element* tar,bool isoutput, int port, Element* e, int e_port);

        static void initialize_ports(Element* tar,const int* input_codes, const int* output_codes);

        static int set_nports(Element* tar,int ninputs,int noutputs);

        static void initialize(Element* tar, ErrorHandler * eh);

        static void start_pcap_dispatch(Element* recv,Element* send,Camkes_proxy * cp,int num);

        //Mashalling
        static int packet_serialize(Packet * dst,Packet *src);

        //vtable realted. Be careful.Demarshalling 
        static void deserialize_packet(Packet* &dst,void* src);

        static void recycle(Packet * p);

        static void  start_proxy(Camkes_proxy_m * camkes_buf,int n);
 
};


