/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

#include <buffer.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <iomanip>
//2 client component at the moment
#include <porttype.h>
#include <click/packet.hh>

//Click related include
#include "elements/ip/checkipheader.hh"
#include <click/camkes_config.hh>
#include <click/config.h>
#include <click/element.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
#include "elements/standard/print.hh"
#include "elements/standard/discard.hh"
#include "elements/standard/strip.hh"
#include "elements/ip/getipaddress.hh"
#include "elements/camkes/camkes_lookupiproute.hh"
#include <vector>
#include <string>

void * db_buffer[NUM_COMPONENT+1];//extra 1 port for this machine
eventfunc_t ev_func[NUM_COMPONENT];//upstream respond emit


extern "C" {
    //message_t *section[NUM_COMPONENT];
    void ev_wait(void);
    void* paint_recvbuffer_buf(int); 
    void ev2ether1_emit(void);
    void ev2ether2_emit(void);
    void ev2ether0_emit(void);
    const char *ip_addr0;
    const char *ip_addr1;
    const char *ip_addr2;
    const char * rt[RT_NUM_ENTRY];
    void* db_buffer_buf(int);
    void* icmp_buffer_buf(int);
}

#pragma weak ev2ether1_emit
#pragma weak ev2ether2_emit
#pragma weak ev2ether0_emit
#pragma weak paint_recvbuffer_buf
#pragma weak db_buffer_buf
#pragma weak ev_wait
#pragma weak ip_addr1
#pragma weak ip_addr0
#pragma weak ip_addr2
#pragma weak rt
#pragma weak icmp_buffer_buf




void inline debugging(const char* s,int val){
    std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}

int main(int argc, char *argv[]) {
    
    /* Click configuration */
    int re = 0;
    
    //Shared pin,pout
    const int pin_v[1] = {1};//0:Bidirectional 1:push 2:pull
    const int pout_v[1] = {1};
    
    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    //proxy strip
    Strip strip;
    //ChceckIPHeader    
    CheckIPHeader cih;
    
    //Discard element
    Discard discard;
    //GetIPAddress
    GetIPAddress gia;
    //LookIPRoute
    Camkes_StaticIPLookup clir;

    //Configuring StaticIPRoute
    Vector<String> clir_config;
    for (int i = 0 ; i < RT_NUM_ENTRY ; i++){
        clir_config.push_back(rt[i]);
    }
    
        re = Camkes_config::set_nports(&clir,1,NUM_COMPONENT+1); 
    debugging("setting n ports for clir",re);
    re = clir.configure(clir_config,&feh); 
    debugging("finish configuration for clir",re);
    const int clir_pout_v[NUM_COMPONENT+1] = {1,1,1,1};
    Camkes_config::initialize_ports(&clir,pin_v,clir_pout_v); //one input three output
    Camkes_config::connect_port(&clir,true,0,&discard,0);//true int Element int
    message_t* buffer[4] = {NULL,
                            (message_t*)db_buffer_buf(1),
                            (message_t*)db_buffer_buf(0),
                            (message_t*)db_buffer_buf(2)};
    eventfunc_t ev[4] = {NULL, ev2ether1_emit,ev2ether0_emit,ev2ether2_emit}; 
    clir.setup_proxy(buffer,ev,4);    
    
    //Configuring GetIPAddres
    Vector<String> gia_config;
    gia_config.push_back("OFFSET 16");
    re = Camkes_config::set_nports(&gia,1,1); 
    debugging("setting n ports for gia",re);
    re = gia.configure(gia_config,&feh); 
    debugging("finish configuration for gia",re);
    Camkes_config::initialize_ports(&gia,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&gia,true,0,&clir,0);//true int Element int

    //Configuring cameks strip
    Vector<String> strip_config;
    strip_config.push_back("LENGTH 14");
    re = Camkes_config::set_nports(&strip,1,1); 
    debugging("setting n ports for strip",re);
    re = strip.configure(strip_config,&feh); 
    debugging("finish configuration for strip",re);
    Camkes_config::initialize_ports(&strip,pin_v,pout_v); //one input three output
    Camkes_config::connect_port(&strip,true,0,&cih,0);//true int Element int

    //Configuring cih
    Vector<String> cih_config;//At the moment hard code a vector to configure it
    cih_config.push_back(String("INTERFACES ") + ip_addr1 + " " + ip_addr0);
    re = Camkes_config::set_nports(&cih,1,1);
    debugging("setting n ports for cih",re);
    re = cih.configure(cih_config,&feh);
    debugging("finish configuration for cih",re);
    Camkes_config::initialize_ports(&cih,pin_v,pout_v); //one input one output
    Camkes_config::connect_port(&cih,true,0,&gia,0);//true int Element int
    
    //Configuring discard
    re = Camkes_config::set_nports(&discard,1,0);
    debugging("setting n ports for discard",re);
    Camkes_config::initialize_ports(&discard,pin_v,NULL);//We don't have output port putting in_v is fine
    debugging("No configuration call to discard",0); 

    int count = NUM_COMPONENT;
    int c = 0;
    Camkes_proxy_m cp[2] = {
        {&clir,icmp_buffer_buf,NUM_COMPONENT},
        {&strip,paint_recvbuffer_buf,NUM_COMPONENT}
    };

    /* Wait for event */ 


    std::cout << "ev_wait" << (unsigned long*)ev_wait << std::endl;
    //A function detects if a pakcet is injected in the corresponding buffer
    Camkes_config::start_proxy(cp,2,ev_wait); 




    //It's dynamically acllocated in camkes_config
    //Not a good design but haven't found en effective way to do this 
    //Camkes_config::recycle(p);

    return 0;
}


