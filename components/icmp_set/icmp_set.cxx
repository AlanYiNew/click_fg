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
#include "elements/camkes/camkes_icmperror.hh"
#include "elements/ip/ipnameinfo.hh"
#include <click/nameinfo.hh>

void * aqb_sendbuffer[NUM_COMPONENT];//extra 1 port for this machine
eventfunc_t ev_func[NUM_COMPONENT];//upstream respond emit


extern "C" {
    void* icmp_buffer; 
    void* icmpmf_buffer;
    void* icmpttl_buffer;
    void* icmpbp_buffer;
    void* icmprd_buffer;
    const char* ip_addr;
    void ev2routing_emit(void);
    void ev_wait(void);
}

#pragma weak icmp_buffer
#pragma weak icmpmf_buffer
#pragma weak icmpttl_buffer
#pragma weak icmpbp_buffer
#pragma weak icmprd_buffer
#pragma weak ip_addr
#pragma weak ev2routing_emit
#pragma weak ev_wait

void inline debugging(const char* s,int val){
    std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}

//Shared pin,pout
const int pin_v[1] = {1};//0:Bidirectional 1:push 2:pull
const int pout_v[1] = {1};


void setup_cicmpbp(Camkes_ICMPError& icmpbp,FileErrorHandler &feh );
void setup_cicmpttl(Camkes_ICMPError& icmpttl,FileErrorHandler &feh );
void setup_cicmpmf(Camkes_ICMPError& icmpmf,FileErrorHandler &feh );
void setup_cicmprd(Camkes_ICMPError& icmprd,FileErrorHandler &feh );
int main(int argc, char *argv[]) {
    
    /* Click configuration */
    int re = 0; 
   
    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    NameInfo::static_initialize();
    IPNameInfo::static_initialize();


    //ICMPError redirect
    Camkes_ICMPError cicmprd;
    //ICMPError parameter problem
    Camkes_ICMPError cicmpbp;
    //ICMPError ttl 
    Camkes_ICMPError cicmpttl;
    //ICMPError must flag 
    Camkes_ICMPError cicmpmf;    
    Camkes_proxy cp[4] = {
        {&cicmprd,(message_t*)icmprd_buffer},
        {&cicmpbp,(message_t*)icmpbp_buffer},
        {&cicmpttl,(message_t*)icmpttl_buffer},
        {&cicmpmf,(message_t*)icmpmf_buffer} 
    };
    //Configuring icmpttl
    setup_cicmpmf(cicmpmf,feh);

    //Configuring icmpttl
    setup_cicmpttl(cicmpttl,feh);

    //Configuring icmprd
    setup_cicmprd(cicmprd,feh);

    //Configuring icmp badparameter
    setup_cicmpbp(cicmpbp,feh);


    std::cout << "ev_wait" << (unsigned long*)ev_wait << std::endl;
    //A function detects if a pakcet is injected in the corresponding buffer
    Camkes_config::start_proxy(cp,4,ev_wait);   

    return 0;
}


void setup_cicmpbp(Camkes_ICMPError& icmpbp,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmpbp_config;
    icmpbp_config.push_back(ip_addr);
    icmpbp_config.push_back("parameterproblem");
    re = Camkes_config::set_nports(&icmpbp,1,1);        
    debugging("setting n ports for icmpbp",re);
    re = icmpbp.configure(icmpbp_config,&feh);
    debugging("finishing configuration for icmpbp",re);
    Camkes_config::initialize_ports(&icmpbp,pin_v,pout_v);

    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmpbp.setup_proxy(buffer,ev,1);

}

void setup_cicmprd(Camkes_ICMPError& icmprd,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmprd_config;
    icmprd_config.push_back(ip_addr);
    icmprd_config.push_back("redirect");
    icmprd_config.push_back("host");
    re = Camkes_config::set_nports(&icmprd,1,1);        
    debugging("setting n ports for icmprd",re);
    re = icmprd.configure(icmprd_config,&feh);
    debugging("finishing configuration for icmprd",re);
    Camkes_config::initialize_ports(&icmprd,pin_v,pout_v);
    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmprd.setup_proxy(buffer,ev,1);
}

void setup_cicmpttl(Camkes_ICMPError& icmpttl,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmpttl_config;
    icmpttl_config.push_back(ip_addr);
    icmpttl_config.push_back("timeexceeded");
    re = Camkes_config::set_nports(&icmpttl,1,1);        
    debugging("setting n ports for icmpttl",re);
    re = icmpttl.configure(icmpttl_config,&feh);
    debugging("finishing configuration for icmpttl",re);
    Camkes_config::initialize_ports(&icmpttl,pin_v,pout_v);
    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmpttl.setup_proxy(buffer,ev,1);

}

void setup_cicmpmf(Camkes_ICMPError& icmpmf,FileErrorHandler &feh ){
    int re = 0;
    Vector<String> icmpmf_config;
    icmpmf_config.push_back(ip_addr);
    icmpmf_config.push_back("unreachable");
    icmpmf_config.push_back("needfrag");
    re = Camkes_config::set_nports(&icmpmf,1,1);        
    debugging("setting n ports for icmpmf",re);
    re = icmpmf.configure(icmpmf_config,&feh);
    debugging("finishing configuration for icmpmf",re);
    Camkes_config::initialize_ports(&icmpmf,pin_v,pout_v);
    message_t* buffer[1] = {(message_t*)icmp_buffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    
    icmpmf.setup_proxy(buffer,ev,1);

}
