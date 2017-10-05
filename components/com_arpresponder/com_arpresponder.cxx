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
#include "elements/camkes/camkes_arpresponder.hh"
#include "elements/ip/ipnameinfo.hh"
#include <click/nameinfo.hh>
#include <vector>
#include <string>



extern "C" {
    void* arpres_sendbuffer; 
    void* arpres_recvbuffer;
    const char * proxy_arp[NUM_COMPONENT-1];
}

#pragma weak arpres_sendbuffer
#pragma weak arpres_recvbuffer
#pragma weak proxy_arp

void setup_arpRes(Camkes_ARPResponder &arpRes,FileErrorHandler &feh);
void inline debugging(const char* s,int val){
    std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}

//Shared pin,pout
const int pin_v[1] = {1};//0:Bidirectional 1:push 2:pull
const int pout_v[1] = {1};



int main(int argc, char *argv[]) {
    
    /* Click configuration */
    int re = 0;

    NameInfo::static_initialize();
    IPNameInfo::static_initialize();



        //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    //Arp element
    Camkes_ARPResponder arpRes;
    
    //Configuring arp element
    setup_arpRes(arpRes,feh);  
   
    Camkes_proxy cp[1] = {
        {&arpRes,(message_t*)arpres_recvbuffer}
    };

    
    /* Wait for event */ 
    //A function detects if a pakcet is injected in the corresponding buffer
    Camkes_config::start_proxy(cp,1);   

    return 0;
}

void setup_arpRes(Camkes_ARPResponder &arpRes,FileErrorHandler &feh){
    Vector<String> arpRes_config;
    for (int i = 0; i < NUM_COMPONENT; i++){
        arpRes_config.push_back(proxy_arp[i]);
    }

    int re = Camkes_config::set_nports(&arpRes,1,1); 
    debugging("setting n ports for arpResponder",re);
    re = arpRes.configure(arpRes_config,&feh); 
    debugging("finish configuration for arpResponder",re);
    Camkes_config::initialize_ports(&arpRes,pin_v,pout_v); //one input three output
    message_t* proxy_buffer[1] = {(message_t*)arpres_sendbuffer};
    arpRes.setup_proxy(proxy_buffer,1);
}
