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
#include "elements/camkes/camkes_tee.hh"
#include <vector>
#include <string>

eventfunc_t ev_func[NUM_COMPONENT];//upstream respond emit


extern "C" {
    void* aqb_sendbuffer_buf(int); 
    void* aqb_recvbuffer_buf(int);
    void ev2ether0_emit(void);
    void ev2ether1_emit(void);
    void ev2ether2_emit(void);
    void ev_wait(void);
}

#pragma weak aqb_sendbuffer_buf
#pragma weak aqb_recvbuffer_buf
#pragma weak ev_wait
#pragma weak ev2ether0_emit
#pragma weak ev2ether1_emit
#pragma weak ev2ether2_emit

void inline debugging(const char* s,int val){
    std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}

void setup_cTee(Camkes_Tee &cTee,ErrorHandler& feh);
//Shared pin,pout
const int pin_v[1] = {1};//0:Bidirectional 1:push 2:pull
const int pout_v[NUM_COMPONENT] = {1,1,1};



int main(int argc, char *argv[]) {
    
    /* Click configuration */
    int re = 0;
    
   
    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    Camkes_Tee cTee; 
    setup_cTee(cTee,feh); 
    Camkes_proxy_m cp[1] = {
        {&cTee,aqb_recvbuffer_buf,NUM_COMPONENT}
    };

    std::cout << "ev_wait" << (unsigned long*)ev_wait << std::endl;
    /* Wait for event */ 
    //A function detects if a pakcet is injected in the corresponding buffer
    Camkes_config::start_proxy(cp,1,ev_wait);   

    return 0;
}

void setup_cTee(Camkes_Tee &cTee,ErrorHandler& feh){
    Vector<String> cTee_config;
    cTee_config.push_back("3");
    int re = Camkes_config::set_nports(&cTee,1,3); 
    debugging("setting n ports for cTee",re);
    re = cTee.configure(cTee_config,&feh); 
    debugging("No configuration for cTee",re);
    Camkes_config::initialize_ports(&cTee,pin_v,pout_v); //one input three output
    
    message_t* aqb_sendbuffer[3];
    aqb_sendbuffer[0] = (message_t*)aqb_sendbuffer_buf(0);
    aqb_sendbuffer[1] = (message_t*)aqb_sendbuffer_buf(1);
    aqb_sendbuffer[2] = (message_t*)aqb_sendbuffer_buf(2);

    eventfunc_t ev[3] = {ev2ether1_emit,
                         ev2ether0_emit,
                         ev2ether2_emit};
    cTee.setup_proxy(aqb_sendbuffer,ev,3);
}
