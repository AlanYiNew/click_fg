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
#include "elements/camkes/camkes_paint.hh"
#include <vector>
#include <string>

void * aqb_sendbuffer[NUM_COMPONENT];//extra 1 port for this machine
eventfunc_t ev_func[NUM_COMPONENT];//upstream respond emit


extern "C" {
    void* paint_recvbuffer; 
    void* paint_sendbuffer;
    const char* camkes_id_attributes;
    void ev_wait(void);
    void ev2routing_emit(void);
}

#pragma weak paint_recvbuffer
#pragma weak paint_sendbuffer
#pragma weak camkes_id_attributes
#pragma weak ev_wait
#pragma weak ev2routing_emit
void inline debugging(const char* s,int val){
    std::cout << "###### " << std::left <<std::setw(40) << s << ": " << val << " #####" << std::endl;
}


void setup_cpaint(Camkes_Paint& cpaint,FileErrorHandler & feh);

//Shared pin,pout
const int pin_v[1] = {1};//0:Bidirectional 1:push 2:pull
const int pout_v[1] = {1};



int main(int argc, char *argv[]) {
    
    /* Click configuration */
    int re = 0;
    
    //Create a std erro handler for outputing message
    FileErrorHandler feh(stderr,"");

    Camkes_Paint cpaint; 
    
    //Configuring cpaint
    setup_cpaint(cpaint,feh); 

 

    int c = 0;
    Camkes_proxy cp[1] = {
        {&cpaint,(message_t*)paint_recvbuffer}
    };

    std::cout << "ev_wait" << (unsigned long*)ev_wait << std::endl;
    /* Wait for event */ 
    //A function detects if a pakcet is injected in the corresponding buffer
    Camkes_config::start_proxy(cp,1,ev_wait);   

    return 0;
}

void setup_cpaint(Camkes_Paint& cpaint,FileErrorHandler & feh){
    Vector<String> cpaint_config;
    cpaint_config.push_back(String("COLOR ") + String(camkes_id_attributes));
    int re = Camkes_config::set_nports(&cpaint,1,1);
    debugging("setting n ports for paint",re);
    re = cpaint.configure(cpaint_config,&feh);
    debugging("finishing configuration for paint",re);
    Camkes_config::initialize_ports(&cpaint,pin_v,pout_v); //one input one output
    message_t* buffer[1] = {(message_t*)paint_sendbuffer};
    eventfunc_t ev[1] = {ev2routing_emit};
    cpaint.setup_proxy(buffer,ev,1);

}
