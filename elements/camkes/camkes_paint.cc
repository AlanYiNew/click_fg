/*
 * paint.{cc,hh} -- element sets packets' paint annotation
 * Eddie Kohler, Robert Morris
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Meraki, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "camkes_paint.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/packet_anno.hh>
#include <iostream>
#include <cstring>
#include "porttype.h"
#include <clicknet/ip.h>
#include <click/camkes_config.hh>
CLICK_DECLS

Camkes_Paint::Camkes_Paint(){}

Camkes_Paint::Camkes_Paint(message_t* camkes_buf):_camkes_buf(camkes_buf){}


int
Camkes_Paint::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int anno = PAINT_ANNO_OFFSET;
    if (Args(conf, this, errh)
	.read_mp("COLOR", _color)
    .read_p("ANNO", AnnoArg(1), anno).complete() < 0)
	return -1;
    _anno = anno;
    return 0;
}

void Camkes_Paint::push(int port, Packet *p)
{ 
    p = simple_action(p);
    
    if (p){
    
        //camkes proxy
        Packet* dst = reinterpret_cast<Packet*>(&(_camkes_buf->content));
        if (((volatile message_t*)_camkes_buf)->ready){
           p->kill();
           return;
        }
        Camkes_config::packet_serialize(dst,p); 
        _camkes_buf->ready = 1;
        p->kill();
    }
        
}


Packet *
Camkes_Paint::simple_action(Packet *p)
{
    p->set_anno_u8(_anno, _color);
    return p;
}

void
Camkes_Paint::add_handlers()
{
    add_data_handlers("color", Handler::OP_READ | Handler::OP_WRITE, &_color);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Paint)
ELEMENT_MT_SAFE(Paint)
