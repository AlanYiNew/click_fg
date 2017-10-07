/*
 * decipttl.{cc,hh} -- element decrements IP packet's time-to-live
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
#include "camkes_decipttl.hh"
#include <click/glue.hh>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <click/camkes_config.hh>
CLICK_DECLS

Camkes_DecIPTTL::Camkes_DecIPTTL()
    : _active(true), _multicast(true)
{
    _drops = 0;
}



Camkes_DecIPTTL::~Camkes_DecIPTTL()
{
}

int
Camkes_DecIPTTL::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return Args(conf, this, errh)
	.read("ACTIVE", _active)
	.read("MULTICAST", _multicast).complete();
}

Packet *
Camkes_DecIPTTL::simple_action(Packet *p)
{
    
    assert(p->has_network_header());
    if (!_active)
	return p;
    const click_ip *ip_in = p->ip_header();
    if (!_multicast && IPAddress(ip_in->ip_dst).is_multicast())
	return p;


    if (ip_in->ip_ttl <= 1) {
        ++_drops;
        //camkes proxy
        Packet* dst = reinterpret_cast<Packet*>(&(proxy_buffer[1]->content));
        if (((volatile message_t*)proxy_buffer[1])->ready){
            p->kill();
            return 0;
        }
        Camkes_config::packet_serialize(dst,p); 
        proxy_buffer[1]->ready = 1;
        proxy_event[1]();
        p->kill();
        return 0;
    } else {
	WritablePacket *q = p->uniqueify();
	if (!q)
	    return 0;
	click_ip *ip = q->ip_header();
	--ip->ip_ttl;

	// 19.Aug.1999 - incrementally update IP checksum as suggested by SOSP
	// reviewers, according to RFC1141, as updated by RFC1624.
	// new_sum = ~(~old_sum + ~old_halfword + new_halfword)
	//         = ~(~old_sum + ~old_halfword + (old_halfword - 0x0100))
	//         = ~(~old_sum + ~old_halfword + old_halfword + ~0x0100)
	//         = ~(~old_sum + ~0 + ~0x0100)
	//         = ~(~old_sum + 0xFEFF)
	unsigned long sum = (~ntohs(ip->ip_sum) & 0xFFFF) + 0xFEFF;
	ip->ip_sum = ~htons(sum + (sum >> 16));

	return q;
    }
}

void
Camkes_DecIPTTL::add_handlers()
{
    add_data_handlers("drops", Handler::OP_READ, &_drops);
    add_data_handlers("active", Handler::OP_READ | Handler::OP_WRITE | Handler::CHECKBOX, &_active);
}

//proxy function to setup the proxy buffer, num must be same as that used for noutputs in set_nports
int Camkes_DecIPTTL::setup_proxy(message_t** buffers,eventfunc_t* notify,int num){
    for (int i = 0 ; i < num; ++i){
        proxy_buffer[i] = buffers[i];
        proxy_event[i] = notify[i]; 
    }   
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Camkes_DecIPTTL)
ELEMENT_MT_SAFE(Camkes_DecIPTTL)
