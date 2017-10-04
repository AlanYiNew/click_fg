/*
 * tee.{cc,hh} -- element duplicates packets
 * Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
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
#include "camkes_tee.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/camkes_config.hh>
CLICK_DECLS

Camkes_Tee::Camkes_Tee()
{
}

Camkes_Tee::Camkes_Tee(message_t ** _camkes_buf){
    this->_camkes_buf = _camkes_buf;
}

int
Camkes_Tee::configure(Vector<String> &conf, ErrorHandler *errh)
{
    unsigned n = noutputs();
    if (Args(conf, this, errh).read_p("N", n).complete() < 0)
	return -1;
    if (n != (unsigned) noutputs())
	return errh->error("%d outputs implies %d arms", noutputs(), noutputs());
    return 0;
}

void
Camkes_Tee::push(int, Packet *p)
{
  int n = noutputs();
 
  for (int i = 0; i < n; i++){
        //camkes proxy
        Packet* dst = reinterpret_cast<Packet*>(&(_camkes_buf[i]->content));
        if (((volatile message_t*)_camkes_buf[i])->ready){
            p->kill();
            return;
        }
        Camkes_config::packet_serialize(dst,p);
        _camkes_buf[i]->ready = 1;
  }
  p->kill();
}

//
// PULLTEE
//

PullCamkes_Tee::PullCamkes_Tee()
{
}

int
PullCamkes_Tee::configure(Vector<String> &conf, ErrorHandler *errh)
{
    unsigned n = noutputs();
    if (Args(conf, this, errh).read_p("N", n).complete() < 0)
	return -1;
    if (n != (unsigned) noutputs())
	return errh->error("%d outputs implies %d arms", noutputs(), noutputs());
    return 0;
}

Packet *
PullCamkes_Tee::pull(int)
{
  Packet *p = input(0).pull();
  if (p) {
    int n = noutputs();
    for (int i = 1; i < n; i++)
      if (Packet *q = p->clone())
	output(i).push(q);
  }
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(Camkes_Tee PullTee)
ELEMENT_MT_SAFE(Camkes_Tee)
ELEMENT_MT_SAFE(PullCamkes_Tee)
