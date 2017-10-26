// -*- c-basic-offset: 4 -*-
/*
 * lookupiproute.{cc,hh} -- element looks up next-hop address in static
 * routing table
 * Robert Morris, Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2002 International Computer Science Institute
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
#include "camkes_lookupiproute.hh"
#include <click/ipaddress.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <iostream>
CLICK_DECLS


Camkes_StaticIPLookup::Camkes_StaticIPLookup()
{
}

Camkes_StaticIPLookup::~Camkes_StaticIPLookup()
{
}

int
Camkes_StaticIPLookup::add_route(const IPRoute& route, bool set, IPRoute* old_route, ErrorHandler *errh)
{

#if !UNDER_CAMKES   
    if (router()->initialized())
	return errh->error("can't add routes dynamically");
    else
#endif
    return Camkes_LinearIPLookup::add_route(route, set, old_route, errh);
}

int
Camkes_StaticIPLookup::remove_route(const IPRoute& r, IPRoute* old_route, ErrorHandler *errh)
{
    if (router()->initialized())
	return errh->error("can't remove routes dynamically");
    else
	return Camkes_LinearIPLookup::remove_route(r, old_route, errh);
}

void
Camkes_StaticIPLookup::add_handlers()
{
    add_read_handler("table", table_handler);
    set_handler("lookup", Handler::OP_READ | Handler::READ_PARAM, lookup_handler);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(Camkes_LinearIPLookup)
EXPORT_ELEMENT(Camkes_StaticIPLookup)
