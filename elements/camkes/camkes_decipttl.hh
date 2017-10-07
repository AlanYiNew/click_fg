#ifndef CLICK_DECIPTTL_HH
#define CLICK_DECIPTTL_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <porttype.h>
CLICK_DECLS

/*
 * =c
 * Camkes_DecIPTTL([keyword I<MULTICAST>])
 * =s ip
 * decrements IP time-to-live, drops dead packets
 * =d
 * Expects IP packet as input.
 * If the ttl is <= 1 (i.e. has expired),
 * Camkes_DecIPTTL sends the packet to output 1 (or discards it if there is no
 * output 1).
 * Otherwise it decrements the ttl, re-calculates the checksum,
 * and sends the packet to output 0.
 *
 * Ordinarily output 1 is connected to an ICMP error packet generator.
 *
 * =over 8
 *
 * =item ACTIVE
 *
 * Boolean.  If false, do not decrement any packets' TTLs.  Defaults to true.
 *
 * =item MULTICAST
 *
 * Boolean.  If false, do not decrement the TTLs for multicast packets.
 * Defaults to true.
 *
 * =back
 *
 * =e
 * This is a typical IP input processing sequence:
 *
 *   ... -> CheckIPHeader -> dt::Camkes_DecIPTTL -> ...
 *   dt[1] -> ICMPError(18.26.4.24, 11, 0) -> ...
 *
 * =a ICMPError, CheckIPHeader
 */

class Camkes_DecIPTTL : public Element { public:

    Camkes_DecIPTTL() CLICK_COLD;
    ~Camkes_DecIPTTL() CLICK_COLD;
    Camkes_DecIPTTL(message_t*);
    const char *class_name() const		{ return "Camkes_DecIPTTL"; }
    const char *port_count() const		{ return PORTS_1_1X2; }
    const char *processing() const		{ return PROCESSING_A_AH; }

    int configure(Vector<String> &conf, ErrorHandler *errh) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

    int setup_proxy(message_t** buffers,eventfunc_t* notify,int num);
  private:

    atomic_uint32_t _drops;
    bool _active;
    bool _multicast;
    message_t * _camkes_buf;

    message_t* proxy_buffer[MAX_OUTPUT_NUM];
    eventfunc_t proxy_event[MAX_OUTPUT_NUM];

};

CLICK_ENDDECLS
#endif
