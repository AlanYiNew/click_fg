#ifndef CLICK_IPGWOPTIONS_HH
#define CLICK_IPGWOPTIONS_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <porttype.h>
CLICK_DECLS

/*
 * =c
 * Camkes_IPGWOptions(MYADDR [, OTHERADDRS])
 * =s ip
 * processes router IP options
 * =d
 * Process the IP options that should be processed by every router,
 * not just when ip_dst refers to the current router. At the moment
 * that amounts to Record Route and Timestamp (in particular,
 * not the source route options). MYADDR is the router's
 * IP address on the interface downstream from the element.
 *
 * Probably needs to be placed on the output path, since MYADDR
 * must be the outgoing interface's IP address (rfc1812 4.2.2.2).
 *
 * Recomputes the IP header checksum if it modifies the packet.
 *
 * The optional OTHERADDRS argument should be a space-separated list of IP
 * addresses containing the router's other interface addresses. It is used to
 * implement the Timestamp option.
 *
 * The second output may be connected to an ICMPError to produce
 * a parameter problem (type=12,code=0) message. Camkes_IPGWOptions sets
 * the param_off packet annotation so that ICMPError can set
 * the Parameter Problem pointer to point to the erroneous byte.
 *
 * =a ICMPError */

class Camkes_IPGWOptions : public Element { public:

  Camkes_IPGWOptions() CLICK_COLD;
  ~Camkes_IPGWOptions() CLICK_COLD;
  Camkes_IPGWOptions(message_t*);

  const char *class_name() const		{ return "Camkes_IPGWOptions"; }
  const char *port_count() const		{ return PORTS_1_1X2; }
  const char *processing() const		{ return PROCESSING_A_AH; }
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
  void add_handlers() CLICK_COLD;

  uint32_t drops() const			{ return _drops; }

  Packet *handle_options(Packet *);
  Packet *simple_action(Packet *);

  int setup_proxy(message_t** buffers,eventfunc_t* notify,int num);
 private:

  atomic_uint32_t _drops;
  struct in_addr _preferred_addr;
  Vector<IPAddress> _my_addrs;
  message_t* proxy_buffer[MAX_OUTPUT_NUM];
  eventfunc_t proxy_event[MAX_OUTPUT_NUM];
};

CLICK_ENDDECLS
#endif
