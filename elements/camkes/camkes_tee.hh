#ifndef CLICK_TEE_HH
#define CLICK_TEE_HH
#include <click/element.hh>
#include <porttype.h>
CLICK_DECLS

/*
 * =c
 * Camkes_Tee([N])
 *
 * PullCamkes_Tee([N])
 * =s basictransfer
 * duplicates packets
 * =d
 * Camkes_Tee sends a copy of each incoming packet out each output.
 *
 * PullCamkes_Tee's input and its first output are pull; its other outputs are push.
 * Each time the pull output pulls a packet, it
 * sends a copy out the push outputs.
 *
 * Camkes_Tee and PullCamkes_Tee have however many outputs are used in the configuration,
 * but you can say how many outputs you expect with the optional argument
 * N.
 */

class Camkes_Tee : public Element {

 public:

  Camkes_Tee() CLICK_COLD;

  const char *class_name() const		{ return "Camkes_Tee"; }
  const char *port_count() const		{ return "1/1-"; }
  const char *processing() const		{ return PUSH; }
  
  int setup_proxy(message_t** buffers,eventfunc_t* ev,int );
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  void push(int, Packet *);
 private:
    message_t* proxy_buffer[MAX_OUTPUT_NUM];
    eventfunc_t proxy_event[MAX_OUTPUT_NUM];

};

class PullCamkes_Tee : public Element {

 public:

  PullCamkes_Tee() CLICK_COLD;

  const char *class_name() const		{ return "PullCamkes_Tee"; }
  const char *port_count() const		{ return "1/1-"; }
  const char *processing() const		{ return "l/lh"; }

  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;

  Packet *pull(int);

};

CLICK_ENDDECLS
#endif
