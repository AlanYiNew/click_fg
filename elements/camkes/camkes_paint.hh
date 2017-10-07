#ifndef CLICK_PAINT_HH
#define CLICK_PAINT_HH
#include <click/element.hh>
#include <porttype.h>
CLICK_DECLS

/*
=c

Paint(COLOR [, ANNO])

=s paint

sets packet paint annotations

=d

Sets each packet's paint annotation to COLOR, an integer 0..255.

Paint sets the packet's PAINT annotation by default, but the ANNO argument can
specify any one-byte annotation.

=h color read/write

Get/set the color to paint.

=a PaintTee */

class Camkes_Paint : public Element { public:

    Camkes_Paint() CLICK_COLD;
    const char *class_name() const		{ return "Camkes Paint"; }
    const char *port_count() const		{ return PORTS_1_1; }
    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    bool can_live_reconfigure() const		{ return true; }
    void add_handlers() CLICK_COLD;

    void push(int port, Packet *p);
    Packet *simple_action(Packet *);

    int setup_proxy(message_t** buffers,eventfunc_t* notify,int num);

  private:

    uint8_t _anno;
    uint8_t _color;
    message_t* proxy_buffer[MAX_OUTPUT_NUM];
    eventfunc_t proxy_event[MAX_OUTPUT_NUM];
};

CLICK_ENDDECLS
#endif
