#ifndef CLICK_PAINTTEE_HH
#define CLICK_PAINTTEE_HH
#include <click/element.hh>
#include <porttype.h>
CLICK_DECLS

/*
 * =c
 * Camkes_PaintTee(COLOR [, ANNO])
 * =s paint
 * duplicates packets with given paint annotation
 * =d
 *
 * Camkes_PaintTee sends every packet through output 0. If the packet's
 * paint annotation is equal to COLOR (an integer), it also
 * sends a copy through output 1.
 *
 * Camkes_PaintTee uses the PAINT annotation by default, but the ANNO argument can
 * specify any one-byte annotation.
 *
 * =e
 * Intended to produce redirects in conjunction with Paint and
 * ICMPError as follows:
 *
 *   FromDevice(eth7) -> Paint(7) -> ...
 *   routingtable[7] -> pt :: Camkes_PaintTee(7) -> ... -> ToDevice(eth7)
 *   pt[1] -> ICMPError(18.26.4.24, 5, 1) -> [0]routingtable;
 *
 * =a Paint, ICMPError
 */

class Camkes_PaintTee : public Element { public:

    Camkes_PaintTee() CLICK_COLD;
    Camkes_PaintTee(message_t*); 

    const char *class_name() const	{ return "Camkes_PaintTee"; }
    const char *port_count() const	{ return "1/2"; }
    const char *processing() const	{ return PROCESSING_A_AH; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    Packet *simple_action(Packet *);

  private:
    message_t* _camkes_buf;
    uint8_t _anno;
    uint8_t _color;

};

CLICK_ENDDECLS
#endif
