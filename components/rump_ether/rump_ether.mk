#
# Copyright 2017, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the BSD 2-Clause license. Note that NO WARRANTY is provided.
# See "LICENSE_BSD2.txt" for details.
#
# @TAG(DATA61_BSD)
#
#

CURRENT_DIR := $(dir $(abspath $(lastword ${MAKEFILE_LIST})))

include ${RUMPRUN_BASE_DIR}/platform/sel4/rumprunlibs.mk

cfiles := $(wildcard ${CURRENT_DIR}/ether_server.cxx)
hfiles := $(wildcard ${CURRENT_DIR}/include/porttype.h)
CAMKES_FLAGS += --cpp-flag=-I${RUMPRUN_BASE_DIR}/platform/sel4/camkes/ 
rumprun_ether_HFILES := $(patsubst ${SOURCE_DIR}/%,%,$(wildcard ${SOURCE_DIR}/include/*.h))
rumprun_ether_rumpbin := click

#-include  ${SOURCE_DIR}/include/click/config.h
#click: $(CLICK_LIBS) $(ELEMENTS_OBJS) $(ELEMENTS_HHFILES) $(cfiles) $(hfiles) 	

click: $(cfiles) $(hfiles) \
		$(SOURCE_DIR)/elements/camkes/camkes_classifier.o \
		$(SOURCE_DIR)/elements/camkes/camkes_classifier.hh \
		$(SOURCE_DIR)/elements/standard/alignmentinfo.o \
		$(SOURCE_DIR)/elements/standard/print.o \
		$(SOURCE_DIR)/elements/standard/print.hh \
		$(SOURCE_DIR)/elements/standard/discard.o \
		$(SOURCE_DIR)/elements/standard/discard.hh \
		$(SOURCE_DIR)/elements/standard/classification.hh \
		$(SOURCE_DIR)/elements/standard/errorelement.o \
		$(SOURCE_DIR)/elements/standard/classification.o \
		$(SOURCE_DIR)/elements/standard/addressinfo.o \
		$(SOURCE_DIR)/elements/ethernet/arpresponder.o \
		$(SOURCE_DIR)/elements/ethernet/arpresponder.hh \
		$(SOURCE_DIR)/elements/ethernet/arpquerier.o \
		$(SOURCE_DIR)/elements/ethernet/arpquerier.hh \
		$(SOURCE_DIR)/elements/ethernet/arptable.o \
		$(SOURCE_DIR)/elements/ethernet/arptable.hh \
		$(SOURCE_DIR)/elements/userlevel/fromdevice.o \
		$(SOURCE_DIR)/elements/userlevel/fromdevice.hh \
		$(SOURCE_DIR)/elements/userlevel/fakepcap.o \
		$(SOURCE_DIR)/elements/userlevel/fakepcap.hh \
		$(SOURCE_DIR)/elements/userlevel/kernelfilter.o \
		$(SOURCE_DIR)/elements/userlevel/kernelfilter.hh \
		$(SOURCE_DIR)/elements/userlevel/todevice.o \
		$(SOURCE_DIR)/elements/userlevel/todevice.hh \
		$(SOURCE_DIR)/elements/standard/fullnotequeue.o \
		$(SOURCE_DIR)/elements/standard/fullnotequeue.hh \
		$(SOURCE_DIR)/elements/standard/notifierqueue.o \
		$(SOURCE_DIR)/elements/standard/notifierqueue.hh \
		$(SOURCE_DIR)/elements/standard/simplequeue.o \
		$(SOURCE_DIR)/elements/standard/simplequeue.hh \
		$(SOURCE_DIR)/elements/camkes/camkes_paint.o \
		$(SOURCE_DIR)/elements/camkes/camkes_paint.hh \
		$(SOURCE_DIR)/elements/standard/dropbroadcasts.hh \
		$(SOURCE_DIR)/elements/standard/dropbroadcasts.o \
		$(SOURCE_DIR)/elements/camkes/camkes_painttee.hh \
		$(SOURCE_DIR)/elements/camkes/camkes_painttee.o \
		$(SOURCE_DIR)/elements/camkes/camkes_icmperror.hh \
		$(SOURCE_DIR)/elements/camkes/camkes_icmperror.o \
		$(SOURCE_DIR)/elements/camkes/camkes_ipgwoptions.hh \
		$(SOURCE_DIR)/elements/camkes/camkes_ipgwoptions.o \
		$(SOURCE_DIR)/elements/ip/ipnameinfo.hh \
		$(SOURCE_DIR)/elements/ip/ipnameinfo.o \
		$(SOURCE_DIR)/elements/ip/fixipsrc.hh \
		$(SOURCE_DIR)/elements/ip/fixipsrc.o \
		$(SOURCE_DIR)/elements/camkes/camkes_decipttl.hh \
		$(SOURCE_DIR)/elements/camkes/camkes_decipttl.o \
		$(SOURCE_DIR)/elements/camkes/camkes_ipfragmenter.hh \
		$(SOURCE_DIR)/elements/camkes/camkes_ipfragmenter.o \
		$(CLICK_LIBS)
	@echo ${CURRENT_DIR}
	$(RUMPRUN_CXX) -no-pie \
		-include $(SOURCE_DIR)/include/click/config.h \
		-I${RUMP_BUILD_DIR}/x86_64/rumprun/rumprun-x86_64/include/c++  \
		-I${SOURCE_DIR}/include \
		-I${SOURCE_DIR} \
		-I${BUILD2_DIR}/x86_64/rumprun/rumprun-x86_64/include/c++ \
		-DUNDER_CAMKES \
		-L${SOURCE_DIR}/lib \
		 $^ -o $@  -lpthread -lpcap
