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


cfiles := $(wildcard ${CURRENT_DIR}/icmp_set.cxx)
hfiles := $(wildcard ${CURRENT_DIR}/include/porttype.h)
CAMKES_FLAGS += --cpp-flag=-I${RUMPRUN_BASE_DIR}/platform/sel4/camkes/ 
CAMKES_FLAGS += --cpp-flag=-I${SOURCE_DIR}/include
icmp_set_HFILES := $(patsubst ${SOURCE_DIR}/%,%,$(wildcard ${SOURCE_DIR}/include/*.h))
icmp_set_rumpbin := icmp_set

#-include  ${SOURCE_DIR}/include/click/config.h
#click: $(CLICK_LIBS) $(ELEMENTS_OBJS) $(ELEMENTS_HHFILES) $(cfiles) $(hfiles) 	

icmp_set: $(cfiles) $(hfiles) \
	$(SOURCE_DIR)/elements/standard/alignmentinfo.o \
	$(SOURCE_DIR)/elements/standard/errorelement.o \
	$(SOURCE_DIR)/elements/standard/addressinfo.o \
	$(SOURCE_DIR)/elements/camkes/camkes_icmperror.o \
	$(SOURCE_DIR)/elements/camkes/camkes_icmperror.hh \
	$(SOURCE_DIR)/elements/ip/ipnameinfo.o \
	$(SOURCE_DIR)/elements/ip/ipnameinfo.hh \
	$(CLICK_LIBS) 
	@echo ${CURRENT_DIR}
	@echo $(icmp_set_HFILES)
	$(RUMPRUN_CXX) -no-pie \
		-include $(SOURCE_DIR)/include/click/config.h \
		-I${RUMP_BUILD_DIR}/x86_64/rumprun/rumprun-x86_64/include/c++  \
		-I${SOURCE_DIR}/include \
		-I${SOURCE_DIR} \
		-I${BUILD2_DIR}/x86_64/rumprun/rumprun-x86_64/include/c++ \
		-DUNDER_CAMKES \
		-L${SOURCE_DIR}/lib \
		 $^ -o $@
