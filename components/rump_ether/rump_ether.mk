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

cfiles := $(wildcard ${CURRENT_DIR}/tcp_server.c)
hfiles := $(wildcard ${CURRENT_DIR}/include/porttype.h)
CAMKES_FLAGS += --cpp-flag=-I${RUMPRUN_BASE_DIR}/platform/sel4/camkes/ 
rumprun_ether_HFILES := $(wildcard ${CURRENT_DIR}/include/porttype.h)
rumprun_ether_HFILES += ${CURRENT_DIR}/../../include/buffer.h
rumprun_ether_rumpbin := hello

hello: $(cfiles) $(hfiles)
	echo ${CURRENT_DIR}
	$(RUMPRUN_CC) -no-pie -I${CURRENT_DIR}/../../include $^ -o $@ -lpthread -lpcap

