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

TARGETS := $(notdir ${SOURCE_DIR}).cdl
ADL := click_scrtach.camkes
TEMPLATES += ../../projects/global-components/templates/

PROJECT_BASE := $(PWD)
RUMPRUN_BASE_DIR := $(PWD)/libs/rumprun


all: default

include TimeServer/TimeServer.mk
include SerialServer/SerialServer.mk
include PCIConfigIO/PCIConfigIO.mk

include ${SOURCE_DIR}/components/rump_ether/rump_ether.mk
include ${SOURCE_DIR}/components/reverse_string/server.mk



include ${PWD}/tools/camkes/camkes.mk