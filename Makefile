APPROOT		 = $(dir $(lastword $(MAKEFILE_LIST)))

CHIP		 = LPC11C24FBD48
PORT		 = /dev/cu.usbserial-SL0l841x
BIN		 = obj/test.bin
SRCS		:= $(abspath $(wildcard $(APPROOT)/*.cpp))
#DEFINES		 = scmRTOS_PROCESS_COUNT=1

include $(abspath $(APPROOT)/../../NXP/lpc11xx_classlib/make.inc)
