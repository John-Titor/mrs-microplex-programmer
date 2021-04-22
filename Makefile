APPROOT		 = $(dir $(lastword $(MAKEFILE_LIST)))

CHIP		 = LPC11C24FBD48
PORT		 = /dev/cu.usbserial-FTVX7O5F
BIN		 = obj/programmer.bin
SRCS		:= $(abspath $(wildcard $(APPROOT)/*.cpp))
#DEFINES		 = scmRTOS_PROCESS_COUNT=1

include $(abspath $(APPROOT)/../../NXP/lpc11xx_classlib/make.inc)
