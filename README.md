# MRS / Microplex firmware flash tools

Tools and firmware to help flash MRS Electronics' range of CAN modules.

https://www.mrs-electronics.com

Tested Modules
==============

 - Microplex 7X
 - CC16WP CAN CAN

Other modules are likely to work with minimal effort, as MRS seem to use a common protocol.

Flasher
=======

Requires modern Python and the Peak PCAN API installed on your system. macOS users can
use mac-CAN.


Firmware
========

The firmware directory contains sample code implementing SLCan on the Olimex LPC11C24
development board. This is not currently supported by the flasher.
