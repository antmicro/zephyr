.. zephyr:code-sample:: usb-host-hid-mouse-display
   :name: USB Host HID Mouse Display
   :relevant-api: usbh_api input_interface display_interface

   Draw a cursor-like marker on a display using a USB HID boot mouse.

Overview
********

This sample demonstrates a USB host application that receives HID boot mouse
events and visualizes them on a display.

The sample:

* Initializes the USB host stack and HID boot class support.
* Receives relative mouse movement and left-button events through Zephyr input.
* Draws a small cross marker at the current pointer position.
* Erases the previously drawn marker before drawing the new one.
* Logs left-button press/release events with current coordinates.

Only relative X/Y movement and the left mouse button are handled by this
application.

Requirements
************

This sample requires:

* A board with USB host support.
* A configured display device (``zephyr,display`` in devicetree ``/chosen``).
* A USB HID boot mouse.

The provided board support is for ``stm32h747i_disco/stm32h747xx/m7``,
using the sparkfun_max3421e shield.

Building and Running
********************

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/usb/host_hid_mouse_display
   :board: stm32h747i_disco/stm32h747xx/m7
   :shield: st_b_lcd40_dsi1_mb1166_a09
   :shield: sparkfun_max3421e
   :goals: flash
   :compact:

After the sample starts, connect a USB mouse to the host port.
Moving the mouse updates the marker position on the display.

Sample Output
*************

Example log output:
(the logging is set to minimal to make the mouse more responsive)

.. code-block:: console

   I: HID Boot Device Class initialized
   I: Device disconnected
   *** Booting Zephyr OS build v4.4.0-1426-g0122fbb01c5f ***
   I: REV 0x13, MODE 0xe1, HIEN 0xe3
   I: host: USB host initialized
   I: LS Device connected
   I: New device with address 1 state 2
   I: Configuration 1 bNumInterfaces 1
   I: HID Boot Mouse detected
   I: Class 'usbh_hid_boot_0' matches interface 0
   I: Left button pressed at x:178 y:120
   I: Left button let go at x:178 y:120
   I: Left button pressed at x:297 y:209
   I: Left button let go at x:499 y:215

Configuration Options
*********************

This Sample
===========

* :kconfig:option:`CONFIG_SAMPLE_COLORED_OUTPUT` - ANSI color highlighting for
  left-button event log messages.

USB Host and HID Boot
=====================

* :kconfig:option:`CONFIG_USB_HOST_STACK` - Enable USB host stack.
* :kconfig:option:`CONFIG_USBH_HID_BOOT_CLASS` - Enable HID boot class driver.
* :kconfig:option:`CONFIG_USBH_HID_BOOT_INSTANCES_COUNT` - Maximum number of
  HID boot devices.

Display and Input
=================

* :kconfig:option:`CONFIG_DISPLAY` - Enable display subsystem.
* :kconfig:option:`CONFIG_INPUT` - Enable input subsystem.
