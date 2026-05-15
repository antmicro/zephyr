.. zephyr:code-sample:: usb-host-hid-boot
   :name: USB Host HID Boot Interface
   :relevant-api: usbh_api input_interface

   Receive input from USB HID boot interface devices (keyboard and mouse).

Overview
********

This sample demonstrates how to use the USB Host HID (Human Interface Device)
Boot Protocol driver to receive input from USB keyboards and mice connected to
a Zephyr device acting as a USB host.

Upon connection, USB HID boot devices (keyboards and mice) are detected and
configured automatically.

The sample logs the following input events:

* Keyboard key presses and releases (with key names)
* Mouse button events (left, middle, right)
* Mouse movement (X and Y axis)

Requirements
************

This sample uses the USB host stack and requires a USB host controller driver.
Currently only MAX3421E USB host controller on a sparkfun shield connected to STM32H747I-DISCO is tested.

A USB keyboard or mouse that supports the HID Boot Protocol is required. Most
standard USB keyboards and mice support this protocol.

If you want to check if your device support HID Boot enter this command in Linux, while the
device is connected:
:command:`lsusb -v -dVENDOR_ID:PRODUCT_ID`

Where vendor id and product id can be found by executing:
:command:`lsusb`

Is my USB device compatible?
============================

And in the output look for:

.. code-block::

   bInterfaceClass         3 Human Interface Device
   bInterfaceSubClass      1 Boot Interface Subclass

Building and Running
********************

.. zephyr-app-commands::
   :zephyr-app: samples/subsys/usb/host_hid_boot
   :board: stm32h747i_disco/stm32h747xx/m7
   :shield: sparkfun_max3421e
   :goals: flash
   :compact:

Sample Output
*************

When the sample starts, you should see:

.. code-block:: console

   [00:00:00.100,000] <inf> usbh_hid_boot: HID Boot Device Class initialized
   *** Booting Zephyr OS build v4.4.0-rc3-93-gf1671ee11957 ***
   [00:00:00.103,000] <inf> max3421e: REV 0x13, MODE 0xe1, HIEN 0xe3
   [00:00:00.103,000] <inf> main: host: USB host initialized

Keyboard Input
==============

When a USB keyboard is connected and keys are pressed, you will see:

.. code-block:: console

   [00:00:05.719,000] <inf> max3421e: Device disconnected
   [00:00:05.720,000] <inf> max3421e: LS Device connected
   [00:00:05.790,000] <inf> usbh_dev: New device with address 1 state 2
   [00:00:05.806,000] <inf> usbh_dev: Configuration 1 bNumInterfaces 2
   [00:00:05.806,000] <dbg> usbh_hid_boot: usbh_hid_boot_probe: Connected a HID Boot device
   [00:00:05.806,000] <dbg> usbh_hid_boot: find_int_in_ep: Found Endpoint for a HID Boot function: 81
   [00:00:05.806,000] <inf> usbh_hid_boot: HID Boot Keyboard detected
   [00:00:05.808,000] <inf> usbh_class: Class 'usbh_hid_boot_0' matches interface 0
   [00:00:08.658,000] <inf> main: Key B was pressed
   [00:00:10.438,000] <inf> main: Key Left Shift was pressed
   [00:00:11.678,000] <inf> main: Key 4 was pressed
   [00:00:12.218,000] <inf> main: Key Left Shift was released
   [00:00:12.488,000] <inf> main: Key B was released
   [00:00:12.558,000] <inf> main: Key 4 was released
   [00:00:14.248,000] <inf> main: Key Left Ctrl was pressed
   [00:00:14.818,000] <inf> main: Key UP was pressed
   [00:00:14.888,000] <inf> main: Key UP was released
   [00:00:15.038,000] <inf> main: Key Left Ctrl was released
   [00:00:15.608,000] <inf> main: Key ESC was pressed
   [00:00:15.698,000] <inf> main: Key ESC was released

The sample recognizes all standard keyboard keys including:

* Letter keys (A-Z)
* Number keys (0-9)
* Function keys (F1-F12)
* Modifier keys (Shift, Ctrl, Alt, Meta)
* Special keys (Enter, Space, Backspace, Tab, ESC)
* Navigation keys (Arrow keys, Home, End, Page Up/Down)
* Numpad keys

Mouse Input
===========

When a USB mouse is connected and moved or clicked, you will see:

.. code-block:: console

   [00:00:08.162,000] <inf> max3421e: LS Device connected
   [00:00:08.233,000] <inf> usbh_dev: New device with address 1 state 2
   [00:00:08.246,000] <inf> usbh_dev: Configuration 1 bNumInterfaces 1
   [00:00:08.246,000] <inf> usbh_hid_boot: HID Boot Mouse detected
   [00:00:08.248,000] <inf> usbh_class: Class 'usbh_hid_boot_0' matches interface 0
   [00:00:15.248,000] <inf> main: Left button pressed
   [00:00:15.248,000] <inf> main: Mouse moved in X axis by 72
   [00:00:15.248,000] <inf> main: Mouse moved in Y axis by 127
   [00:00:16.248,000] <inf> main: Left button let go
   [00:00:16.248,000] <inf> main: Right button pressed
   [00:00:16.248,000] <inf> main: Middle button pressed
   [00:00:16.248,000] <inf> main: Mouse moved in X axis by 44
   [00:00:16.248,000] <inf> main: Mouse moved in Y axis by 127
   [00:00:17.248,000] <inf> main: Right button let go
   [00:00:17.248,000] <inf> main: Middle button let go
   [00:00:17.248,000] <inf> main: Mouse moved in Y axis by 125

The sample reports:

* Left, middle, and right button press and release events
* Mouse movement in X and Y axes with delta values

Notice that scroll wheel events are not supported as they are not defined in HID Boot

Configuration Options
*********************

This Sample
===========

- :kconfig:option:`CONFIG_SAMPLE_COLORED_OUTPUT` - ANSI Coloring of the output

HID Boot Protocol Driver
========================

- :kconfig:option:`CONFIG_USBH_HID_BOOT_CLASS` - Enable USB HID Boot Protocol class driver
- :kconfig:option:`CONFIG_USBH_HID_BOOT_INSTANCES_COUNT` - Maximum number of HID boot devices
- :kconfig:option:`CONFIG_USBH_HID_BOOT_LOG_LEVEL_` - HID boot driver log level

Problems
********

Latency
=======

If you notice significant latecny between pressing a key and seeing the output on the screen try to
enable :kconfig:option:`CONFIG_LOG_MODE_MINIMAL`. The full LOG system slows down the reporting.

More than one device is not being detected
==========================================

Make sure that :kconfig:option:`CONFIG_USBH_HID_BOOT_INSTANCES_COUNT` is higher or equal to the
amount of devices that you want to connect.
