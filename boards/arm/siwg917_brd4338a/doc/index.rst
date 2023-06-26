.. _sigw917_brd4338a:

SiWG917 BRD4338A
################

Overview
========

The BRD4338a board is a platform based on the SiLabs SiWG917 SoC.

Building and flashing
=====================

The sample application :ref:`hello_world` is used for this example. Build the Zephyr kernel and
application:

.. zephyr-app-commands::
   :zephyr-app: samples/hello_world
   :board: siwg917_brd4338a
   :goals: build

Connect your device to your host computer using the USB port and you should see a USB connection.
The simplest way to flash the board is by using the `west flash` command, which runs
`Simplicity Commander`_ in unattended mode and passes all the necessary arguments to it.

- If Simplicity Commander is installed in the system and the directory in which `commander`
  executable is located is present in the `PATH` environment variable:

  .. code-block:: console

   west flash

- Otherwise, one should specify full path to the `commander` executable:

  .. code-block:: console

   west flash --commander <path_to_commander_directory>/commander

- In case several `J-Link`_ adapters are connected, you must specify serial number of the adapter which
  should be used for flashing:

  .. code-block:: console

   west flash --dev-id <J-Link serial number>

Open a serial terminal (e.g. `picocom`_) with the following settings:

- Speed: 115200
- Data: 8 bits
- Parity: None
- Stop bits: 1

Reset the board and you should be able to see on the corresponding Serial Port (EXP Header pins 4
and 6 for Tx and Rx, respectively) the following
message:

.. code-block:: console

   Hello World! siwg917_brd4338a

References
==========

.. target-notes::

.. _picocom:
   https://github.com/npat-efault/picocom

.. _J-Link:
   https://www.segger.com/jlink-debug-probes.html

.. _Simplicity Commander:
   https://www.silabs.com/developers/mcu-programming-options
