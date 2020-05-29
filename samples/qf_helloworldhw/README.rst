.. _hello_world:

Hello World
###########

Overview
********
The Hello World example can be used on Quick Feather board. 
It prints 'Hello World' to the console using EOS S3 H/W UART and 
blinks green on the board. It uses FPGA IP to blink the LED.

Building and Running
********************

This project can be built and executed
on Quick Feather as follows:

.. zephyr-app-commands::
   :zephyr-app: samples/qf_hello_worldhw
   :host-os: unix
   :board: quick feather
   :goals: run
   :compact:

Sample Output
=============

.. code-block:: console

    Hello World!

