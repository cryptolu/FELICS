#!/usr/bin/python

#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2015 University of Luxembourg
#
# Written in 2015 by Yann Le Corre <yann.lecorre@uni.lu> and 
# Daniel Dinu <dumitru-daniel.dinu@uni.lu>
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

from __future__ import print_function
import sys
import serial
import argparse


DefaultDevice = '/dev/ttyACM0'
DefaultTimeout = 1
DefaultBaudRate = 115200


class ArmBoard(object):
    def __init__(self, device=DefaultDevice, baud_rate=DefaultBaudRate, timeout=DefaultTimeout):
        self.device = device
        self.baud_rate = baud_rate
        self.timeout = timeout
        self.port = None

    def open(self):
        self.port = serial.Serial(
            port=self.device,
            baudrate=self.baud_rate,
            bytesize=8,
            parity='N',
            stopbits=1,
            xonxoff=0,
            rtscts=0,
            dsrdtr=0,
            timeout=self.timeout
        )

    def close(self):
        self.port.close()

    def drain(self):
        if None == self.port:
            self.open()
            was_open = False
        else:
            self.close()
            self.open()
            was_open = True
        while True:
            c = self.port.read(1024)
            if 1024 != len(c):
                break
        self.close()
        if was_open:
            self.open()

    def read_all(self):
        msg = ''
        while True:
            c = self.port.read(1024)
            msg += c
            if len(c) < 1024:
                break
        return msg

if '__main__' == __name__:
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     description='Open a serial connection to a target device and print the output.')
    parser.add_argument('-d', '--device', default=DefaultDevice, help='Specifies the serial port to which the target '
                                                                      'device is connected to')
    parser.add_argument('-b', '--baud_rate', type=int, default=DefaultBaudRate, help='The baud rate of the serial port')
    parser.add_argument('-t', '--timeout', type=int, default=DefaultTimeout, help='The timeout of the serial port')
    arguments = parser.parse_args()

    board = ArmBoard(device=arguments.device, baud_rate=arguments.baud_rate, timeout=arguments.timeout)
    board.open()
    board.drain()
    print(board.read_all())
    board.close()
