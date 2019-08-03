#!/usr/bin/env python3
#############################################################################
# Filename    : safe_gpio_sim.py
# Description : GPIO Module for CSAFE safe
# Author      : Sean House
# modification: 19 Jan 2019
########################################################################
#import RPi.GPIO as GPIO
from time import sleep
from typing import Tuple
import logging
import os
from settings import safe_datadir

# GPIO Pins  GPIO.BOARD Numbering
GPIO4 = 7
GPIO17 = 11
GPIO18 = 12
GPIO16 = 36
GPIO20 = 38
GPIO21 = 40
GPIO22 = 15
GPIO23 = 16
GPIO24 = 18
GPIO25 = 22
GPIO27 = 13


# Defines the data bit that is transmitted preferentially in the shiftOut function.
LSBFIRST = 1
MSBFIRST = 2
lock_switch_pin = GPIO21
req_switch_pin = GPIO4
hinge_switch_pin = GPIO16
lid_switch_pin = GPIO20
dataPin = GPIO17  # DS Pin of 74HC595(Pin14)
latchPin = GPIO27  # ST_CP Pin of 74HC595(Pin12)
clockPin = GPIO22  # CH_CP Pin of 74HC595(Pin11)
motorPins = (GPIO18, GPIO23, GPIO24, GPIO25)
advance_step = (0x01, 0x02, 0x04, 0x08)  # define power supply order for coil for rotating anticlockwise
retract_step = (0x08, 0x04, 0x02, 0x01)  # define power supply order for coil for rotating clockwise

light_state = 0


def setup_gpio(callback):
    """

    :return:
    """
    # GPIO.setwarnings(False)
    # GPIO.setmode(GPIO.BOARD)  # Number GPIOs by its physical location
    # GPIO.setup(dataPin, GPIO.OUT)
    # GPIO.setup(latchPin, GPIO.OUT)
    # GPIO.setup(clockPin, GPIO.OUT)
    # GPIO.setup(lock_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    # GPIO.setup(hinge_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    # GPIO.setup(lid_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    # GPIO.setup(req_switch_pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    # for pin in motorPins:
    #     GPIO.setup(pin, GPIO.OUT)
    # GPIO.add_event_detect(req_switch_pin, GPIO.FALLING, callback=callback, bouncetime=900)
    pass
    return


# def moveOneCycle(direction: str, ms: int):
#     """
#     as for four phase stepping motor, four steps is a cycle. the function is used to drive the
#     stepping motor clockwise or anticlockwise to take four steps
#
#     :param direction: the direction of movement; 'R' = Retract (Unlock), 'A' = Advance (Lock)
#     :param ms:
#     :return:
#     """
#     for j in range(0, 4, 1):  # cycle for power supply order
#         for i in range(0, 4, 1):  # assign to each pin, a total of 4 pins
#             if (direction == 'R'):  # power supply order RETRACT
#                 GPIO.output(motorPins[i], ((retract_step[j] == 1 << i) and GPIO.HIGH or GPIO.LOW))
#             else:  # power supply order ADVANCE
#                 GPIO.output(motorPins[i], ((advance_step[j] == 1 << i) and GPIO.HIGH or GPIO.LOW))
#         if ms < 3:  # the delay can not be less than 3ms, otherwise it will exceed speed limit of the motor
#             ms = 3
#         sleep(ms * 0.001)
#   return


# def moveLock(direction: str, distance: int, ms: int = 3):
#     """
#     continuous rotation function, the parameter steps specifies the distance to move
#     :param direction: R or A
#     :param distance: in mm
#     :param ms: speed, default = 3ms delay (max speed)
#     :return:
#     """
#     for i in range(int(distance * 21)):  # 21 steps is 1 mm of movement
#         moveOneCycle(direction, ms)
#     return


# shiftOut function, use bit serial transmission.
# def shift_bits(dPin, cPin, order, val):
#     for i in range(0, 8):
#         GPIO.output(cPin, GPIO.LOW);
#         if (order == LSBFIRST):
#             GPIO.output(dPin, (0x01 & (val >> i) == 0x01) and GPIO.HIGH or GPIO.LOW)
#         elif (order == MSBFIRST):
#             GPIO.output(dPin, (0x80 & (val << i) == 0x80) and GPIO.HIGH or GPIO.LOW)
#         GPIO.output(cPin, GPIO.HIGH)
#     return


def set_lights(n: str, safe: str):
    """
    Set the RPi lights to the parameters specified OFF, Green or 1-5 Red
    :param n:
    :return:
    """
    # light_settings = {'OFF': 0x00,
    #                   'G': 0x80,
    #                   '1R': 0x40,
    #                   '2R': 0x60,
    #                   '3R': 0x70,
    #                   '4R': 0x78,
    #                   '5R': 0x7C,
    #                   'ERR': 0x54}
    # GPIO.output(latchPin, GPIO.LOW) # Set 74HC595 to receive
    # shift_bits(dataPin, clockPin, LSBFIRST, light_settings[n])  # Shift the relevant definition byte to the 74HC595
    # GPIO.output(latchPin, GPIO.HIGH)    # Lock the 74HC595 / show the lights
    with open(os.path.join(safe_datadir.format(safe), 'lights.txt'), 'w') as fo:
        fo.write(n + '\n')
    return


def lock_safe(safe: str):
    """
    Check switches are closed then lock the safe
    :return:
    """
    # while any([GPIO.input(hinge_switch_pin) == GPIO.HIGH, GPIO.input(lid_switch_pin) == GPIO.HIGH]):
    #     cannot_lock()
    #     sleep(0.5)
    # print('Locking now....')
    # while GPIO.input(lock_switch_pin) == GPIO.HIGH:
    #     moveLock('A', 1)
    with open(os.join(safe_datadir.format(safe), 'locked.txt'), 'w') as fo:
        fo.write('LOCKED\n')
    return


# def cannot_lock():
#     """
#     Display flashing lights if safe cannot be locked
#     :return:
#     """
#     seq = ['5R', 'OFF', '5R', 'OFF', '5R', 'OFF']
#     for i in seq:
#         set_lights(i)
#         sleep(0.1)
#     print('Diagnostic message:  Cannot lock')

def unlock_safe(safe: str):
    """
    Unlock the safe by withdrawing the bar a set distance
    :return:
    """
    #moveLock('R', 16)
    with open(os.path.join(safe_datadir.format(safe), 'locked.txt'), 'w') as fo:
        fo.write('UNLOCKED\n')
    return


def get_safe_status(safe: str) -> Tuple[bool, bool, bool]:
    """
    Query the 'Virtual' microswitches to determine the safe status
    :return:
    """

    with open(os.path.join(safe_datadir.format(safe),'status.txt'), 'r') as fi:
        status_lst = fi.readline().strip().split(',')
        status = status_lst[0] == 'TRUE', status_lst[1] == 'TRUE', status_lst[2] == 'TRUE'
    # status = GPIO.input(lid_switch_pin) == GPIO.LOW, \
    #          GPIO.input(hinge_switch_pin) == GPIO.LOW, \
    #          GPIO.input(lock_switch_pin) == GPIO.LOW
    logging.debug(f'Safe status = {safe}/{status}')
    print(f'Safe status = {safe}/{status}')
    return status


def button_pressed(channel):
    """
    Interrupt call when button has been pressed - this routine only used in test case
    see 'button_pushed' routine in main prog for real usage
    """
    global light_state
    seq = ['5R', '4R', '3R', '2R', '1R', 'OFF', 'G']
    print(get_safe_status())
    light_state += 1
    light_state = light_state % 7
    print('Setting lights to {}'.format(seq[light_state]))
    set_lights(seq[light_state])
    return


def destroy_gpio():  # When 'Ctrl+C' is pressed, the function is executed.
    """

    :return:
    """
    set_lights('OFF')
    #GPIO.cleanup()
    return


if __name__ == '__main__':  # Program starting from here
    print('Program is starting...')
    #setup_gpio(button_pressed)
    try:
        while True:
            sleep(5)
    except KeyboardInterrupt:
        destroy_gpio()
