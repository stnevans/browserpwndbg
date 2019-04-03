#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command to what page a virtual address is contained by.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb
import six
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.elf
import pwndbg.vmmap


parser = argparse.ArgumentParser()
parser.description = '''Locate the page a virtual address resides in.'''

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def locate(address=0x0):
    if address == 0x0:
        print("Invalid argument provided. Please give a valid address such as 0x")
        return
    pages = list(filter(None, pwndbg.vmmap.get()))
    print(M.legend())

    
    for page in pages:
        if address >= page.vaddr and address <= page.vaddr + page.memsz:
            texta = str(page) + " + " + hex(int(address-page.vaddr))
            print(M.get(page.vaddr, text=texta))

    if pwndbg.qemu.is_qemu():
        print("\n[QEMU target detected - locate result might not be accurate; see `help vmmap`]")
