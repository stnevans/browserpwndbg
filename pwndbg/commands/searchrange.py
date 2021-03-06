#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command to find a pointer to another memory region.
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
import pwndbg.memory

parser = argparse.ArgumentParser()
parser.description = '''Find a pointer to another page. Searches a memory region.'''

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def searchrange(search_start_address=0x0,search_end_address=0x0,page_start_address=0x0,page_end_address=0x0):
    if page_end_address == 0x0:
        print("Invalid arguments provided. Please provide 4 addresses.\nThe format is search_start search_end page_start page_end")
        return
    if page_start_address >= page_end_address:
        print("The page start address should be less than the page end address")
    if search_start_address >= search_end_address:
        print("The search start address should be less than the search end address. " + hex(search_start_address) + "-" + hex(search_end_address    ))
    
    pages = pwndbg.vmmap.get()
    realPages = []
    for page in pages:
        if page.vaddr >= search_end_address:
            break
        if page.vaddr >= search_start_address:
            realPages.append(page)
            if page.vaddr+page.memsz >= search_end_address:
                break
    for page in realPages:
        start = page.start if page.start > search_start_address else search_start_address
        end = page.start +page.memsz if page.start+page.memsz < search_end_address else search_end_address
        #start = page.start
        #end = page.end
        end = int(end)
        start = int(start)
        if not pwndbg.memory.peek(start):
            print("Unable to read memory in one region.")
            break
        #Test pwndbg.arch.ptrsize
        for addr in range(start,end,pwndbg.arch.ptrsize):
            result = pwndbg.memory.pvoid(addr)
            if result >= page_start_address and result <= page_end_address:
                print(pwndbg.chain.format(addr))




    
    if pwndbg.qemu.is_qemu():
        print("\n[QEMU target detected - searchrange result might not be accurate; see `help vmmap`]")
