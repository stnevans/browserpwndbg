#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Find a leak relative to some address.
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
import pwndbg.color.theme as theme
import pwndbg.color.chain as C
from queue import *

#Utility function to get a page from an address.
#Probably should be replaced with pwndbg.vmmap.find(address)
def getPage(address):
    pages = list(filter(None, pwndbg.vmmap.get()))
    for page in pages:
        if address >= page.vaddr and address <= page.vaddr + page.memsz:
            return page
    return None


config_arrow_right = theme.Parameter('chain-arrow-right', '—▸', 'right arrow of chain formatting')
arrow_right = C.arrow(' %s ' % config_arrow_right)


#Used to recursively print the pointer chain. 
#addr is a pointer. It is taken to be a child pointer.
#visitedMap is a map of children -> (parent,parent_start)
def get_rec_addr_string(addr,visitedMap):
    page = getPage(addr)
    if not (page == None):
        if not addr in visitedMap:
            return ""
        
        parentInfo = visitedMap[addr]
        parent = parentInfo[0]
        parent_base_addr = parentInfo[1]
        curText = hex(parent_base_addr) + "+"+hex(parent-parent_base_addr)
        if parent_base_addr == addr:
            return ""
        #print("[DBG] " + hex(addr) + " parent " + hex(parent_base_addr))
        return get_rec_addr_string(parent_base_addr,visitedMap) + M.get(parent_base_addr,text=curText)+arrow_right
    else:
        return ""

#Useful for debugging. Prints a map of child -> (parent, parent_start)
def dbg_print_map(maps):
    for child, parentInfo in maps.items():
        print(hex(child) + "("+hex(parentInfo[0])+","+hex(parentInfo[1])+")")

parser = argparse.ArgumentParser()
parser.description = 'Find a leak by doing a BFS with addresses near a given address'
parser.add_argument("address",help="Address to find a leak from.")
parser.add_argument("max_offset",default=0x40,nargs="?",help="Max Offset to add to addresses when looking for leak.")
parser.add_argument("max_depth",default=0x4,nargs="?",help="Maximum depth to follow pointers to.")
parser.add_argument("binary_name",type=str,nargs="?",default=None,help="Substring required to be part of the name of any found pages")
parser.add_argument("pointer_tagging",default=True,nargs="?",type=bool,help="Enable pointer tagging")

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def leakfind(address=0x0,max_offset=0x40,max_depth=0x4,binary_name=None,pointer_tagging=True):
    if address == 0x0:
        print("Invalid argument provided. Please give a valid address such as 0x")
        return

    foundPages = getPage(address)

    if not foundPages:
        print("Unable to find starting address.")
        return

    if not pwndbg.memory.peek(address):
        print("Unable to read from starting address")
    address=int(address)
    max_offset = int(max_offset)
    max_depth = int(max_depth)

    if pointer_tagging:
        address=address & 0xfffffffffffffffe

    
    visitedMap = {}
    visitedSet = set()
    visitedSet.add(int(address))
    addressQueue = Queue()
    addressQueue.put(int(address))
    depth = 0
    timeToDepthIncrease=0

    #Run a bfs
    #TODO look into performance gain from checking if an address is mapped before calling pwndbg.memory.pvoid()
    while addressQueue.qsize() > 0 and depth < max_depth:
        if timeToDepthIncrease == 0:
            depth=depth+1
            timeToDepthIncrease=addressQueue.qsize()
        cur_start_addr = addressQueue.get()
        timeToDepthIncrease-=1
        for cur_addr in range(cur_start_addr,cur_start_addr+max_offset,1):
            try:
                result = int(pwndbg.memory.pvoid(cur_addr))
                if result in visitedMap:
                    continue
                if pointer_tagging:
                    result = result & 0xfffffffffffffffe
                if result in visitedSet:
                    continue
                visitedMap[result]=(cur_addr,cur_start_addr) #map is of form child->(parent,parent_start)
                addressQueue.put(result)
                visitedSet.add(result)
            except gdb.error:
                #That means the memory was unreadable. Just skip it if we can't read it. 
                break

    for child, unused in visitedMap.items():
        childPage = getPage(child)
        if (not childPage == None) and not (childPage.vaddr == foundPages.vaddr):
            if not binary_name == None:
                if not binary_name in childPage.objfile:
                    continue
            print(get_rec_addr_string(child,visitedMap) + M.get(child) + " " + M.get(child,text=childPage.objfile))
    
    if pwndbg.qemu.is_qemu():
        print("\n[QEMU target detected - leakfind result might not be accurate; see `help vmmap`]")
