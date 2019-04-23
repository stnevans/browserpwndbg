#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
<<<<<<< HEAD
Find a leak relative to some address.
=======
Find a chain of leaks given some starting address.
>>>>>>> 93aabaa5fb9aa806eab8cd5017739673500c1cac
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
<<<<<<< HEAD

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


config_arrow_right = theme.Parameter('chain-arrow-right', '—▸', 'right arrow of chain formatting')
arrow_right = C.arrow(' %s ' % config_arrow_right)

    if not page is None:
        if not addr in visited_map:
            return ""
        
        parent_info = visited_map[addr]
            return ""
        
        parentInfo = visitedMap[addr]
        parent = parentInfo[0]
        parent_base_addr = parentInfo[1]
        curText = hex(parent_base_addr) + "+"+hex(parent-parent_base_addr)
        if parent_base_addr == addr:
            return ""
        return get_rec_addr_string(parent_base_addr,visitedMap) + M.get(parent_base_addr,text=curText)+arrow_right
    else:
        return ""

#Utility function to get a page from an address.
def getPage(address):
    return pwndbg.vmmap.find(address)

#Useful for debugging. Prints a map of child -> (parent, parent_start)
def dbg_print_map(maps):
    for child, parentInfo in maps.items():
        print(hex(child) + "("+hex(parentInfo[0])+","+hex(parentInfo[1])+")")
=======
from queue import *

import gdb

import pwndbg.color.chain as C
import pwndbg.color.memory as M
import pwndbg.color.theme as theme
import pwndbg.commands
import pwndbg.vmmap
from pwndbg.chain import config_arrow_right


# Used to recursively print the pointer chain. 
# addr is a pointer. It is taken to be a child pointer.
# visited_map is a map of children -> (parent,parent_start)
def get_rec_addr_string(addr,visited_map):
    page = pwndbg.vmmap.find(addr)
    arrow_right = C.arrow(' %s ' % config_arrow_right)

    if not page is None:
        if not addr in visited_map:
            return ""
        
        parent_info = visited_map[addr]
        parent = parent_info[0]
        parent_base_addr = parent_info[1]
        if parent - parent_base_addr < 0:
            curText = hex(parent_base_addr) + hex(parent - parent_base_addr)
        else:
            curText = hex(parent_base_addr) + "+" + hex(parent - parent_base_addr)
        if parent_base_addr == addr:
            return ""
        return get_rec_addr_string(parent_base_addr,visited_map) + M.get(parent_base_addr,text=curText) + arrow_right
    else:
        return ""


# Useful for debugging. Prints a map of child -> (parent, parent_start)
def dbg_print_map(maps):
    for child, parent_info in maps.items():
        print("0x%x + (0x%x, 0x%x)" % (child, parent_info[0], parent_info[1]))
>>>>>>> 93aabaa5fb9aa806eab8cd5017739673500c1cac

parser = argparse.ArgumentParser()
parser.description = """
Attempt to find a leak chain given a starting address. Scans memory near the given address, looks for pointers, 
and continues that process to attempt to find leaks.\n
<<<<<<< HEAD
Example: leakfind $rsp 0x48 6. This would look for any chains of leaks that begins near $rsp, is never 0x48 bytes further from a known pointer, 
and is a maximum length of 6.\n
"""
parser.add_argument("address",help="Starting address to find a leak chain from.")
parser.add_argument("max_offset",default=0x48,nargs="?",help="Max Offset to add to addresses when looking for leak.")
parser.add_argument("max_depth",default=0x4,nargs="?",help="Maximum depth to follow pointers to.")
parser.add_argument("page_name",type=str,nargs="?",default=None,help="Substring required to be part of the name of any found pages")
parser.add_argument("stride",nargs="?",default=0x1,help="Stride to add to add between pointers considered")
parser.add_argument("pointer_tagging",default=True,nargs="?",type=bool,help="Enable pointer tagging")

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def leakfind(address=-1,max_offset=0x40,max_depth=0x4,page_name=None,stride=0x1,pointer_tagging=True):
    if address == -1:
        print("No starting address provided. Please run leakfind -h for more information.")
        return

    foundPages = getPage(address)

    if not foundPages:
        print("Starting address is not mapped. Please run leakfind -h for more information.")
        return

    if not pwndbg.memory.peek(address):
        print("Unable to read from starting address. Please run leakfind -h for more information.")
        return

    max_depth=int(max_depth)
    #Just a warning
=======
Example: leakfind $rsp --page_name=filename --max_offset=0x48 --max_depth=6. This would look for any chains of leaks that point to a section in filename which begin near $rsp, are never 0x48 bytes further from a known pointer, 
and are a maximum length of 6\n
"""
parser.add_argument("address",help="Starting address to find a leak chain from")
parser.add_argument("-p", "--page_name", type=str, nargs="?", default=None, help="Substring required to be part of the name of any found pages")
parser.add_argument("-o", "--max_offset", default=0x48, nargs="?", help="Max offset to add to addresses when looking for leak")
parser.add_argument("-d", "--max_depth", default=0x4, nargs="?", help="Maximum depth to follow pointers to")
parser.add_argument("-s", "--step", nargs="?", default=0x1, help="Step to add between pointers so they are considered. For example, if this is 4 it would only consider pointers at an offset divisible by 4 from the starting pointer")
parser.add_argument('--negative_offset',nargs="?", default=0x0, help="Max negative offset to search before an address when looking for a leak")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def leakfind(address=None, page_name=None, max_offset=0x40, max_depth=0x4, stride=0x1, negative_offset=0x0):
    if address is None:
        raise argparse.ArgumentTypeError('No starting address provided.')

    foundPages = pwndbg.vmmap.find(address)

    if not foundPages:
        raise argparse.ArgumentTypeError('Starting address is not mapped.')

    if not pwndbg.memory.peek(address):
        raise argparse.ArgumentTypeError('Unable to read from starting address.')

    max_depth = int(max_depth)
    # Just warn the user that a large depth might be slow.
    # Probably worth checking offset^depth < threshold. Do this when more benchmarking is established.
>>>>>>> 93aabaa5fb9aa806eab8cd5017739673500c1cac
    if max_depth > 8:
        print("leakfind may take a while to run on larger depths.")
    
    stride = int(stride)
<<<<<<< HEAD
    address=int(address)
    max_offset = int(max_offset)

    if pointer_tagging:
        address=address & 0xfffffffffffffffe

    
    #The below map stores a map of child address->(parent_address,parent_start_address)
    #In the above tuple, parent_address is the exact address with a pointer to the child adddress.
    #parent_start_address is an address that a previous address pointed to.
    #We need to store both so that we can nicely create our leak chain.
    visitedMap = {}
    visitedSet = set()
    visitedSet.add(int(address))
    addressQueue = Queue()
    addressQueue.put(int(address))
    depth = 0
    timeToDepthIncrease=0

    #Run a bfs
    #TODO look into performance gain from checking if an address is mapped before calling pwndbg.memory.pvoid()
    #TODO also check using pwndbg.memory.read for possible performance boosts.
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

    #A map of chain_length->list of lines. Used to let us print in a somewhat nice manner.
    outputMap = {}

    for child, unused in visitedMap.items():
        childPage = getPage(child)
        if (not childPage == None) and not (childPage.vaddr == foundPages.vaddr):
            if not page_name == None:
                if not page_name in childPage.objfile:
                    continue
            line = get_rec_addr_string(child,visitedMap) + M.get(child) + " " + M.get(child,text=childPage.objfile)
            chain_length = line.count(arrow_right)
            if chain_length in outputMap:
                outputMap[chain_length].append(line)
            else:
                outputMap[chain_length]=[line]
            #outputMap[line.count(arrow_right)]=line
            #print(line)

    #Output sorted by length of chain
    for chain_length in outputMap:
        for line in outputMap[chain_length]:
=======
    address = int(address)
    max_offset = int(max_offset)
    negative_offset = int(negative_offset)
    
    # The below map stores a map of child address->(parent_address,parent_start_address)
    # In the above tuple, parent_address is the exact address with a pointer to the child adddress.
    # parent_start_address is an address that a previous address pointed to.
    # We need to store both so that we can nicely create our leak chain.
    visited_map = {}
    visited_set = {int(address)}
    address_queue = Queue()
    address_queue.put(int(address))
    depth = 0
    time_to_depth_increase = 0

    # Run a bfs
    # TODO look into performance gain from checking if an address is mapped before calling pwndbg.memory.pvoid()
    # TODO also check using pwndbg.memory.read for possible performance boosts.
    while address_queue.qsize() > 0 and depth < max_depth:
        if time_to_depth_increase == 0:
            depth = depth + 1
            time_to_depth_increase = address_queue.qsize()
        cur_start_addr = address_queue.get()
        time_to_depth_increase -= 1
        for cur_addr in range(cur_start_addr - negative_offset, cur_start_addr + max_offset, stride):
            try:
                result = int(pwndbg.memory.pvoid(cur_addr))
                if result in visited_map or result in visited_set:
                    continue
                visited_map[result] = (cur_addr, cur_start_addr) # map is of form child->(parent,parent_start)
                address_queue.put(result)
                visited_set.add(result)
            except gdb.error:
                # That means the memory was unmapped. Just skip it if we can't read it. 
                break

    # A map of length->list of lines. Used to let us print in a somewhat nice manner.
    output_map = {}
    arrow_right = C.arrow(' %s ' % config_arrow_right)

    for child in visited_map:
        child_page = pwndbg.vmmap.find(child)
        if child_page is not None:
            if page_name is not None and page_name not in child_page.objfile:
                    continue
            line = get_rec_addr_string(child,visited_map) + M.get(child) + " " + M.get(child,text=child_page.objfile)
            chain_length = line.count(arrow_right)
            if chain_length in output_map:
                output_map[chain_length].append(line)
            else:
                output_map[chain_length] = [line]


    # Output sorted by length of chain
    for chain_length in output_map:
        for line in output_map[chain_length]:
>>>>>>> 93aabaa5fb9aa806eab8cd5017739673500c1cac
            print(line)

    if pwndbg.qemu.is_qemu():
        print("\n[QEMU target detected - leakfind result might not be accurate; see `help vmmap`]")
