import lldb
import os
import shlex
import optparse
import struct
import re

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
    'command script add -f xref.handle_command xref -h "Find references to code/data"')
"""
def get_addr_bytes(target, addr):
    byteorder = target.GetByteOrder()
    addr_size = target.GetAddressByteSize()

    if byteorder == lldb.eByteOrderLittle:
        endian = "<"
    else:
        endian = ">"

    if addr_size == 4:
        addr_bytes = struct.pack(endian + "l", addr)
    else:
        addr_bytes = struct.pack(endian + "q", addr)

    return addr_bytes
"""

def xrefs_in_region(target, addr, refs, region_info):
    start = region_info.GetRegionBase()
    end = region_info.GetRegionEnd()
    addr_size = target.GetAddressByteSize()
    process = target.GetProcess()
    error = lldb.SBError()
    while start + addr_size <= end:
        ptr = process.ReadPointerFromMemory(start, error)
        if error.Success():
            if ptr == addr:
                refs.append(start)
                start += addr_size
            else:
                start += 1
        else:
            start += 1

    if region_info.IsExecutable():
        start = region_info.GetRegionBase()
        xrefs_from_ins(target, addr, start, end, refs)

def resolve_ins_ref_addr(target, base_addr, ins):
    matches = re.search('\*(?P<pc>[+-]?0x[0-9a-f]+)\(%rip\)', ins.GetOperands(target))
    if matches == None:
        return None

    return (ins.GetAddress().GetLoadAddress(target) + ins.GetByteSize()) + int(matches.group('pc'), 0)

def resolve_branch_ref_addr(target, base_addr, ins):
    resolved_addr = None
    process = target.GetProcess()
    # relative, indirect call/jump
    # 0x500|*-0x500(%rip)
    matches = re.search('(?P<imm>[+-]?0x[0-9a-f]+)|\*(?P<pc>[+-]?0x[0-9a-f]+)\(%rip\)', ins.GetOperands(target))
    if matches == None:
        return None
    if matches.group('pc'):
            # next pc + offset 
            addr_indirect = (ins.GetAddress().GetLoadAddress(target) + ins.GetByteSize()) + int(matches.group('pc'), 0)
            error = lldb.SBError()
            addr_indirect = process.ReadPointerFromMemory(addr_indirect, error)
            if error.Success():
                resolved_addr = addr_indirect
    else:
        resolved_addr = base_addr + int(matches.group('imm'), 0)

    """ print ins
    if resolved_addr != None:
        print "resolved addr 0x%x" % resolved_addr
    """
    return resolved_addr

def xrefs_from_ins(target, addr, start, end, refs):
    while start < end: 
        dis_addr = target.ResolveLoadAddress(start)
        ins_dis = target.ReadInstructions(dis_addr, 1024)
        base_addr = None

        if ins_dis.GetSize() <= 0:
            start += 1
            continue

        for ins in ins_dis:
            if base_addr == None:
                base_addr = dis_addr.GetLoadAddress(target) - ins.GetAddress().GetFileAddress()

            if ins.DoesBranch() and ins.GetOperands(target) != "":
                ref_addr = resolve_branch_ref_addr(target, base_addr, ins)
            else:
                ref_addr = resolve_ins_ref_addr(target, base_addr, ins)

            if ref_addr == addr:
                refs.append(start)

            start += ins.GetByteSize()
def handle_command(debugger, command, exe_ctx, result, internal_dict):
    command_args = shlex.split(command, posix=False)
    usage = "usage: %prog [options] address"
    parser = optparse.OptionParser(usage=usage, prog="xref")
    target = exe_ctx.target 
    process = target.GetProcess()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        result.SetError(parser.usage)
        return
    if not process.is_alive:
        result.SetError("process not exist")
        return
    try:
        addr = int(args[0], 16)
    except:
        addr = int(args[0])
    regions = process.GetMemoryRegions()
    refs = []
    for i in range(regions.GetSize()):
        region_info = lldb.SBMemoryRegionInfo()
        regions.GetMemoryRegionAtIndex(i, region_info)
        if region_info.IsReadable():
            region_perms = "r"
        else:
            region_perms = "-"

        if region_info.IsWritable():
            region_perms += "w"
        else:
            region_perms += "-"
        if region_info.IsExecutable():
            region_perms += "x"
        else:
            region_perms += "-"
        print("Searching in the memory region [0x%x-0x%x %s]" % (region_info.GetRegionBase(), region_info.GetRegionEnd(), region_perms))
        xrefs_in_region(target, addr, refs, region_info)
      
    print("%d references found it of 0x%x" % (len(refs), addr))
    for ref in refs:
        resol_addr = target.ResolveLoadAddress(ref)
        print("\t* 0x%x %s" % (ref, resol_addr.section))
