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

def get_pc_reg_name(debugger):
    interpreter = debugger.GetCommandInterpreter()
    rto = lldb.SBCommandReturnObject()
    interpreter.HandleCommand("reg read pc", rto)
    if not rto.Succeeded() or not rto.GetOutput():
      raise Exception("failed to read the program counter register")
    matches = re.search('([a-zA-Z0-9]+)\s*=\s*0x', rto.GetOutput())
    if not matches:
      raise Exception("failed to read the program counter register")

    return matches.group(1)


def get_addr_from_expression(target, expression):
    value = target.EvaluateExpression(expression)

    return value.GetValueAsUnsigned()

def xrefs_in_region(target, addr, refs, region_info):
    start = region_info.GetRegionBase()
    end = region_info.GetRegionEnd()
    addr_size = target.GetAddressByteSize()
    process = target.GetProcess()
    error = lldb.SBError()
    refs_count = len(refs)
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

    return len(refs) - refs_count

def resolve_ins_ref_addr(target, base_addr, ins):
    matches = re.search('\*(?P<pc>[+-]?0x[0-9a-f]+)\(%' + pc_reg_name + '\)', ins.GetOperands(target))
    if matches == None:
        return None

    return (ins.GetAddress().GetLoadAddress(target) + ins.GetByteSize()) + int(matches.group('pc'), 0)

def resolve_branch_ref_addr(target, base_addr, ins):
    resolved_addr = None
    process = target.GetProcess()
    # relative, indirect call/jump
    # 0x500|*-0x500(%rip)
    matches = re.search('(?P<imm>[+-]?0x[0-9a-f]+)|\*(?P<pc>[+-]?0x[0-9a-f]+)\(%' + pc_reg_name + '\)', ins.GetOperands(target))
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
    global pc_reg_name

    max_region_size = 10*1024*1024
    command_args = shlex.split(command, posix=False)
    usage = "usage: xref [options] address/expression"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-e", "--expression",
                  action="store", dest="expression",
                  help="evaluate expression for get an memory address")
    parser.add_option("-m", "--max-region-size",
                  action="store", dest="max_region_size",
                  help="search in the memory region with a max size")
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
    if options.expression:
        addr = get_addr_from_expression(target, options.expression)
    else:
        try:
            addr = int(args[0], 16)
        except:
            addr = int(args[0])
    regions = process.GetMemoryRegions()
    refs = []
    pc_reg_name = get_pc_reg_name(debugger)
    if options.max_region_size:
        max_region_size = int(options.max_region_size, 0)
    print("Searching external references to 0x%x" % addr)
    for i in range(regions.GetSize()):
        region_info = lldb.SBMemoryRegionInfo()
        regions.GetMemoryRegionAtIndex(i, region_info)
        if (region_info.GetRegionEnd() - region_info.GetRegionBase()) > max_region_size:
            continue
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
        refs_count = xrefs_in_region(target, addr, refs, region_info)
        if refs_count > 0:
            print("\t* %d references found it" % refs_count)

    print("%d references count" % len(refs))
    for ref in refs:
        resol_addr = target.ResolveLoadAddress(ref)
        print("\t* 0x%x %s" % (ref, resol_addr.section))
