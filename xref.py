import lldb
import os
import shlex
import optparse
import struct
import re

max_region_size = 40 * 1024 * 1024
debug = False

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
    error = value.GetError()

    if not error.Success():
        raise Exception("invalid expresion " + expression)

    return value.GetValueAsUnsigned()

def do_xrefs_in_region(target, addr, refs, region_info):
    start = region_info['start']
    end = region_info['end']
    addr_size = target.GetAddressByteSize()
    process = target.GetProcess()
    error = lldb.SBError()
    refs_count = len(refs)
    while start + addr_size <= end:
        ptr = process.ReadPointerFromMemory(start, error)
        if error.Success():
            if ptr == addr:
                refs.add(start)
                start += addr_size
            else:
                start += 1
        else:
            start += 1

    if region_info['perms'].find('x') != -1:
        start = region_info['start']
        xrefs_from_ins(target, addr, start, end, refs)

    return len(refs) - refs_count

def resolve_ins_ref_addr(target, ins):
    global pc_reg_name

    matches = re.search('(?P<pc>[+-]?0x[0-9a-f]+)\(%' + pc_reg_name + '\)', ins.GetOperands(target))

    return (ins.GetAddress().GetLoadAddress(target) + ins.GetByteSize()) + int(matches.group('pc'), 0) if matches else None

def resolve_branch_ref_addr(target, ins):
    global pc_reg_name

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
        resolved_addr = int(matches.group('imm'), 0)

    return resolved_addr

def xrefs_from_ins(target, addr, start, end, refs):
    sections_region = []
    module = target.ResolveLoadAddress(start).GetModule()
    for section in module.section_iter():
        load_addr = section.GetLoadAddress(target)
        if load_addr >= start and load_addr < end:
            if section.GetNumSubSections() > 0:
                for subsection in section:
                    if subsection.GetSectionType() == lldb.eSectionTypeCode:
                        sections_region.append(subsection)
            else:
                sections_region.append(section)

    sections_region.sort(key=lambda section : section.GetLoadAddress(target))
    section_idx = 0
    if len(sections_region) > 0:
        section = sections_region[0]
        section_start_addr = section.GetLoadAddress(target)
        section_end_addr = section_start_addr + section.GetByteSize()
        section_idx = 0

    section_current = None
    while start < end: 
        dis_addr = target.ResolveLoadAddress(start)
        ins_dis = target.ReadInstructions(dis_addr, 10)

        if ins_dis.GetSize() == 0:
            start += 1
        for ins in ins_dis:
            #if base_addr == None:
            #    base_addr = module.ResolveFileAddress(0).GetLoadAddress(target);
            if ins.DoesBranch() and ins.GetOperands(target) != "":
                ref_addr = resolve_branch_ref_addr(target, ins)
            else:
                ref_addr = resolve_ins_ref_addr(target, ins)

            if ref_addr == addr:
                refs.add(start)

            start += ins.GetByteSize()
            if section_idx < len(sections_region):
                if start > section_start_addr and not section_current:
                    start = section_start_addr
                    section_current = section
                    if debug:
                        print("Starting search from %s section [0x%x-0x%x]" % (section.GetName(), start, section_end_addr))

                    break

                if start > section_end_addr:
                    section_idx += 1
                    section_current = None
                    start = section_end_addr
                    if debug:
                        print("Continue search from 0x%x" % (start))

                    if section_idx < len(sections_region):
                        section = sections_region[section_idx]
                        section_start_addr = section.GetLoadAddress(target)
                        section_end_addr = section_start_addr + section.GetByteSize()

def get_size_summary(size):
    size_summary = ""

    if size > 1024*1024:
        size_summary = "%dM" % (size / (1024 * 1024))
    else:
        size_summary = "%db" % size

    return size_summary

def get_region_info_perms(region_info):
    region_perms = ""
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

    return region_perms

def get_region_map(region_info):
    region_map = {}
    region_map['start'] = region_info.GetRegionBase()
    region_map['end'] = region_info.GetRegionEnd()
    region_map['perms'] = get_region_info_perms(region_info)
    region_map['joined'] = 0

    return region_map


def xrefs_in_region(target, addr, refs, region_map):
    global max_region_size

    if (region_map['end'] - region_map['start']) > max_region_size:
        return

    print("Searching in the memory region [0x%x-0x%x %s %s %d]" %
            (region_map['start'], region_map['end'], region_map['perms'], get_size_summary(region_map['end'] - region_map['start']), region_map['joined']))
    refs_count = do_xrefs_in_region(target, addr, refs, region_map)
    if refs_count > 0:
        print("\t* %d references found it" % refs_count)
"""
def test_dis(target,addr,n):
    dis_addr = target.ResolveLoadAddress(addr)
    ins_dis = target.ReadInstructions(dis_addr, n)
    for ins in ins_dis:
        ins.GetOperands(target)
        print(ins)

    exit(1)
"""

def handle_command(debugger, command, exe_ctx, result, internal_dict):
    refs = set()

    try:
        do_handle_command(debugger, command, exe_ctx, result, internal_dict, refs)
    except KeyboardInterrupt:
        print("keyboard")
        None

    target = exe_ctx.target
    refs = list(refs)
    refs.sort(key=lambda e : e)
    print("%d references count" % len(refs))
    for ref in refs:
        resol_addr = target.ResolveLoadAddress(ref)
        print("\t* 0x%x %s" % (ref, resol_addr.section))

def do_handle_command(debugger, command, exe_ctx, result, internal_dict, refs):
    global pc_reg_name
    global debug

    command_args = shlex.split(command, posix=False)
    usage = "usage: xref [options] expression"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-m", "--max-region-size",
                  action="store", dest="max_region_size",
                  help="search in the memory region with a max size")
    parser.add_option("-d", "--debug",
                  action="store_true", dest="debug",
                  help="enable debug output")
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

    if options.debug:
        debug = options.debug

    if options.max_region_size:
        max_region_size = int(options.max_region_size, 0)

    addr = get_addr_from_expression(target, args[0])
    regions = process.GetMemoryRegions()
    pc_reg_name = get_pc_reg_name(debugger)
    print("Searching external references to 0x%x" % addr)
    region_map = None
    for i in range(regions.GetSize()):
        region_info = lldb.SBMemoryRegionInfo()
        regions.GetMemoryRegionAtIndex(i, region_info)
        if debug:
            print("Parsing the memory region [0x%x:0x%x %s]" % (region_info.GetRegionBase(), region_info.GetRegionEnd(), get_region_info_perms(region_info))) 
        if not region_map:
            region_map = get_region_map(region_info)
        elif region_map['end'] == region_info.GetRegionBase() and region_map['perms'] == get_region_info_perms(region_info):
            region_map['end'] = region_info.GetRegionEnd()
            region_map['joined'] += 1
        else:
            xrefs_in_region(target, addr, refs, region_map)
            region_map = get_region_map(region_info)

    if region_map:
        xrefs_in_region(target, addr, refs, region_map)
