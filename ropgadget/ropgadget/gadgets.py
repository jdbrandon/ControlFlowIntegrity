## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-05-12 - ROPgadget tool
##
##  http://twitter.com/JonathanSalwan
##  http://shell-storm.org/project/ROPgadget/
##
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.

import re
from   capstone import *
from sys import stderr
from binascii import hexlify


CLP = [b"\x0f\x1f\x40\xaa", 4, 1]
JLP = [b"\x0f\x1f\x40\xbb", 4, 1]
RLP = [b"\x0f\x1f\x40\xcc", 4, 1]
LPI = { CLP[0]: "CLP; ", JLP[0]: "JLP; ", RLP[0]: "RLP; "}


class Gadgets:
    def __init__(self, binary, options, offset):
        self.__binary  = binary
        self.__options = options
        self.__offset  = offset


    def __checkInstructionBlackListedX86(self, insts):
        bl = ["db", "int3"]
        for inst in insts:
            for b in bl:
                if inst.split(" ")[0] == b:
                    return True
        return False

    def __checkMultiBr(self, insts, br):
        count = 0
        for inst in insts:
            if inst.split()[0] in br:
                count += 1
        return count

    def __passCleanX86(self, gadgets, multibr=False):
        new = []
        br = ["ret", "int", "sysenter", "jmp", "call", "syscall"]
        for gadget in gadgets:
            insts = gadget["gadget"].split(" ; ")
            if len(insts) == 1 and insts[0].split(" ")[0] not in br:
                continue
            if insts[-1].split(" ")[0] not in br:
                continue
            if self.__checkInstructionBlackListedX86(insts):
                continue
            if not multibr and self.__checkMultiBr(insts, br) > 1:
                continue
            if len([m.start() for m in re.finditer("ret", gadget["gadget"])]) > 1:
                continue
            new += [gadget]
        return new

    def __gadgetsFinding(self, section, gadgets, arch, mode):

        C_OP    = 0
        C_SIZE  = 1
        C_ALIGN = 2

        #stderr.write("gadgetsFinding with %s gadgets\n" % len(gadgets))
    
        svaddr = section["vaddr"]
        ret = []
        md = Cs(arch, mode)
        for gad in gadgets:
            """ For all potential gadgets iter their references """
            allRefRet = [m.start() for m in re.finditer(gad[C_OP], section["opcodes"])]
            galign = gad[C_ALIGN]
            gsize = gad[C_SIZE]
            for ref in allRefRet:
                offset = svaddr + ref
                for i in range(self.__options.depth):
                    """ Always true for x86 instructions"""
                    if (offset - (i * galign)) % galign == 0:
                        #stderr.write("Section VADDR: %s\tRef: %s\t=%s\n" %(svaddr, ref, offset))
                        #stderr.write("\tOffset: %s:%s\n" % (ref-(i*galign), ref+gsize))
                        """ Decode the section's code from the found instruction backwards """
                        decodes = md.disasm(section["opcodes"][ref-(i*galign):ref+gsize], offset)
                        gadget = ""
                        for decode in decodes:
                            gadget += (decode.mnemonic + " " + decode.op_str + " ; ").replace("  ", " ")
                            #stderr.write("\tdecoded: '%s'\n" % decode.mnemonic)
                            #stderr.write("\tG: '%s'\n" % gadget)
                        if len(gadget) > 0:
                            """ Strip off some white space and semi-colon """
                            gadget = gadget[:-3]
                            off = self.__offset
                            ret += [{"vaddr" :  off+section["vaddr"]+ref-(i*gad[C_ALIGN]), "gadget" : gadget, "decodes" : decodes, "bytes": section["opcodes"][ref-(i*gad[C_ALIGN]):ref+gad[C_SIZE]]}]
        return ret

    def __gadgetsFindingLPI(self, section, gadgets, arch, mode):
        ret = []

        branches = ["ret", "int", "sysenter", "jmp", "call", "syscall"]

        sect_vaddr = section["vaddr"]

        disassembler = Cs(arch, mode)
        for gad in gadgets:
            g_opcode = gad[0]
            g_size = gad[1]
            g_align = gad[2]
            
            """
            Find all the offsets of this LPI gadget in the bytecode of this executable section
            """
            lpi_offsets = [m.start() for m in re.finditer(g_opcode, section["opcodes"])]
           
            """
            For each discovered offset of the LPI then try to disassemble a gadget
            """
            for lpi_offset in lpi_offsets:
                lpi_addr = sect_vaddr + lpi_offset
                i = 0 
                ret_reached = False
                while i < 100 and not ret_reached:
                    """
                    i is an arbitrary limiter so that we don't add enormous functions to the gadget list.
                    Necessary? Probably not.
                    """
                    try:
                        """
                        Disassemble forwards not backwards like regular ROP gadget.
                        Start just after the LPI so that we don't get nonsense NOP from Capstone.
                        """
                        disassembly = disassembler.disasm(section["opcodes"][lpi_offset + g_size:], lpi_addr)
                    except CsError as e:
                        """
                        Bad disassembly ruins a gadget
                        """
                        stderr.write("CsError: %s\n" % e)
                        break
                    else:
                        i += 1
                        """
                        Gadget starts with the LPI not with '' like regular gadget.
                        """
                        gadget = LPI.get(g_opcode)
                        for instruction in disassembly:
                            #stderr.write("0x%s:  %s %s\n" % (hexlify(instruction.bytes), instruction.mnemonic, instruction.op_str))
                            gadget += (instruction.mnemonic + " " + instruction.op_str + " ; ").replace("  ", " ")
                            if instruction.mnemonic == "ret":
                                ret_reached = True
                                break
                        if gadget:
                            gadget = gadget[:-3]
                            offset = self.__offset
                            ret += [{"vaddr" :  offset + sect_vaddr + lpi_offset - i,
                                     "gadget" : gadget,
                                     "decodes" : disassembly,
                                     "bytes": section["opcodes"][lpi_offset - i:lpi_offset + g_size]}]
        return ret 


    def addROPGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()

        if arch == CS_ARCH_X86:
            gadgets = [
                            [b"\xc3", 1, 1],               # ret
                            [b"\xc2[\x00-\xff]{2}", 3, 1]  # ret <imm>
                       ]

        elif arch == CS_ARCH_MIPS:   gadgets = []            # MIPS doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_PPC:
            gadgets = [
                            [b"\x4e\x80\x00\x20", 4, 4] # blr
                       ]
            arch_mode = arch_mode + CS_MODE_BIG_ENDIAN

        elif arch == CS_ARCH_SPARC:
            gadgets = [
                            [b"\x81\xc3\xe0\x08", 4, 4], # retl
                            [b"\x81\xc7\xe0\x08", 4, 4], # ret
                            [b"\x81\xe8\x00\x00", 4, 4]  # restore
                       ]
            arch_mode = CS_MODE_BIG_ENDIAN

        elif arch == CS_ARCH_ARM:    gadgets = []            # ARM doesn't contains RET instruction set. Only JOP gadgets
        elif arch == CS_ARCH_ARM64:
            gadgets =  [
                            [b"\xc0\x03\x5f\xd6", 4, 4] # ret
                       ]
            arch_mode = CS_MODE_ARM

        else:
            print("Gadgets().addROPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return gadgets


    def addJOPGadgets(self, section):
        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()



        if arch  == CS_ARCH_X86:
            gadgets = [
                               [b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1], # jmp  [reg]
                               [b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1],     # jmp  [reg]
                               [b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1]  # call [reg]
                      ]


        elif arch == CS_ARCH_MIPS:
            gadgets = [
                               [b"\x09\xf8\x20\x03[\x00-\xff]{4}", 8, 4], # jrl $t9
                               [b"\x08\x00\x20\x03[\x00-\xff]{4}", 8, 4], # jr  $t9
                               [b"\x08\x00\xe0\x03[\x00-\xff]{4}", 8, 4]  # jr  $ra
                      ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # PPC architecture doesn't contains reg branch instruction
        elif arch == CS_ARCH_SPARC:
            gadgets = [
                               [b"\x81\xc0[\x00\x40\x80\xc0]{1}\x00", 4, 4]  # jmp %g[0-3]
                      ]
            arch_mode = CS_MODE_BIG_ENDIAN
        elif arch == CS_ARCH_ARM64:
            gadgets = [
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00\x02]{1}\x1f\xd6", 4, 4],     # br  reg
                               [b"[\x00\x20\x40\x60\x80\xa0\xc0\xe0]{1}[\x00\x02]{1}\x5C\x3f\xd6", 4, 4]  # blr reg
                      ]
            arch_mode = CS_MODE_ARM
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"[\x00\x08\x10\x18\x20\x28\x30\x38\x40\x48\x70]{1}\x47", 2, 2], # bx   reg
                               [b"[\x80\x88\x90\x98\xa0\xa8\xb0\xb8\xc0\xc8\xf0]{1}\x47", 2, 2], # blx  reg
                               [b"[\x00-\xff]{1}\xbd", 2, 2]                                     # pop {,pc}
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"[\x10-\x19\x1e]{1}\xff\x2f\xe1", 4, 4],  # bx   reg
                               [b"[\x30-\x39\x3e]{1}\xff\x2f\xe1", 4, 4],  # blx  reg
                               [b"[\x00-\xff]{1}\x80\xbd\xe8", 4, 4]       # pop {,pc}
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addJOPGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return gadgets


    def addSYSGadgets(self, section):

        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()

        if   arch == CS_ARCH_X86:
            gadgets = [
                               [b"\xcd\x80", 2, 1],                         # int 0x80
                               [b"\x0f\x34", 2, 1],                         # sysenter
                               [b"\x0f\x05", 2, 1],                         # syscall
                               [b"\x65\xff\x15\x10\x00\x00\x00", 7, 1],     # call DWORD PTR gs:0x10
                               [b"\xcd\x80\xc3", 3, 1],                     # int 0x80 ; ret
                               [b"\x0f\x34\xc3", 3, 1],                     # sysenter ; ret
                               [b"\x0f\x05\xc3", 3, 1],                     # syscall ; ret
                               [b"\x65\xff\x15\x10\x00\x00\x00\xc3", 8, 1], # call DWORD PTR gs:0x10 ; ret
                      ]

        elif arch == CS_ARCH_MIPS:
            gadgets = [
                               [b"\x0c\x00\x00\x00", 4, 4] # syscall
                      ]
        elif arch == CS_ARCH_PPC:    gadgets = [] # TODO (sc inst)
        elif arch == CS_ARCH_SPARC:  gadgets = [] # TODO (ta inst)
        elif arch == CS_ARCH_ARM64:  gadgets = [] # TODO
        elif arch == CS_ARCH_ARM:
            if self.__options.thumb or self.__options.rawMode == "thumb":
                gadgets = [
                               [b"\x00-\xff]{1}\xef", 2, 2] # svc
                          ]
                arch_mode = CS_MODE_THUMB
            else:
                gadgets = [
                               [b"\x00-\xff]{3}\xef", 4, 4] # svc
                          ]
                arch_mode = CS_MODE_ARM
        else:
            print("Gadgets().addSYSGadgets() - Architecture not supported")
            return None

        if len(gadgets) > 0 :
            return self.__gadgetsFinding(section, gadgets, arch, arch_mode)
        return []

    
    def addLPIGadgets(self, section):
        
        arch = self.__binary.getArch()
        arch_mode = self.__binary.getArchMode()
        
        if   arch == CS_ARCH_X86:
            gadgets = [CLP, JLP, RLP]
        else:
            print("Gadgets().addLPIGadgets() - Architecture not supported")
            return None

        return self.__gadgetsFindingLPI(section, gadgets, arch, arch_mode)


    def passClean(self, gadgets, multibr):

        arch = self.__binary.getArch()
        if   arch == CS_ARCH_X86:    return self.__passCleanX86(gadgets, multibr)
        elif arch == CS_ARCH_MIPS:   return gadgets
        elif arch == CS_ARCH_PPC:    return gadgets
        elif arch == CS_ARCH_SPARC:  return gadgets
        elif arch == CS_ARCH_ARM:    return gadgets
        elif arch == CS_ARCH_ARM64:  return gadgets
        else:
            print("Gadgets().passClean() - Architecture not supported")
            return None

