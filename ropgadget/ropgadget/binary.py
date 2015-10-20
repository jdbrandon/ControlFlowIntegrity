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

from ropgadget.loaders.elf       import *
from ropgadget.loaders.pe        import *
from ropgadget.loaders.raw       import *
from ropgadget.loaders.macho     import *
from ropgadget.loaders.universal import *
from binascii import unhexlify

class Binary:
    def __init__(self, options):
        self.__fileName  = options.binary
        self.__rawBinary = None
        self.__binary    = None
        
        try:
            fd = open(self.__fileName, "rb")
            self.__rawBinary = fd.read()
            fd.close()
        except:
            print("[Error] Can't open the binary or binary not found")
            return None

        if   options.rawArch and options.rawMode:
             self.__binary = Raw(self.__rawBinary, options.rawArch, options.rawMode)
        elif self.__rawBinary[:4] == unhexlify(b"7f454c46"):
             self.__binary = ELF(self.__rawBinary)
        elif self.__rawBinary[:2] == unhexlify(b"4d5a"):
             self.__binary = PE(self.__rawBinary)
        elif self.__rawBinary[:4] == unhexlify(b"cafebabe"):
             self.__binary = UNIVERSAL(self.__rawBinary)
        elif self.__rawBinary[:4] == unhexlify(b"cefaedfe") or self.__rawBinary[:4] == unhexlify(b"cffaedfe"):
             self.__binary = MACHO(self.__rawBinary)
        else:
            print("[Error] Binary format not supported")
            return None

    def getFileName(self):
        return self.__fileName

    def getRawBinary(self):
        return self.__rawBinary

    def getBinary(self):
        return self.__binary

    def getEntryPoint(self):
        return self.__binary.getEntryPoint()

    def getDataSections(self):
        return self.__binary.getDataSections()

    def getExecSections(self):
        return self.__binary.getExecSections()

    def getArch(self):
        return self.__binary.getArch()

    def getArchMode(self):
        return self.__binary.getArchMode()

    def getFormat(self):
        return self.__binary.getFormat()

