# Function: Crifan Unicorn template
#   Use Unicorn to emulate akd +[AKADIProxy getIDMSRoutingInfo:forDSID:] internal implementation function code to running
#       arm64: ___lldb_unnamed_symbol2575$$akd
# Author: Crifan Li
# Update: 20241215
# Usage
#   python3 UnicornEmulateTemplate.py

from __future__ import print_function
import re
from unicorn import *
from unicorn.arm64_const import *
from unicorn.arm_const import *
# import binascii
from capstone import *
from capstone.arm64 import *

from libs.UnicornSimpleHeap import UnicornSimpleHeap

import os
from datetime import datetime,timedelta
import logging
from libs.crifan import crifanLogging

def getCurDatetimeStr(outputFormat="%Y%m%d_%H%M%S"):
    """
    get current datetime then format to string


    eg:
        20171111_220722


    :param outputFormat: datetime output format
    :return: current datetime formatted string
    """
    curDatetime = datetime.now() # 2017-11-11 22:07:22.705101
    curDatetimeStr = curDatetime.strftime(format=outputFormat) #'20171111_220722'
    return curDatetimeStr


def getFilenameNoPointSuffix(curFilePath):
    """Get current filename without point and suffix


    Args:
        curFilePath (str): current file path. Normally can use __file__
    Returns:
        str, file name without .xxx
    Raises:
    Examples:
        input: /Users/xxx/pymitmdump/mitmdumpOtherApi.py
        output: mitmdumpOtherApi
    """
    root, pointSuffix = os.path.splitext(curFilePath)
    curFilenameNoSuffix = root.split(os.path.sep)[-1]
    return curFilenameNoSuffix

################################################################################
# Global Variable
################################################################################

# current all code is 4 byte -> single line arm code
# gSingleLineCode = True

# only for debug
gNoUse = 0

BYTES_PER_LINE = 4

uc = None
ucHeap = None

################################################################################
# Util Function
################################################################################

def readBinFileBytes(inputFilePath):
    fileBytes = None
    with open(inputFilePath, "rb") as f:
        fileBytes = f.read()
    return fileBytes

def readMemory(memAddr, byteNum, endian="little", signed=False):
    """read out value from memory"""
    global uc
    readoutRawValue = uc.mem_read(memAddr, byteNum)
    logging.info(" >> readoutRawValue hex=0x%s", readoutRawValue.hex())
    readoutValue = int.from_bytes(readoutRawValue, endian, signed=signed)
    logging.info(" >> readoutValue=0x%016X", readoutValue)
    return readoutValue

def writeMemory(memAddr, newValue, byteLen):
    """
        for ARM64 little endian, write new value into memory address
        memAddr: memory address to write
        newValue: value to write
        byteLen: 4 / 8
    """
    global uc

    valueFormat = "0x%016X" if byteLen == 8 else "0x%08X"
    if isinstance(newValue, bytes):
        logging.info("writeMemory: memAddr=0x%X, newValue=0x%s, byteLen=%d", memAddr, newValue.hex(), byteLen)
        newValueBytes = newValue
    else:
        valueStr = valueFormat % newValue
        logging.info("writeMemory: memAddr=0x%X, newValue=%s, byteLen=%d", memAddr, valueStr, byteLen)
        newValueBytes = newValue.to_bytes(byteLen, "little")
    uc.mem_write(memAddr, newValueBytes)
    logging.info(" >> has write newValueBytes=%s to address=0x%X", newValueBytes, memAddr)

    # # for debug: verify write is OK or not
    # readoutValue = uc.mem_read(memAddr, byteLen)
    # logging.info("for address 0x%X, readoutValue hex=0x%s", memAddr, readoutValue.hex()))
    # # logging.info("readoutValue hexlify=%b", binascii.hexlify(readoutValue))
    # readoutValueLong = int.from_bytes(readoutValue, "little", signed=False)
    # logging.info("readoutValueLong=0x%x", readoutValueLong)
    # # if readoutValue == newValue:
    # if readoutValueLong == newValue:
    #     logging.info("=== Write and read back OK")
    # else:
    #     logging.info("!!! Write and read back Failed")

def shouldStopEmulate(curPc, decodedInsn):
    isShouldStop = False
    # isRetInsn = decodedInsn.mnemonic == "ret"
    isRetInsn = re.match("^ret", decodedInsn.mnemonic) # support: ret/retaa/retab/...
    if isRetInsn:
        isPcInsideMainCode = (curPc >= CODE_ADDRESS) and (curPc < CODE_ADDRESS_REAL_END)
        isShouldStop = isRetInsn and isPcInsideMainCode

    return isShouldStop

# debug related

def bytesToOpcodeStr(curBytes):
    opcodeByteStr = ''.join('{:02X} '.format(eachByte) for eachByte in curBytes)
    return opcodeByteStr

def dbgAddressRangeStr(startAddress, size):
    endAddress = startAddress + (size - 1)
    addrRangeStr = "0x%X:0x%X" % (startAddress, endAddress)
    return addrRangeStr

################################################################################
# Main
################################################################################

# init logging
curLogFile = "%s_%s.log" % (getFilenameNoPointSuffix(__file__), getCurDatetimeStr())
# 'TIAutoOrder_20221201_174058.log'
curLogFullFile = os.path.join("debug", "log", curLogFile) # 'emulate_akd_getIDMSRoutingInfo_20230529_094920.log'
# 'debug\\log\\TIAutoOrder_20221201_174112.log'
crifanLogging.loggingInit(filename=curLogFullFile)
# crifanLogging.testLogging()
# logging.debug("debug log")
# logging.info("info log")
logging.info("Output log to %s", curLogFullFile)


# Init Capstone instance
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
cs.detail = True

# Init Unicorn

# code to be emulated

# for arm64e: ___lldb_unnamed_symbol2540$$akd
# akd_symbol2540_FilePath = "input/arm64e/akd_arm64e_symbol2540.bin"
# akd_symbol2540_FilePath = "input/arm64e/akd_arm64e_symbol2540_noCanary.bin"
# akd_symbol2540_FilePath = "input/arm64e/akd_arm64e_symbol2540_noCanary_braaToBr.bin"
# b"\x7F\x23\x03\xD5..."

# for arm64: ___lldb_unnamed_symbol2575$$akd
akd_symbol2575_FilePath = "input/arm64/akd_arm64_symbol2575.bin"
logging.info("akd_symbol2575_FilePath=%s", akd_symbol2575_FilePath)
ARM64_CODE_akd_symbol2575 = readBinFileBytes(akd_symbol2575_FilePath) # b'\xff\xc3\x03\xd1\xfco\t\xa9\xfag\n\xa9\xf8_\x0b\xa9\xf6W\x0c\xa9\xf4O
gCodeSizeReal = len(ARM64_CODE_akd_symbol2575)
logging.info("gCodeSizeReal=%d == 0x%X", gCodeSizeReal, gCodeSizeReal)
# ___lldb_unnamed_symbol2540: 10064 == 0x2750
# ___lldb_unnamed_symbol2575 == sub_1000A0460: 9416 == 0x24C8

#-------------------- Code --------------------

# memory address where emulation starts
CODE_ADDRESS = 0x10000
logging.info("CODE_ADDRESS=0x%X", CODE_ADDRESS)

# code size: 4MB
CODE_SIZE = 4 * 1024 * 1024
logging.info("CODE_SIZE=0x%X", CODE_SIZE)
CODE_ADDRESS_END = (CODE_ADDRESS + CODE_SIZE) # 0x00410000
logging.info("CODE_ADDRESS_END=0x%X", CODE_ADDRESS_END)

CODE_ADDRESS_REAL_END = CODE_ADDRESS + gCodeSizeReal
logging.info("CODE_ADDRESS_REAL_END=0x%X", CODE_ADDRESS_REAL_END)
# CODE_ADDRESS_REAL_LAST_LINE = CODE_ADDRESS_REAL_END - 4
# logging.info("CODE_ADDRESS_REAL_LAST_LINE=0x%X", CODE_ADDRESS_REAL_LAST_LINE)

#-------------------- Try fix br jump UC_ERR_MAP --------------------

x9SmallOffsetFile = "input/arm64/lldb_memory/akd_arm64_data_0x100d91680_0x100d938b0_x9SmallOffset.bin"
logging.info("x9SmallOffsetFile=%s", x9SmallOffsetFile)
x9SmallOffsetBytes = readBinFileBytes(x9SmallOffsetFile)
x9SmallOffsetBytesLen = len(x9SmallOffsetBytes) # b' \x00\x00\x00\xc0\x00\x00\x00\\\x00\x00\x00D\x00\x00\x00h\x00\x00\x00H\x01 ...
# logging.info("x9SmallOffsetBytesLen=%d=0x%X", x9SmallOffsetBytesLen, x9SmallOffsetBytesLen))

x9SmallOffsetStartAddress = CODE_ADDRESS + 0x21220
# logging.info("x9SmallOffsetStartAddress=0x%X", x9SmallOffsetStartAddress)
x9SmallOffsetEndAddress = x9SmallOffsetStartAddress + x9SmallOffsetBytesLen
# logging.info("x9SmallOffsetEndAddress=0x%X", x9SmallOffsetEndAddress)

# x10AbsFuncAddrWithOffsetFile = "input/arm64/lldb_memory/akd_arm64_data_0x100dc8480_0x100dc9fe0_x10AbsFuncAddrWithOffset.bin"
x10AbsFuncAddrWithOffsetFile = "input/arm64/lldb_memory/akd_arm64_data_x10EmulateAddr.bin"
logging.info("x10AbsFuncAddrWithOffsetFile=%s", x10AbsFuncAddrWithOffsetFile)
x10AbsFuncAddrWithOffsetBytes = readBinFileBytes(x10AbsFuncAddrWithOffsetFile)
# x10AbsFuncAddrWithOffsetBytesLen = len(x10AbsFuncAddrWithOffsetBytes) # b'\xa8F\xd6\x00\x01\x00\x00\x00\x10G\xd6\x00\x01\x00\x00\x00lG\xd6\x00\x01 ...
x10AbsFuncAddrWithOffsetBytesLen = len(x10AbsFuncAddrWithOffsetBytes) # b'HB\x00\x00\x00\x00\x00\x00\xb0B\x00\x00\x00\x00\x00\x00\x0cC\x00\x00\x00\ ...
# logging.info("x10AbsFuncAddrWithOffsetBytesLen=%d=0x%X", x10AbsFuncAddrWithOffsetBytesLen, x10AbsFuncAddrWithOffsetBytesLen)) # x10AbsFuncAddrWithOffsetBytesLen=7008=0x1B60

x10AbsFuncAddrWithOffsetStartAddress = CODE_ADDRESS + 0x58020
# logging.info("x10AbsFuncAddrWithOffsetStartAddress=0x%X", x10AbsFuncAddrWithOffsetStartAddress)
x10AbsFuncAddrWithOffsetEndAddress = x10AbsFuncAddrWithOffsetStartAddress + x10AbsFuncAddrWithOffsetBytesLen
# logging.info("x10AbsFuncAddrWithOffsetEndAddress=0x%X", x10AbsFuncAddrWithOffsetEndAddress)

#-------------------- emulate malloc --------------------
emulateMallocOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateMallocCodeSize = len(emulateMallocOpcode)

EMULATE_MALLOC_CODE_START = 2 * 1024 * 1024
EMULATE_MALLOC_CODE_END = EMULATE_MALLOC_CODE_START + gEmulateMallocCodeSize

MALLOC_JUMP_ADDR = 0x69BD8
MALLOC_JUMP_VALUE = EMULATE_MALLOC_CODE_START + 2
MALLOC_JUMP_SIZE = 8

#-------------------- emulate free --------------------
emulateFreeOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateFreeCodeSize = len(emulateFreeOpcode)

EMULATE_FREE_CODE_START = (2 * 1024 * 1024) + (128 * 1024)
EMULATE_FREE_CODE_END = EMULATE_FREE_CODE_START + gEmulateFreeCodeSize

FREE_JUMP_ADDR = 0x69B88
FREE_JUMP_VALUE = EMULATE_FREE_CODE_START + 2
FREE_JUMP_SIZE = 8

#-------------------- emulate demalloc --------------------

emulateDemallocOpcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateDemallocCodeSize = len(emulateDemallocOpcode)

EMULATE_DEMALLOC_CODE_START = (2 * 1024 * 1024) + (256 * 1024)
EMULATE_DEMALLOC_CODE_END = EMULATE_DEMALLOC_CODE_START + gEmulateDemallocCodeSize

DEMALLOC_JUMP_ADDR = 0x69C08
DEMALLOC_JUMP_VALUE = EMULATE_DEMALLOC_CODE_START + 2
DEMALLOC_JUMP_SIZE = 8

#-------------------- emulate (call sub function) ___lldb_unnamed_symbol2567$$akd --------------------
emulateAkdFunc2567Opcode = b"\xC0\x03\x5F\xD6" # current only ret=0xC0035FD6
gEmulateAkdFunc2567Size = len(emulateAkdFunc2567Opcode)

EMULATE_AKD_FUNC_2567_START = (2 * 1024 * 1024) + (512 * 1024)
EMULATE_AKD_FUNC_2567_END = EMULATE_AKD_FUNC_2567_START + gEmulateAkdFunc2567Size

AKD_FUNC_2567_JUMP_ADDR = 0x69BC0
AKD_FUNC_2567_JUMP_VALUE = EMULATE_AKD_FUNC_2567_START + 3
AKD_FUNC_2567_JUMP_SIZE = 8

#-------------------- misc jump address and value --------------------

LINE_7396_STORE_VALUE_ADDR = 0x80000

LINE_7392_JUMP_ADDR = 0x69BE8
LINE_7392_JUMP_VALUE = LINE_7396_STORE_VALUE_ADDR + 2
LINE_7392_JUMP_SIZE = 8


#-------------------- __stack_chk_guard --------------------
# ->  0x10469c484 <+36>: ldr    x8, #0x54354              ; (void *)0x00000001f13db058: __stack_chk_guard
#       x8 = 0x00000001f13db058  libsystem_c.dylib`__stack_chk_guard
LIBC_ADDRESS = 5 * 1024 * 1024
LIBC_SIZE = 512 * 1024
STACK_CHECK_GUADR_ADDRESS = LIBC_ADDRESS + 0xB058

#-------------------- Heap --------------------

HEAP_ADDRESS = 6 * 1024 * 1024
HEAP_SIZE = 1 * 1024 * 1024

HEAP_ADDRESS_END = HEAP_ADDRESS + HEAP_SIZE
HEAP_ADDRESS_LAST_BYTE = HEAP_ADDRESS_END - 1

#-------------------- Stack --------------------
# Stack: from High address to lower address ?
STACK_ADDRESS = 7 * 1024 * 1024
STACK_SIZE = 1 * 1024 * 1024
STACK_HALF_SIZE = (int)(STACK_SIZE / 2)

# STACK_ADDRESS_END = STACK_ADDRESS - STACK_SIZE # 8 * 1024 * 1024
# STACK_SP = STACK_ADDRESS - 0x8 # ARM64: offset 0x8

# STACK_TOP = STACK_ADDRESS + STACK_SIZE
STACK_TOP = STACK_ADDRESS + STACK_HALF_SIZE
STACK_SP = STACK_TOP

FP_X29_VALUE = STACK_SP + 0x30

LR_INIT_ADDRESS = CODE_ADDRESS

#-------------------- Args --------------------

# memory address for arguments
ARGS_ADDRESS = 8 * 1024 * 1024
ARGS_SIZE =  0x10000

# init args value
ARG_routingInfoPtr = ARGS_ADDRESS
ARG_DSID = 0xfffffffffffffffe

#-------------------- Unicorn Hook --------------------

# callback for tracing basic blocks
def hook_block(mu, address, size, user_data):
    logging.info("@@@ Tracing basic block at 0x%x, block size = 0x%x", address, size)

# callback for tracing instructions
def hook_code(mu, address, size, user_data):
    global ucHeap

    pc = mu.reg_read(UC_ARM64_REG_PC)

    # logging.info(">>> Tracing instruction at 0x%x, instruction size = 0x%x", address, size)
    lineCount = int(size / BYTES_PER_LINE)
    for curLineIdx in range(lineCount):
        startAddress = address + curLineIdx * BYTES_PER_LINE
        codeOffset = startAddress - CODE_ADDRESS
        opcodeBytes = mu.mem_read(startAddress, BYTES_PER_LINE)
        opcodeByteStr = bytesToOpcodeStr(opcodeBytes)
        decodedInsnGenerator = cs.disasm(opcodeBytes, address)
        # if gSingleLineCode:
        for eachDecodedInsn in decodedInsnGenerator:
            eachInstructionName = eachDecodedInsn.mnemonic
            offsetStr = "<+%d>" % codeOffset
            logging.info("--- 0x%08X %7s: %s -> %s\t%s", startAddress, offsetStr, opcodeByteStr, eachInstructionName, eachDecodedInsn.op_str)
            if shouldStopEmulate(pc, eachDecodedInsn):
                mu.emu_stop()
                logging.info("Emulate done!")

            gNoUse = 1

    # for debug
    toLogDict = {
        0x00010070: ["x25"],
        0x00010074: ["cpsr", "w9", "x9", "x25"],
        0x00010078: ["cpsr", "x9"],
        0x00010080: ["cpsr", "x9", "x10"],
        0x00010084: ["cpsr", "x9"],
        0x00010100: ["x24", "w10"],
        0x00010104: ["x10"],
        0x00010108: ["x27"],
        0x00200000: ["cpsr", "x0", "x1"],
        0x000100D0: ["x0", "x1"],
        0x000100F8: ["x9", "x10"],
        0x000100FC: ["x9"],
        0x0001011C: ["x9"],
        0x0001016C: ["w8", "x25"],
        0x00010170: ["x8"],
        0x00010178: ["x10"],
        0x00011124: ["w24"],
        0x00011128: ["w8"],
        0x0001112C: ["x9"],
        0x00011150: ["x8", "x9"],
        0x00011160: ["x0", "x1", "x2", "x3", "x4", "x26"],
        0x00011164: ["x0"],
        0x000118B4: ["x0", "x22"],
        0x000118B8: ["x0", "x9"],
        0x00011CE0: ["w8", "x9"],
        0x00011CE4: ["x8"],
        0x00011CFC: ["w8", "x9"],
        0x00011D00: ["x8"],
        0x00012138: ["sp"],
        0x00012430: ["x25", "w8"],
        0x00012434: ["x8"],
        0x0001243C: ["x8", "x9"],
        0x00012440: ["x8"],
        0x0001244C: ["x16"],
        0x00012450: ["x27"],
    }

    # common debug

    cpsr = mu.reg_read(UC_ARM_REG_CPSR)
    sp = mu.reg_read(UC_ARM_REG_SP)

    w8 = mu.reg_read(UC_ARM64_REG_W8)
    w9 = mu.reg_read(UC_ARM64_REG_W9)
    w10 = mu.reg_read(UC_ARM64_REG_W10)
    w11 = mu.reg_read(UC_ARM64_REG_W11)
    w24 = mu.reg_read(UC_ARM64_REG_W24)
    w26 = mu.reg_read(UC_ARM64_REG_W26)

    x0 = mu.reg_read(UC_ARM64_REG_X0)
    x1 = mu.reg_read(UC_ARM64_REG_X1)
    x2 = mu.reg_read(UC_ARM64_REG_X2)
    x3 = mu.reg_read(UC_ARM64_REG_X3)
    x4 = mu.reg_read(UC_ARM64_REG_X4)
    x8 = mu.reg_read(UC_ARM64_REG_X8)
    x9 = mu.reg_read(UC_ARM64_REG_X9)
    x10 = mu.reg_read(UC_ARM64_REG_X10)
    x16 = mu.reg_read(UC_ARM64_REG_X16)
    x22 = mu.reg_read(UC_ARM64_REG_X22)
    x24 = mu.reg_read(UC_ARM64_REG_X24)
    x25 = mu.reg_read(UC_ARM64_REG_X25)
    x26 = mu.reg_read(UC_ARM64_REG_X26)
    x27 = mu.reg_read(UC_ARM64_REG_X27)

    regNameToValueDict = {
        "cpsr": cpsr,
        "sp": sp,

        "w8": w8,
        "w9": w9,
        "w10": w10,
        "w11": w11,
        "w24": w24,
        "w26": w26,

        "x0": x0,
        "x1": x1,
        "x2": x2,
        "x3": x3,
        "x4": x4,
        "x8": x8,
        "x9": x9,
        "x10": x10,
        "x16": x16,
        "x22": x22,
        "x24": x24,
        "x25": x25,
        "x26": x26,
        "x27": x27,
    }

    toLogAddressList = toLogDict.keys()
    if pc in toLogAddressList:
        toLogRegList = toLogDict[pc]
        initLogStr = "\tdebug: PC=0x%X: " % pc
        regLogStrList = []
        for eachRegName in toLogRegList:
            eachReg = regNameToValueDict[eachRegName]
            isWordReg = re.match(r"x\d+", eachRegName)
            logFormt = "0x%016X" if isWordReg else "0x%08X"
            curRegValueStr = logFormt % eachReg
            curRegLogStr = "%s=%s" % (eachRegName, curRegValueStr)
            regLogStrList.append(curRegLogStr)
        allRegStr = ", ".join(regLogStrList)
        wholeLogStr = initLogStr + allRegStr
        logging.info("%s", wholeLogStr)
        gNoUse = 1

    # for emulateMalloc
    # if pc == 0x00200000:
    if pc == EMULATE_MALLOC_CODE_START:
        mallocSize = mu.reg_read(UC_ARM64_REG_X0)
        newAddrPtr = ucHeap.malloc(mallocSize)
        mu.reg_write(UC_ARM64_REG_X0, newAddrPtr)
        logging.info("\temulateMalloc: input x0=0x%x, output ret: 0x%x", mallocSize, newAddrPtr)
        gNoUse = 1

    if pc == EMULATE_FREE_CODE_START:
        address = mu.reg_read(UC_ARM64_REG_X0)
        logging.info("\temulateFree: input address=0x%x", address)
        gNoUse = 1

    if pc == EMULATE_DEMALLOC_CODE_START:
        targetTask = mu.reg_read(UC_ARM64_REG_X0)
        address = mu.reg_read(UC_ARM64_REG_X1)
        size = mu.reg_read(UC_ARM64_REG_X2)
        # zeroValue = 0
        # zeroValueBytes = zeroValue.to_bytes(size, "little")
        if (address > 0) and (size > 0):
            writeMemory(address, 0, size)
        logging.info("\temulateDemalloc: input targetTask=0x%X,address=0x%X,size=%d=0x%X", targetTask, address, size, size)
        gNoUse = 1

    if pc == EMULATE_AKD_FUNC_2567_START:
        paraX0 = mu.reg_read(UC_ARM64_REG_X0)
        paraX1 = mu.reg_read(UC_ARM64_REG_X1)
        paraX2 = mu.reg_read(UC_ARM64_REG_X2)
        paraX3 = mu.reg_read(UC_ARM64_REG_X3)
        paraX4 = mu.reg_read(UC_ARM64_REG_X4)

        realDebuggedRetValue = 0
        mu.reg_write(UC_ARM64_REG_X0, realDebuggedRetValue)
        logging.info("\temulateAkdFunc2567: input x0=0x%x,x1=0x%x,x2=0x%x,x3=0x%x,x4=0x%x, output ret: 0x%x", paraX0,paraX1,paraX2,paraX3,paraX4, realDebuggedRetValue)
        gNoUse = 1
    
    # if pc == 0x00011754:
    #     logging.info("")

    # if pc == 0x0001010C:
    #     logging.info("")

    if pc == 0x12138:
        spValue = mu.mem_read(sp)
        logging.info("\tspValue=0x%X", spValue)
        gNoUse = 1

    if pc == 0x1213C:
        gNoUse = 1

    if pc == 0x118B4:
        gNoUse = 1

    if pc == 0x118B8:
        gNoUse = 1


def hook_unmapped(mu, access, address, size, value, context):
    pc = mu.reg_read(UC_ARM64_REG_PC)
    logging.info("!!! Memory UNMAPPED at 0x%X size=0x%x, access(r/w)=%d, value=0x%X, PC=0x%X", address, size, access, value, pc)
    mu.emu_stop()
    return True

def hook_mem_write(uc, access, address, size, value, user_data):
    if address == ARG_routingInfoPtr:
        logging.info("write ARG_routingInfoPtr")
        gNoUse = 1

    pc = uc.reg_read(UC_ARM64_REG_PC)
    logging.info(" >> Memory WRITE at 0x%X, size=%u, value=0x%X, PC=0x%X", address, size, value, pc)
    # logging.info(" >> Memory WRITE at 0x%X, size=%u, value=0x%s, PC=0x%X", address, size, value.to_bytes(8, "little").hex(), pc))
    gNoUse = 1

def hook_mem_read(uc, access, address, size, value, user_data):
    if address == ARG_routingInfoPtr:
        logging.info("read ARG_routingInfoPtr")
        gNoUse = 1

    pc = uc.reg_read(UC_ARM64_REG_PC)
    data = uc.mem_read(address, size)
    logging.info(" << Memory READ at 0x%X, size=%u, rawValueLittleEndian=0x%s, pc=0x%X", address, size, data.hex(), pc)
    gNoUse = 1

    dataLong = int.from_bytes(data, "little", signed=False)
    if dataLong == 0:
        logging.info(" !! Memory read out 0 -> possbile abnormal -> need attention")
        gNoUse = 1


# def hook_mem_fetch(uc, access, address, size, value, user_data):
#     pc = uc.reg_read(UC_ARM64_REG_PC)
#     logging.info(" >> Memory FETCH at 0x%X, size= %u, value= 0x%X, PC= 0x%X", address, size, value, pc))
#     gNoUse = 1

#-------------------- Unicorn main --------------------

# Emulate arm function running
def emulate_akd_arm64_symbol2575():
    global uc, ucHeap
    logging.info("Emulate arm64 sub_1000A0460 == ___lldb_unnamed_symbol2575$$akd function running")
    try:
        # Initialize emulator in ARM mode
        # mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN)
        uc = mu
        # map code memory for this emulation
        mu.mem_map(CODE_ADDRESS, CODE_SIZE)
        logging.info("Mapped memory: Code\t[0x%08X-0x%08X]", CODE_ADDRESS, CODE_ADDRESS + CODE_SIZE)
        # code sub area
        logging.info("\t\t\t  [0x%08X-0x%08X] func: ___lldb_unnamed_symbol2575$$akd", CODE_ADDRESS, CODE_ADDRESS_REAL_END)
        logging.info("\t\t\t  [0x%08X-0x%08X]   fix br err: x9SmallOffset", x9SmallOffsetStartAddress, x9SmallOffsetEndAddress)
        logging.info("\t\t\t  [0x%08X-0x%08X]   fix br err: x10AbsFuncAddrWithOffset", x10AbsFuncAddrWithOffsetStartAddress, x10AbsFuncAddrWithOffsetEndAddress)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateFree jump", FREE_JUMP_ADDR, FREE_JUMP_ADDR + FREE_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateAkdFunc2567 jump", AKD_FUNC_2567_JUMP_ADDR, AKD_FUNC_2567_JUMP_ADDR + AKD_FUNC_2567_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateMalloc jump", MALLOC_JUMP_ADDR, MALLOC_JUMP_ADDR + MALLOC_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   line 7392 jump", LINE_7392_JUMP_ADDR, LINE_7392_JUMP_ADDR + LINE_7392_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X]   emulateDemalloc jump", DEMALLOC_JUMP_ADDR, DEMALLOC_JUMP_ADDR + DEMALLOC_JUMP_SIZE)
        logging.info("\t\t\t  [0x%08X-0x%08X] func: emulateMalloc", EMULATE_MALLOC_CODE_START, EMULATE_MALLOC_CODE_END)
        logging.info("\t\t\t  [0x%08X-0x%08X] func: emulateFree", EMULATE_FREE_CODE_START, EMULATE_FREE_CODE_END)
        logging.info("\t\t\t  [0x%08X-0x%08X] func: emulateAkdFunc2567", EMULATE_AKD_FUNC_2567_START, EMULATE_AKD_FUNC_2567_END)

        # map libc, for __stack_chk_guard
        mu.mem_map(LIBC_ADDRESS, LIBC_SIZE)
        logging.info("Mapped memory: Libc\t[0x%08X-0x%08X]", LIBC_ADDRESS, LIBC_ADDRESS + LIBC_SIZE)
        # map heap
        mu.mem_map(HEAP_ADDRESS, HEAP_SIZE)
        logging.info("Mapped memory: Heap\t[0x%08X-0x%08X]", HEAP_ADDRESS, HEAP_ADDRESS + HEAP_SIZE)
        # map stack
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)
        # mu.mem_map(STACK_ADDRESS_END, STACK_SIZE)
        logging.info("Mapped memory: Stack\t[0x%08X-0x%08X]", STACK_ADDRESS, STACK_ADDRESS + STACK_SIZE)
        # map arguments
        mu.mem_map(ARGS_ADDRESS, ARGS_SIZE)
        logging.info("Mapped memory: Args\t[0x%08X-0x%08X]", ARGS_ADDRESS, ARGS_ADDRESS + ARGS_SIZE)

        # init Heap malloc emulation
        ucHeap = UnicornSimpleHeap(uc, HEAP_ADDRESS, HEAP_ADDRESS_LAST_BYTE, debug_print=True)

        # write machine code to be emulated to memory
        # mu.mem_write(CODE_ADDRESS, ARM64_CODE_akd_symbol2540)
        mu.mem_write(CODE_ADDRESS, ARM64_CODE_akd_symbol2575)

        # # for debug: test memory set to 0
        # testAddr = 0x300000
        # testInt = 0x12345678
        # testIntBytes = testInt.to_bytes(8, "little", signed=False)
        # mu.mem_write(testAddr, testIntBytes)
        # readoutInt1 = readMemory(testAddr, 8)
        # logging.info("readoutInt1=0x%x", readoutInt1)
        # writeMemory(testAddr, 0, 3)
        # readoutInt2 = readMemory(testAddr, 8)
        # logging.info("readoutInt2=0x%x", readoutInt2)

        mu.mem_write(x9SmallOffsetStartAddress, x9SmallOffsetBytes)
        logging.info(" >> has write %d=0x%X bytes into memory [0x%X-0x%X]", x9SmallOffsetBytesLen, x9SmallOffsetBytesLen, x9SmallOffsetStartAddress, x9SmallOffsetStartAddress + x9SmallOffsetBytesLen)
        mu.mem_write(x10AbsFuncAddrWithOffsetStartAddress, x10AbsFuncAddrWithOffsetBytes)
        logging.info(" >> has write %d=0x%X bytes into memory [0x%X-0x%X]", x10AbsFuncAddrWithOffsetBytesLen, x10AbsFuncAddrWithOffsetBytesLen, x10AbsFuncAddrWithOffsetStartAddress, x10AbsFuncAddrWithOffsetStartAddress + x10AbsFuncAddrWithOffsetBytesLen)

        # for emuleateMalloc
        writeMemory(EMULATE_MALLOC_CODE_START, emulateMallocOpcode, gEmulateMallocCodeSize)
        # writeMemory(0x69BD8, EMULATE_MALLOC_CODE_START + 2, 8)
        writeMemory(MALLOC_JUMP_ADDR, MALLOC_JUMP_VALUE, MALLOC_JUMP_SIZE)

        # for emuleateFree
        writeMemory(EMULATE_FREE_CODE_START, emulateFreeOpcode, gEmulateFreeCodeSize)
        writeMemory(FREE_JUMP_ADDR, FREE_JUMP_VALUE, FREE_JUMP_SIZE) # <+256>: 0A DB 6A F8  -> ldr     x10, [x24, w10, sxtw #3]

        # for emuleateDemalloc
        writeMemory(EMULATE_DEMALLOC_CODE_START, emulateDemallocOpcode, gEmulateDemallocCodeSize)
        writeMemory(DEMALLOC_JUMP_ADDR, DEMALLOC_JUMP_VALUE, DEMALLOC_JUMP_SIZE) # <+7420>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]

        # for emulateAkdFunc2567
        writeMemory(EMULATE_AKD_FUNC_2567_START, emulateAkdFunc2567Opcode, gEmulateAkdFunc2567Size)
        # writeMemory(0x69BC0, EMULATE_AKD_FUNC_2567_START + 3, 8) # <+4432>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]
        writeMemory(AKD_FUNC_2567_JUMP_ADDR, AKD_FUNC_2567_JUMP_VALUE, AKD_FUNC_2567_JUMP_SIZE) # <+4432>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]

        # initialize some memory

        # for arm64e:
        # writeMemory(0x757DC, 0x0000000100af47c2, 8)
        # writeMemory(0x662FC, 0x237d5780000100A0, 8)

        # for arm64:

        # for __stack_chk_guard
        writeMemory(0x64378, STACK_CHECK_GUADR_ADDRESS, 4)
        writeMemory(0x50B058, 0x75c022d064c70008, 8)

        # Note: following addr and value have been replaced by: x9 and x10, two group addr and values
        # writeMemory(0x32850, 0x00000094, 4)             # <+236>: 29 DB A9 B8  -> ldrsw   x9, [x25, w9, sxtw #2]
        # readMemory(0x32850, 4)
        # writeMemory(0x32870, 0xffffdbc4, 4)     # <+116>: 29 DB A9 B8  -> ldrsw   x9, [x25, w9, sxtw #2]
        # readMemory(0x32870, 4)
        # writeMemory(0x68CF8, CODE_ADDRESS_REAL_END, 8)  # <+124>: EA 63 2C 58  -> ldr     x10, #0x68cf8
        # readMemory(0x68CF8, 8)
        # writeMemory(0x68D00, 0x1008C, 8)        # <+244>: 6A 60 2C 58  -> ldr     x10, #0x68d00
        # readMemory(0x68D00, 8)
        # writeMemory(0x32858, 0xc4, 4)           # <+364>: 28 DB A8 B8  -> ldrsw   x8, [x25, w8, sxtw #2]
        # readMemory(0x32858, 4)
        # writeMemory(0x68D08, 0x10120, 8)        # <+372>: AA 5C 2C 58  -> ldr     x10, #0x68d08
        # readMemory(0x68D08, 8)

        writeMemory(0x69C18, 0x0000000000078dfa, 8) # <+4400>: 36 D9 68 F8  -> ldr     x22, [x9, w8, sxtw #3]
        writeMemory(0x78DF8, 0x0000000000003f07, 8) # <+4404>: C0 EE 5F B8  -> ldr     w0, [x22, #-2]!

        writeMemory(LINE_7392_JUMP_ADDR, LINE_7392_JUMP_VALUE, LINE_7392_JUMP_SIZE) # <+7392>: 28 D9 68 F8  -> ldr     x8, [x9, w8, sxtw #3]
        writeMemory(LINE_7396_STORE_VALUE_ADDR, 0x00000203, 4) # <+7396>: 00 E1 5F B8  -> ldur    w0, [x8, #-2]

        # initialize machine registers

        # # for arm64e arm64e ___lldb_unnamed_symbol2540$$akd
        # mu.reg_write(UC_ARM64_REG_X0, ARG_routingInfoPtr)
        # mu.reg_write(UC_ARM64_REG_X1, ARG_DSID)

        # for current arm64 ___lldb_unnamed_symbol2575$$akd =====
        mu.reg_write(UC_ARM64_REG_X0, ARG_DSID)
        mu.reg_write(UC_ARM64_REG_X1, ARG_routingInfoPtr)

        # mu.reg_write(UC_ARM64_REG_LR, CODE_ADDRESS_END)
        mu.reg_write(UC_ARM64_REG_LR, LR_INIT_ADDRESS)
        
        # initialize stack
        # mu.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS)
        mu.reg_write(UC_ARM64_REG_SP, STACK_SP)

        mu.reg_write(UC_ARM64_REG_FP, FP_X29_VALUE)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing one instruction with customized callback
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS)
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_REAL_END)
        # mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=EMULATE_MALLOC_CODE_END)
        mu.hook_add(UC_HOOK_CODE, hook_code, begin=CODE_ADDRESS, end=CODE_ADDRESS_END)

        # hook unmamapped memory
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

        # hook memory read and write
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        # mu.hook_add(UC_HOOK_MEM_FETCH, hook_mem_fetch)

        logging.info("---------- Emulation Start ----------")

        # emulate machine code in infinite time
        mu.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(ARM64_CODE_akd_symbol2575))

        # now print out some registers
        logging.info("---------- Emulation done. Below is the CPU context ----------")

        retVal = mu.reg_read(UC_ARM64_REG_X0)
        # routingInfo = mu.mem_read(ARG_routingInfoPtr)
        # logging.info(">>> retVal=0x%x, routingInfo=%d", retVal, routingInfo))
        logging.info(">>> retVal=0x%x", retVal)

        routingInfoEnd = mu.mem_read(ARG_routingInfoPtr, 8)
        logging.info(">>> routingInfoEnd hex=0x%s", routingInfoEnd.hex())
        routingInfoEndLong = int.from_bytes(routingInfoEnd, "little", signed=False)
        logging.info(">>> routingInfoEndLong=%d", routingInfoEndLong)

    except UcError as e:
        logging.info("ERROR: %s", e)
        logging.info("\n")

if __name__ == '__main__':
    emulate_akd_arm64_symbol2575()
    logging.info("=" * 26)
