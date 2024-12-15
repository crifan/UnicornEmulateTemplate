# Function: process akd_arm64_data_x10AbsFuncAddrWithOffset_fixOffset.bin offset
#   read out stored function abs address
#   remove function start address
#   add new Unicorn emulate address
#   write back
# Author: Crifan Li
# Update: 20230515

################################################################################
# Global Variable
################################################################################

gNoUse = 0

VALUE_GROUP_BYTE_LEN = 8
REAL_FUNC_START_ADDR = 0x0000000100d70460
EMULATE_FUNC_START_ADDR = 0x10000

################################################################################
# Util Function
################################################################################

def readBinFileBytes(inputFilePath):
    fileBytes = None
    with open(inputFilePath, "rb") as f:
        fileBytes = f.read()
    return fileBytes

def writeBytesToFile(outputFile, bytesData):
    with open(outputFile, "wb") as f:
        f.write(bytesData)

################################################################################
# Main
################################################################################

inputX10FuncAbsOffsetFile = "input/akd_getIDMSRoutingInfo/arm64/lldb_memory/akd_arm64_data_0x100dc8480_0x100dc9fe0_x10AbsFuncAddrWithOffset.bin"
print("inputX10FuncAbsOffsetFile=%s" % inputX10FuncAbsOffsetFile)
inputX10AddrBytes = readBinFileBytes(inputX10FuncAbsOffsetFile) # b'\xa8F\xd6\x00\x01\x00\x00\x00\x10G\xd6\x00\x01\x00\x00\x00lG\xd6\x00\x01 ...
inputX10AddrBytesLen = len(inputX10AddrBytes)
print("inputX10AddrBytesLen=%d == 0x%X" % (inputX10AddrBytesLen, inputX10AddrBytesLen))
inputX10AddrValueLen = (int)(inputX10AddrBytesLen / VALUE_GROUP_BYTE_LEN)
print("inputX10AddrValueLen=%d == 0x%X" % (inputX10AddrValueLen, inputX10AddrValueLen))

outputX10EmulateAddrValueBytes = bytearray()

for eachValueIdx in range(inputX10AddrValueLen):
    bytesStartIdx = eachValueIdx * VALUE_GROUP_BYTE_LEN
    bytesEndIdx = (bytesStartIdx + VALUE_GROUP_BYTE_LEN) - 1
    realAddrValueBytes = inputX10AddrBytes[bytesStartIdx:bytesEndIdx]
    realAddrValue = int.from_bytes(realAddrValueBytes, byteorder="little", signed=False)
    relativeOffset = realAddrValue - REAL_FUNC_START_ADDR
    relativeAbsOffset = abs(relativeOffset)
    emulateAddr = EMULATE_FUNC_START_ADDR + relativeOffset
    emuAddrBytes = int.to_bytes(emulateAddr, 8, byteorder="little", signed=False)
    outputX10EmulateAddrValueBytes.extend(emuAddrBytes)
    # print("outputX10EmulateAddrValueBytes=%s" % outputX10EmulateAddrValueBytes.hex())
    print("[0x%04X-0x%04X]=0x%s==0x%016X -> off:%d=abs(0x%X)->emu:0x%X>>%s" % (bytesStartIdx, bytesEndIdx, realAddrValueBytes.hex(), realAddrValue, relativeOffset, relativeAbsOffset, emulateAddr, emuAddrBytes.hex()))
    gNoUse = 0

outputX10EmulateAddrValueByteLen = len(outputX10EmulateAddrValueBytes)
print("\noutputX10EmulateAddrValueByteLen=%d=0x%X" % (outputX10EmulateAddrValueByteLen, outputX10EmulateAddrValueByteLen))

outputX10EmulateFuncAddrFile = "input/akd_getIDMSRoutingInfo/arm64/lldb_memory/akd_arm64_data_x10EmulateAddr.bin"
print("outputX10EmulateFuncAddrFile=%s" % outputX10EmulateFuncAddrFile)

writeBytesToFile(outputX10EmulateFuncAddrFile, outputX10EmulateAddrValueBytes)

gNoUse = 0
