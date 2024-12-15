# Function: Emulate memory management (malloc/free/...)
# Author: Crifan Li
# Update: 20230529

from unicorn import *
import logging

# Page size required by Unicorn
UNICORN_PAGE_SIZE = 0x1000

# Max allowable segment size (1G)
MAX_ALLOWABLE_SEG_SIZE = 1024 * 1024 * 1024

# Alignment functions to align all memory segments to Unicorn page boundaries (4KB pages only)
ALIGN_PAGE_DOWN = lambda x: x & ~(UNICORN_PAGE_SIZE - 1)
ALIGN_PAGE_UP   = lambda x: (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE-1)

# refer: https://github.com/Battelle/afl-unicorn/blob/master/unicorn_mode/helper_scripts/unicorn_loader.py
class UnicornSimpleHeap(object):
    """ Use this class to provide a simple heap implementation. This should
        be used if malloc/free calls break things during emulation. This heap also
        implements basic guard-page capabilities which enable immediate notice of
        heap overflow and underflows.
    """

    # Helper data-container used to track chunks
    class HeapChunk(object):
        def __init__(self, actual_addr, total_size, data_size):
            self.total_size = total_size                        # Total size of the chunk (including padding and guard page)
            self.actual_addr = actual_addr                      # Actual start address of the chunk
            self.data_size = data_size                          # Size requested by the caller of actual malloc call
            self.data_addr = actual_addr + UNICORN_PAGE_SIZE    # Address where data actually starts

        # Returns true if the specified buffer is completely within the chunk, else false
        def is_buffer_in_chunk(self, addr, size):
            if addr >= self.data_addr and ((addr + size) <= (self.data_addr + self.data_size)):
                return True
            else:
                return False

        def isSameChunk(self, anotherChunk):
            isSame = (self.actual_addr == anotherChunk.actual_addr) and (self.total_size == anotherChunk.total_size)
            return isSame

        def debug(self):
            chunkEndAddr = self.actual_addr + self.total_size
            chunkStr = "chunk: [0x%X-0x%X] ptr=0x%X, size=%d=0x%X"% (self.actual_addr, chunkEndAddr, self.data_addr, self.data_size, self.data_size)
            return chunkStr

        def isOverlapped(self, newChunk):
            # logging.info("debug: self=%s, newChunk=%s", self.debug(), newChunk.debug())
            selfStartAddr = self.actual_addr
            selfLastAddr = selfStartAddr + self.total_size - 1
            newChunkStartAddr = newChunk.actual_addr
            newChunkLastAddr = newChunkStartAddr + newChunk.total_size - 1
            isOverlapStart = (newChunkStartAddr >= selfStartAddr) and (newChunkStartAddr <= selfLastAddr)
            isOverlapEnd = (newChunkLastAddr >= selfStartAddr) and (newChunkLastAddr <= selfLastAddr)
            isOverlapped = isOverlapStart or isOverlapEnd
            return isOverlapped

    # # Skip the zero-page to avoid weird potential issues with segment registers
    # HEAP_MIN_ADDR = 0x00002000 # 8KB
    # HEAP_MAX_ADDR = 0xFFFFFFFF # 4GB-1
    _headMinAddr = None
    _heapMaxAddr = None

    _uc = None              # Unicorn engine instance to interact with
    _chunks = []            # List of all known chunks
    _debug_print = False    # True to print debug information

    # def __init__(self, uc, debug_print=False):
    def __init__(self, uc, headMinAddr, heapMaxAddr, debug_print=False):
        self._uc = uc
        self._headMinAddr = headMinAddr
        self._heapMaxAddr = heapMaxAddr
        self._debug_print = debug_print

        # Add the watchpoint hook that will be used to implement psuedo-guard page support
        self._uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, self.__check_mem_access)

    def isChunkAllocated(self, newChunk):
        isAllocated = False
        for eachChunk in self._chunks:
            if eachChunk.isSameChunk(newChunk):
                isAllocated = True
                break
        return isAllocated

    def isChunkOverlapped(self, newChunk):
        isOverlapped = False
        for eachChunk in self._chunks:
            if eachChunk.isOverlapped(newChunk):
                isOverlapped = True
                break
        return isOverlapped

    def malloc(self, size):
        # Figure out the overall size to be allocated/mapped
        #    - Allocate at least 1 4k page of memory to make Unicorn happy
        #    - Add guard pages at the start and end of the region
        total_chunk_size = UNICORN_PAGE_SIZE + ALIGN_PAGE_UP(size) + UNICORN_PAGE_SIZE
        # Gross but efficient way to find space for the chunk:
        chunk = None
        # for addr in range(self.HEAP_MIN_ADDR, self.HEAP_MAX_ADDR, UNICORN_PAGE_SIZE):
        for addr in range(self._headMinAddr, self._heapMaxAddr, UNICORN_PAGE_SIZE):
            try:
                # self._uc.mem_map(addr, total_chunk_size, UC_PROT_READ | UC_PROT_WRITE)
                chunk = self.HeapChunk(addr, total_chunk_size, size)
                # chunkStr = "[0x{0:X}-0x{1:X}]".format(chunk.actual_addr, chunk.actual_addr + chunk.total_size)
                chunkStr = chunk.debug()
                # if chunk in self._chunks:
                # if self.isChunkAllocated(chunk):
                if self.isChunkOverlapped(chunk):
                    # if self._debug_print:
                    #     logging.info(" ~~ Omit overlapped chunk: %s", chunkStr)
                    continue
                else:
                    if self._debug_print:
                        # logging.info("Heap: allocating 0x{0:X} byte addr=0x{1:X} of chunk {2:s}".format(chunk.data_size, chunk.data_addr, chunkStr))
                        logging.info(" ++ Allocated heap chunk: %s", chunkStr)
                    break
            except UcError as err:
                logging.error("!!! Heap malloc failed: error=%s", err)
                continue
        # Something went very wrong
        if chunk == None:
            return 0
        self._chunks.append(chunk)
        return chunk.data_addr

    def calloc(self, size, count):
        # Simple wrapper around malloc with calloc() args
        return self.malloc(size*count)

    def realloc(self, ptr, new_size):
        # Wrapper around malloc(new_size) / memcpy(new, old, old_size) / free(old)
        if self._debug_print:
            logging.info("Reallocating chunk @ 0x{0:016x} to be 0x{1:x} bytes".format(ptr, new_size))
        old_chunk = None
        for chunk in self._chunks:
            if chunk.data_addr == ptr:
                old_chunk = chunk
        new_chunk_addr = self.malloc(new_size)
        if old_chunk != None:
            self._uc.mem_write(new_chunk_addr, str(self._uc.mem_read(old_chunk.data_addr, old_chunk.data_size)))
            self.free(old_chunk.data_addr)
        return new_chunk_addr

    def free(self, addr):
        for chunk in self._chunks:
            if chunk.is_buffer_in_chunk(addr, 1):
                if self._debug_print:
                    logging.info("Freeing 0x{0:x}-byte chunk @ 0x{0:016x}".format(chunk.req_size, chunk.data_addr))
                self._uc.mem_unmap(chunk.actual_addr, chunk.total_size)
                self._chunks.remove(chunk)
                return True
        return False

    # Implements basic guard-page functionality
    def __check_mem_access(self, uc, access, address, size, value, user_data):
        for chunk in self._chunks:
            if address >= chunk.actual_addr and ((address + size) <= (chunk.actual_addr + chunk.total_size)):
                if chunk.is_buffer_in_chunk(address, size) == False:
                    if self._debug_print:
                        logging.info("Heap over/underflow attempting to {0} 0x{1:x} bytes @ {2:016x}".format( \
                            "write" if access == UC_MEM_WRITE else "read", size, address))
                    # Force a memory-based crash
                    uc.force_crash(UcError(UC_ERR_READ_PROT))