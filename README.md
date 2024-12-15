# UnicornEmulateTemplate

* Update: `20241215`

## Repo

https://github.com/crifan/UnicornEmulateTemplate.git

## Function

use this template as a startup for using [Unicorn](https://book.crifan.org/books/cpu_emulator_unicorn/website/) to emulate code

## Run

```bash
python3 UnicornEmulateTemplate.py
```

## Output log example

```bash

➜  UnicornEmulateTemplate git:(main) ✗ python3 UnicornEmulateTemplate.py
20241215 23:00:11 UnicornEmulateTemplate.py:159  INFO    Output log to debug/log/UnicornEmulateTemplate_20241215_230011.log
20241215 23:00:11 UnicornEmulateTemplate.py:178  INFO    akd_symbol2575_FilePath=input/arm64/akd_arm64_symbol2575.bin
20241215 23:00:11 UnicornEmulateTemplate.py:181  INFO    gCodeSizeReal=9416 == 0x24C8
20241215 23:00:11 UnicornEmulateTemplate.py:189  INFO    CODE_ADDRESS=0x10000
20241215 23:00:11 UnicornEmulateTemplate.py:193  INFO    CODE_SIZE=0x400000
20241215 23:00:11 UnicornEmulateTemplate.py:195  INFO    CODE_ADDRESS_END=0x410000
20241215 23:00:11 UnicornEmulateTemplate.py:198  INFO    CODE_ADDRESS_REAL_END=0x124C8
20241215 23:00:11 UnicornEmulateTemplate.py:205  INFO    x9SmallOffsetFile=input/arm64/lldb_memory/akd_arm64_data_0x100d91680_0x100d938b0_x9SmallOffset.bin
20241215 23:00:11 UnicornEmulateTemplate.py:217  INFO    x10AbsFuncAddrWithOffsetFile=input/arm64/lldb_memory/akd_arm64_data_x10EmulateAddr.bin
20241215 23:00:11 UnicornEmulateTemplate.py:565  INFO    Emulate arm64 sub_1000A0460 == ___lldb_unnamed_symbol2575$$akd function running
20241215 23:00:11 UnicornEmulateTemplate.py:573  INFO    Mapped memory: Code	[0x00010000-0x00410000]
20241215 23:00:11 UnicornEmulateTemplate.py:575  INFO    			  [0x00010000-0x000124C8] func: ___lldb_unnamed_symbol2575$$akd
20241215 23:00:11 UnicornEmulateTemplate.py:576  INFO    			  [0x00031220-0x00033450]   fix br err: x9SmallOffset
20241215 23:00:11 UnicornEmulateTemplate.py:577  INFO    			  [0x00068020-0x00069B80]   fix br err: x10AbsFuncAddrWithOffset
20241215 23:00:11 UnicornEmulateTemplate.py:578  INFO    			  [0x00069B88-0x00069B90]   emulateFree jump
20241215 23:00:11 UnicornEmulateTemplate.py:579  INFO    			  [0x00069BC0-0x00069BC8]   emulateAkdFunc2567 jump
20241215 23:00:11 UnicornEmulateTemplate.py:580  INFO    			  [0x00069BD8-0x00069BE0]   emulateMalloc jump
20241215 23:00:11 UnicornEmulateTemplate.py:581  INFO    			  [0x00069BE8-0x00069BF0]   line 7392 jump
20241215 23:00:11 UnicornEmulateTemplate.py:582  INFO    			  [0x00069C08-0x00069C10]   emulateDemalloc jump
20241215 23:00:11 UnicornEmulateTemplate.py:583  INFO    			  [0x00200000-0x00200004] func: emulateMalloc
20241215 23:00:11 UnicornEmulateTemplate.py:584  INFO    			  [0x00220000-0x00220004] func: emulateFree
20241215 23:00:11 UnicornEmulateTemplate.py:585  INFO    			  [0x00280000-0x00280004] func: emulateAkdFunc2567
20241215 23:00:11 UnicornEmulateTemplate.py:589  INFO    Mapped memory: Libc	[0x00500000-0x00580000]
20241215 23:00:11 UnicornEmulateTemplate.py:592  INFO    Mapped memory: Heap	[0x00600000-0x00700000]
20241215 23:00:11 UnicornEmulateTemplate.py:596  INFO    Mapped memory: Stack	[0x00700000-0x00800000]
20241215 23:00:11 UnicornEmulateTemplate.py:599  INFO    Mapped memory: Args	[0x00800000-0x00810000]
20241215 23:00:11 UnicornEmulateTemplate.py:620  INFO     >> has write 8752=0x2230 bytes into memory [0x31220-0x33450]
20241215 23:00:11 UnicornEmulateTemplate.py:622  INFO     >> has write 7008=0x1B60 bytes into memory [0x68020-0x69B80]
20241215 23:00:11 UnicornEmulateTemplate.py:104  INFO    writeMemory: memAddr=0x200000, newValue=0xc0035fd6, byteLen=4
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x200000
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x69BD8, newValue=0x0000000000200002, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x02\x00 \x00\x00\x00\x00\x00' to address=0x69BD8
20241215 23:00:11 UnicornEmulateTemplate.py:104  INFO    writeMemory: memAddr=0x220000, newValue=0xc0035fd6, byteLen=4
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x220000
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x69B88, newValue=0x0000000000220002, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x02\x00"\x00\x00\x00\x00\x00' to address=0x69B88
20241215 23:00:11 UnicornEmulateTemplate.py:104  INFO    writeMemory: memAddr=0x240000, newValue=0xc0035fd6, byteLen=4
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x240000
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x69C08, newValue=0x0000000000240002, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x02\x00$\x00\x00\x00\x00\x00' to address=0x69C08
20241215 23:00:11 UnicornEmulateTemplate.py:104  INFO    writeMemory: memAddr=0x280000, newValue=0xc0035fd6, byteLen=4
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\xc0\x03_\xd6' to address=0x280000
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x69BC0, newValue=0x0000000000280003, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x03\x00(\x00\x00\x00\x00\x00' to address=0x69BC0
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x64378, newValue=0x0050B058, byteLen=4
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'X\xb0P\x00' to address=0x64378
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x50B058, newValue=0x75C022D064C70008, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x08\x00\xc7d\xd0"\xc0u' to address=0x50B058
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x69C18, newValue=0x0000000000078DFA, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\xfa\x8d\x07\x00\x00\x00\x00\x00' to address=0x69C18
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x78DF8, newValue=0x0000000000003F07, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x07?\x00\x00\x00\x00\x00\x00' to address=0x78DF8
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x69BE8, newValue=0x0000000000080002, byteLen=8
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x02\x00\x08\x00\x00\x00\x00\x00' to address=0x69BE8
20241215 23:00:11 UnicornEmulateTemplate.py:108  INFO    writeMemory: memAddr=0x80000, newValue=0x00000203, byteLen=4
20241215 23:00:11 UnicornEmulateTemplate.py:111  INFO     >> has write newValueBytes=b'\x03\x02\x00\x00' to address=0x80000
20241215 23:00:11 UnicornEmulateTemplate.py:710  INFO    ---------- Emulation Start ----------
20241215 23:00:11 UnicornEmulateTemplate.py:328  INFO    @@@ Tracing basic block at 0x10000, block size = 0x8c
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010000    <+0>: FF C3 03 D1  -> sub	sp, sp, #0xf0
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010004    <+4>: FC 6F 09 A9  -> stp	x28, x27, [sp, #0x90]
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFA0, size=8, value=0x0, PC=0x10004
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFA8, size=8, value=0x0, PC=0x10004
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010008    <+8>: FA 67 0A A9  -> stp	x26, x25, [sp, #0xa0]
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFB0, size=8, value=0x0, PC=0x10008
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFB8, size=8, value=0x0, PC=0x10008
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001000C   <+12>: F8 5F 0B A9  -> stp	x24, x23, [sp, #0xb0]
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFC0, size=8, value=0x0, PC=0x1000C
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFC8, size=8, value=0x0, PC=0x1000C
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010010   <+16>: F6 57 0C A9  -> stp	x22, x21, [sp, #0xc0]
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFD0, size=8, value=0x0, PC=0x10010
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFD8, size=8, value=0x0, PC=0x10010
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010014   <+20>: F4 4F 0D A9  -> stp	x20, x19, [sp, #0xd0]
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFE0, size=8, value=0x0, PC=0x10014
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFE8, size=8, value=0x0, PC=0x10014
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010018   <+24>: FD 7B 0E A9  -> stp	x29, x30, [sp, #0xe0]
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFF0, size=8, value=0x780030, PC=0x10018
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FFF8, size=8, value=0x10000, PC=0x10018
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001001C   <+28>: FD 83 03 91  -> add	x29, sp, #0xe0
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010020   <+32>: 1F 20 03 D5  -> nop
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010024   <+36>: A8 1A 2A 58  -> ldr	x8, #0x64378
20241215 23:00:11 UnicornEmulateTemplate.py:546  INFO     << Memory READ at 0x64378, size=8, rawValueLittleEndian=0x58b0500000000000, pc=0x10024
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010028   <+40>: 08 01 40 F9  -> ldr	x8, [x8]
20241215 23:00:11 UnicornEmulateTemplate.py:546  INFO     << Memory READ at 0x50B058, size=8, rawValueLittleEndian=0x0800c764d022c075, pc=0x10028
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001002C   <+44>: A8 83 1A F8  -> stur	x8, [x29, #-0x58]
20241215 23:00:11 UnicornEmulateTemplate.py:535  INFO     >> Memory WRITE at 0x77FF98, size=8, value=0x75C022D064C70008, PC=0x1002C
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010030   <+48>: FA 50 8B 52  -> movz	w26, #0x5a87
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010034   <+52>: 9A 84 AD 72  -> movk	w26, #0x6c24, lsl #16
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010038   <+56>: 08 18 00 91  -> add	x8, x0, #6
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001003C   <+60>: 1F 15 00 F1  -> cmp	x8, #5
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010040   <+64>: 04 28 48 BA  -> ccmn	x0, #8, #4, hs
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010044   <+68>: 28 00 80 52  -> movz	w8, #0x1
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010048   <+72>: E8 03 88 1A  -> csel	w8, wzr, w8, eq
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001004C   <+76>: 4B B4 94 52  -> movz	w11, #0xa5a2
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010050   <+80>: 6B 7B B2 72  -> movk	w11, #0x93db, lsl #16
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010054   <+84>: 3F 00 00 F1  -> cmp	x1, #0
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010058   <+88>: E9 17 9F 1A  -> cset	w9, eq
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001005C   <+92>: 28 01 08 2A  -> orr	w8, w9, w8
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010060   <+96>: 49 03 08 0B  -> add	w9, w26, w8
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010064  <+100>: 29 01 0B 0B  -> add	w9, w9, w11
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010068  <+104>: 29 85 00 51  -> sub	w9, w9, #0x21
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001006C  <+108>: 39 3F 11 10  -> adr	x25, #0x32850
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010070  <+112>: 1F 20 03 D5  -> nop
20241215 23:00:11 UnicornEmulateTemplate.py:462  INFO    	debug: PC=0x10070: x25=0x0000000000032850
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010074  <+116>: 29 DB A9 B8  -> ldrsw	x9, [x25, w9, sxtw #2]
20241215 23:00:11 UnicornEmulateTemplate.py:462  INFO    	debug: PC=0x10074: cpsr=0x20000000, w9=0x00000008, x9=0x0000000000000008, x25=0x0000000000032850
20241215 23:00:11 UnicornEmulateTemplate.py:546  INFO     << Memory READ at 0x32870, size=4, rawValueLittleEndian=0xc4dbffff, pc=0x10074
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010078  <+120>: 1F 20 03 D5  -> nop
20241215 23:00:11 UnicornEmulateTemplate.py:462  INFO    	debug: PC=0x10078: cpsr=0x20000000, x9=0xFFFFFFFFFFFFDBC4
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001007C  <+124>: EA 63 2C 58  -> ldr	x10, #0x68cf8
20241215 23:00:11 UnicornEmulateTemplate.py:546  INFO     << Memory READ at 0x68CF8, size=8, rawValueLittleEndian=0xc824010000000000, pc=0x1007C
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010080  <+128>: 29 01 0A 8B  -> add	x9, x9, x10
20241215 23:00:11 UnicornEmulateTemplate.py:462  INFO    	debug: PC=0x10080: cpsr=0x20000000, x9=0xFFFFFFFFFFFFDBC4, x10=0x00000000000124C8
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010084  <+132>: 16 F9 95 12  -> movn	w22, #0xafc8
20241215 23:00:11 UnicornEmulateTemplate.py:462  INFO    	debug: PC=0x10084: cpsr=0x20000000, x9=0x000000000001008C
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010088  <+136>: 20 01 1F D6  -> br	x9
20241215 23:00:11 UnicornEmulateTemplate.py:328  INFO    @@@ Tracing basic block at 0x1008c, block size = 0x44
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x0001008C  <+140>: F7 03 01 AA  -> mov	x23, x1
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010090  <+144>: FC 03 00 AA  -> mov	x28, x0
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010094  <+148>: 08 01 00 52  -> eor	w8, w8, #1
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x00010098  <+152>: 69 A5 00 51  -> sub	w9, w11, #0x29
...
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x000124B8 <+9400>: FC 6F 49 A9  -> ldp	x28, x27, [sp, #0x90]
20241215 23:00:11 UnicornEmulateTemplate.py:546  INFO     << Memory READ at 0x77FFA0, size=8, rawValueLittleEndian=0x0000000000000000, pc=0x124B8
20241215 23:00:11 UnicornEmulateTemplate.py:551  INFO     !! Memory read out 0 -> possbile abnormal -> need attention
20241215 23:00:11 UnicornEmulateTemplate.py:546  INFO     << Memory READ at 0x77FFA8, size=8, rawValueLittleEndian=0x0000000000000000, pc=0x124B8
20241215 23:00:11 UnicornEmulateTemplate.py:551  INFO     !! Memory read out 0 -> possbile abnormal -> need attention
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x000124BC <+9404>: FF C3 03 91  -> add	sp, sp, #0xf0
20241215 23:00:11 UnicornEmulateTemplate.py:348  INFO    --- 0x000124C0 <+9408>: C0 03 5F D6  -> ret
20241215 23:00:11 UnicornEmulateTemplate.py:351  INFO    Emulate done!
20241215 23:00:11 UnicornEmulateTemplate.py:716  INFO    ---------- Emulation done. Below is the CPU context ----------
20241215 23:00:11 UnicornEmulateTemplate.py:721  INFO    >>> retVal=0xffff5016
20241215 23:00:11 UnicornEmulateTemplate.py:724  INFO    >>> routingInfoEnd hex=0x0000000000000000
20241215 23:00:11 UnicornEmulateTemplate.py:726  INFO    >>> routingInfoEndLong=0
20241215 23:00:11 UnicornEmulateTemplate.py:734  INFO    ==========================
```
