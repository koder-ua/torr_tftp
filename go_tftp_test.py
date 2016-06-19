import sys
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto("\x00\x00", ('localhost', int(sys.argv[1])))
