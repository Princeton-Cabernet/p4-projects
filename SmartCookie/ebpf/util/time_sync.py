import time 
import socket 
import os 
import struct

#set ip to client ip to direct to proxy, proxy will process and drop pkt 
UDP_IP = "169.254.0.1"
UDP_PORT = 5555; 
period = 2

print("Sending one timesync UDP pkt every", period, "seconds, hit CTRL+C to stop")

#f = open('/proc/uptime', 'r')
#def int32(val):
#    return c_int32(val).value

def get_time_bytes():
    #return bytes(4) #use 0 ts
    with open('/proc/uptime', 'r') as uptime_file:
        uptime_src = uptime_file.read().strip().split()[0]        
        #print("Current monotonic ts:", uptime_src)
        uptime_ns = int(float(uptime_src)*1e9)
        # Convert the integer to 4 bytes (32-bit)
        uptime_bytes = struct.pack('I', uptime_ns//(2**16))
        return uptime_bytes

while 1:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
        sock.sendto(get_time_bytes(), (UDP_IP, UDP_PORT))
        #for now, send timesync pkt every 10s 
        time.sleep(period)
    except KeyboardInterrupt:
        print("\nEnding timesync pkt send")
        break 
