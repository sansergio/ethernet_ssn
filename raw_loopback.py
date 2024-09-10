
from scapy.all import *
import sys, signal
def signal_handler(signal, frame):
    print("\nprogram exiting gracefully")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
verbose = True # True -> Enables debug messages

###############################################################################
#                              INTERNAL METHODS
###############################################################################
# Check if the frame has the MAC address sent by the k64
def is_k64_frame(frame):
    try:
        return frame.getlayer(0).src=='d4:be:d9:45:22:61'
        #return frame[802.3].src == 'd4:be:d9:45:22:61'
    except:
        return False

def sendMessage(data):
    # Convert to bytes
    byte_message = bytes(data, 'utf-8')

    # Get data len
    data_len = len(byte_message)

    frame = Ether()/byte_message

    # Set frame header
    frame[Ether].dst = 'd4:be:d9:45:22:61'
    # frame[Ether].dst = 'ff:ff:ff:ff:ff:ff'
    frame[Ether].src = 'd4:be:d9:45:22:62'
    frame[Ether].type = data_len

    # Send frame
    sendp(frame)

def main():

    cont = 0

    # Configure Scapy to use the ethernet interface
    conf.iface="Intel(R) Ethernet Connection (16) I219-LM"

    sendMessage("Hola")
    # Process the frames
    while True:
        # # Wait to receive a frame
        frames = sniff(count=1, lfilter=is_k64_frame) #, prn= lambda x:x.show())
        frame = frames[0]
        data_len = frame.getlayer(0).len
        # Extract data from frame
        data = bytes(frame)
        print('Received: ' + str(data))
        sendMessage(str(data))



if __name__=="__main__":
    main()