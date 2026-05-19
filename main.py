import pyshark
import asyncio
import sys
from pyshark.packet.packet import Packet
from datetime import datetime
import json
from pyshark.capture.live_capture import UnknownInterfaceException

def check_interface(iface_name):
    loop = asyncio.new_event_loop()
    live_capture = pyshark.LiveCapture(interface=iface_name, eventloop=loop)

    try:
        live_capture.sniff(packet_count=20, timeout=100)
        live_capture.close()
        return True
    except UnknownInterfaceException:
        live_capture.close()
        return False

def get_packet_data(packet: Packet, timestamp: float):
    num = packet.number
    source_ip = ""
    destination_ip = ""
    protocol = packet.highest_layer
    frame_length = packet.length
    dt = packet.sniff_time
    p_timestamp = dt.timestamp()
    packet_time = p_timestamp - timestamp

    if hasattr(packet, 'ip'):
        source_ip = packet.ip.src
        destination_ip = packet.ip.dst
    elif hasattr(packet, 'ipv6'):
        source_ip = packet.ipv6.src
        destination_ip = packet.ipv6.dst
    elif hasattr(packet, 'arp'):
        source_ip = packet.arp.src_proto_ipv4
        destination_ip = packet.arp.dst_proto_ipv4
    elif hasattr(packet, 'eth'):
        source_ip = packet.eth.src
        destination_ip = packet.eth.dst

    print(f"Num: {num}, Time: {packet_time:.9f}, Source: {source_ip}, Destination: {destination_ip}, Protocol: {protocol}, Length: {frame_length}")

def start_capture(iface_name: str):
    loop = asyncio.new_event_loop()
    if check_interface(iface_name):
        live_capture = pyshark.LiveCapture(interface=iface_name, eventloop=loop, output_file='data/output.pcapng')

        now = datetime.now()
        now_timestamp = now.timestamp()

        data = {
            "start_timestamp": now_timestamp
        }

        with open("data/program_exe.json", "w") as f:
            json.dump(data, f)
    
        live_capture.sniff(packet_count=20, timeout=100)

        for packet in live_capture:
            get_packet_data(packet, now_timestamp)
    
        live_capture.close()
    else:
        print(f"Interface {iface_name} invalid")

def read_capture():
    loop = asyncio.new_event_loop()
    file_capture = pyshark.FileCapture("data/output.pcapng", eventloop=loop)

    data = {}
    with open("data/program_exe.json", "r") as f:
        data = json.load(f)

    start_timestamp = data['start_timestamp']

    for packet in file_capture:
        get_packet_data(packet, start_timestamp)

    file_capture.close()

def help_usage():
    print("Usage:")
    print("sniff i <interface_name> -> sniff packets on a specified interface")
    print("read -> read packet data from a file")

def main():
    if len(sys.argv) > 1:
        flag = sys.argv[1]

        match flag:
            case "sniff":
                if len(sys.argv) > 3:
                    interface_flag = sys.argv[2]
                    if interface_flag == "i":
                        iface_name = sys.argv[3]
                        start_capture(iface_name)
                else:
                    help_usage()
            case "read":
                read_capture()
            case _:
                print(f"Flag {flag} not supported\n")
                help_usage()
    else:
        help_usage()

if __name__ == "__main__":
    main()