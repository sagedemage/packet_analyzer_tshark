import pyshark
import asyncio
import sys
from pyshark.packet.packet import Packet
from datetime import datetime
import json

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

def start_capture():
    loop = asyncio.new_event_loop()

    live_capture = pyshark.LiveCapture(interface='Ethernet', eventloop=loop, output_file='data/output.pcapng')

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


def main():
    if len(sys.argv) > 1:
        flag = sys.argv[1]

        match flag:
            case "sniff":
                start_capture()
            case "read":
                read_capture()
            case _:
                print(f"Flag {flag} not supported\n")
                print("Usage:")
                print("sniff -> sniff packets")
                print("read -> read packet data from a file")
    else:
        print("Usage:")
        print("sniff -> sniff packets")
        print("read -> read packet data from a file")

if __name__ == "__main__":
    main()