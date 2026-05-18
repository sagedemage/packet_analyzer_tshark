import pyshark
import asyncio
import time

def start_capture():
    loop = asyncio.new_event_loop()

    live_capture = pyshark.LiveCapture(interface='Ethernet', eventloop=loop, only_summaries=False)
    
    start_time = time.time()
    live_capture.sniff(packet_count=20, timeout=100)

    i = 1
    for packet in live_capture:
        num = i
        source_ip = ""
        destination_ip = ""
        protocol = packet.highest_layer
        frame_length = packet.length
        dt = packet.sniff_time
        timestamp = dt.timestamp()
        packet_time = timestamp - start_time

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

        # Num, Time, Source, Destination, Protocol, Lenght, Info
        print(f"Num: {num}, Time: {packet_time:.9f}, Source: {source_ip}, Destination: {destination_ip}, Protocol: {protocol}, Length: {frame_length}")

        i += 1
    
    live_capture.close()

def main():
    start_capture()

if __name__ == "__main__":
    main()