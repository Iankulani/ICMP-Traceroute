# -*- coding: utf-8 -*-
"""
Created on Fri Feb  21 03:345:47 2025

@author: IAN CAERTER KULANI

"""
from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("ICMP TRACEROUTE")
print(Fore.GREEN+font)

import scapy.all as scapy
import socket

def trace_route(destination_ip, max_hops=30):
    """
    Trace the route to a destination IP using ICMP echo requests.
    
    :param destination_ip: IP address of the destination
    :param max_hops: Maximum number of hops to trace
    """
    print(f"Tracing route to {destination_ip}...\n")
    
    for ttl in range(1, max_hops + 1):
        # Create an ICMP Echo Request packet
        packet = scapy.IP(dst=destination_ip, ttl=ttl) / scapy.ICMP()
        
        # Send the packet and receive the response (with a timeout of 2 seconds)
        response = scapy.sr1(packet, timeout=2, verbose=False)
        
        if response is None:
            print(f"{ttl} * * * Request Timed Out")
        else:
            # Get the response IP address and round-trip time (RTT)
            rtt = response.time - packet.sent_time
            print(f"{ttl} {response.src}  RTT = {rtt * 1000:.2f} ms")
            
            # If we reached the destination, stop the trace
            if response.src == destination_ip:
                print(f"Trace complete: Destination reached at hop {ttl}.")
                break

def main():
    
    # Prompt user for an IP address to trace
    ip_address = input("Enter the target IP address or hostname (e.g., 192.168.1.1): ")

    # Check if the input is a valid IP or hostname
    try:
        socket.inet_aton(ip_address)  # Try to check if it's a valid IP address
    except socket.error:
        print("[!] Invalid IP address. Attempting to resolve the hostname...")
        # If it's a hostname, resolve it to IP
        try:
            ip_address = socket.gethostbyname(ip_address)
            print(f"Resolved hostname to IP: {ip_address}")
        except socket.gaierror:
            print("[!] Unable to resolve hostname to IP.")
            return

    # Start the trace route
    trace_route(ip_address)

if __name__ == "__main__":
    main()
