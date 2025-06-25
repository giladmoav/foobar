from argparse import ArgumentParser
from typing import Dict, Tuple
from scapy.all import *

SOME_MAC = "aa:aa:aa:aa:aa:aa"
SOME_IP = "1.1.1.1"


def apply_packet_changes(pkt: Packet, forward_iface: str) -> None:
    """Apply changes to a forwarded packet"""
    # layer 2 changes
    pkt.src = get_if_hwaddr(forward_iface)
    pkt.dst = SOME_MAC

    # layer 3 changes
    if pkt.haslayer(IP):
        pkt[IP].ttl -= 1
        pkt[IP].src = get_if_addr(forward_iface)
        pkt[IP].dst = SOME_IP


def forward_packet(peers: Dict[str, str], pkt: Packet, verbose: bool = False) -> None:
    """Forward a packet from one peer to another"""
    sniffed_iface = pkt.sniffed_on
    forward_iface = peers[sniffed_iface]

    # check if the packet was sent by the router
    if pkt.src == get_if_hwaddr(sniffed_iface):
        return

    if verbose:
        print(f"Forwarding packet from {sniffed_iface} to {forward_iface}:")
        print(pkt.summary())

    # check if TTL 0 will be reached
    if pkt.haslayer(IP) and pkt[IP] == 1:
        # I really don't want to implement the ICMP error thingy so lets just drop it and print something
        print(f"TTL zero reached for packt: {pkt.summary()}")
        return

    # apply changes to the packet and send
    apply_packet_changes(pkt, forward_iface)
    sendp(pkt, iface=forward_iface, verbose=verbose)


def route_packets(iface1: str, iface2: str, verbose: bool = False) -> None:
    """Enable routing from iface1 to iface2"""
    peers = {iface1: iface2, iface2: iface1}
    sniff(iface=list(peers), prn=partial(forward_packet, peers, verbose=verbose))


def parse_args() -> Tuple[str, str, bool]:
    """Parse command line arguments"""
    argument_parser = ArgumentParser()
    argument_parser.add_argument("iface1", help="Interface for routing")
    argument_parser.add_argument("iface2", help="Interface for routing")
    argument_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose printing")
    args = argument_parser.parse_args()
    return args.iface1, args.iface2, args.verbose


def main() -> None:
    iface1, iface2, verbose = parse_args()
    if verbose:
        print("Using verbose printing")
    route_packets(iface1, iface2, verbose=verbose)


if __name__ == "__main__":
    main()
