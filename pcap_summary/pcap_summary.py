from warnings import filterwarnings
filterwarnings("ignore")
from scapy.layers.inet import TCP, IP, UDP
from scapy.all import *
from tabulate import tabulate
import argparse


FORWARD_COUNTER = 6
REVERSE_COUNTER = 7


def read_pcap(pcap):
    flows = list()
    packets = rdpcap(pcap)
    for packet in packets:
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                flows.append(["TCP", f"{packet[IP].src}:{packet[TCP].sport}", f"{packet[IP].dst}:{packet[TCP].dport}",
                             packet.sprintf('%TCP.flags%'), packet.sprintf('%IP.len%')])
            elif packet.haslayer(UDP):
                flows.append(["UDP", f"{packet[IP].src}:{packet[UDP].sport}", f"{packet[IP].dst}:{packet[UDP].dport}",
                             '--', packet.sprintf('%IP.len%')])
    return flows


def reverse_socket(socket):
    return [socket[0], socket[2], socket[1], socket[3], socket[4]]


def increment_count(socket, flow_list, counter_position):
    for sockets in range(len(flow_list)):
        if flow_list[sockets][0] == socket[0] \
                and flow_list[sockets][1] == socket[1] \
                and flow_list[sockets][2] == socket[2]:
            if len(flow_list[sockets]) == counter_position - 1:
                # Add the counter if the position doesn't exist
                flow_list[sockets].append(1)
            elif len(flow_list[sockets]) >= counter_position:
                # Counter exists increment it
                flow_list[sockets][counter_position - 1] = flow_list[sockets][counter_position - 1] + 1


def increment_size(socket, flow_list):
    for sockets in range(len(flow_list)):
        if flow_list[sockets][0] == socket[0] \
                and flow_list[sockets][1] == socket[1] \
                and flow_list[sockets][2] == socket[2]:
            flow_list[sockets][4] = int(flow_list[sockets][4]) + int(socket[4])


def add_tcp_flags(socket, flow_list):
    for sockets in range(len(flow_list)):
        if flow_list[sockets][0] == socket[0] \
                and flow_list[sockets][1] == socket[1] \
                and flow_list[sockets][2] == socket[2]:
            for flag in socket[3]:
                if flag not in flow_list[sockets][3]:
                    flow_list[sockets][3] = flow_list[sockets][3] + flag


def summarize_packets(flows):
    flows_with_count = list()
    flows_without_count = list()
    for flow in flows:
        rsocket = reverse_socket(flow)
        short_flow = [flow[0], flow[1], flow[2]]
        reverse_short_flow = [flow[0], flow[2], flow[1]]
        if short_flow not in flows_without_count:
            if reverse_short_flow not in flows_without_count:
                forward_socket_with_count = flow.copy()
                forward_socket_with_count.append(1)
                flows_with_count.append(forward_socket_with_count)
                flows_without_count.append(short_flow)
            else:
                increment_count(rsocket, flows_with_count, REVERSE_COUNTER)
                increment_size(rsocket, flows_with_count)
                add_tcp_flags(rsocket, flows_with_count)
        else:
            increment_count(flow, flows_with_count, FORWARD_COUNTER)
            increment_size(flow, flows_with_count)
            add_tcp_flags(flow, flows_with_count)
    return flows_with_count


def filter_flows(flows, search):
    filtered = filter(lambda flow: search in str(flow), flows)
    table = list(filtered)
    return table


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to the pcap file to analyze")
    parser.add_argument("search", nargs='?', help="Serach string within the sockets tuple", default="")
    args = parser.parse_args()

    capture = read_pcap(args.pcap)
    summary = summarize_packets(capture)

    if args.search:
        summary = filter_flows(summary, args.search)

    print(tabulate(summary, headers=["Proto", "Src", "Dst", "Flags", "Flow Size", "FCount", "RCount"]))


if __name__ == "__main__":
    main()