import pytest
from pcap_summary.pcap_summary import *


def pcap_path():
    return 'tests/mock_data/http.pcap' if os.path.exists('tests/mock_data/http.pcap') else 'mock_data/http.pcap'


def test_read_pcap():
    flows = read_pcap(pcap_path())
    assert len(flows) == 95


def test_increment_count():
    socket = ['TCP', '24.6.173.220:42380', '174.137.42.75:80']
    socket2 = ['TCP', '24.6.173.221:4890', '174.137.42.72:80']
    flows = [socket, socket2]
    increment_count(socket, flows, 4)
    increment_count(socket, flows, 5)
    assert flows[0][3] == 1
    assert flows[0][4] == 1
    increment_count(socket, flows, 4)
    increment_count(socket, flows, 5)
    assert flows[0][3] == 2
    assert flows[0][4] == 2
    increment_count(socket2, flows, 4)
    increment_count(socket2, flows, 5)
    assert flows[1][3] == 1
    assert flows[1][4] == 1


def test_summarize_packets():
    flows = read_pcap(pcap_path())
    flows_with_count = summarize_packets(flows)
    assert len(flows_with_count) == 20


def test_filter_flows():
    flows = read_pcap(pcap_path())
    flows_with_count = summarize_packets(flows)
    filtered = filter_flows(flows_with_count, '174.137.42.75')
    assert len(filtered) == 5


def test_increment_size():
    socket = ['TCP', '24.6.173.220:42380', '174.137.42.75:80', '--', '100']
    socket2 = ['TCP', '24.6.173.221:42380', '174.137.42.72:80', '--', '100']
    flows = [socket, socket2]
    increment_size(socket, flows)
    assert flows[0][4] == 200


def test_add_tcp_flags():
    socket = ['TCP', '24.6.173.220:42380', '174.137.42.75:80', 'S', '100']
    socket2 = ['TCP', '24.6.173.220:42380', '174.137.42.75:80', 'SA', '100']
    socket3 = ['TCP', '24.6.173.220:42380', '174.137.42.75:80', 'R', '100']
    flows = [socket, socket2, socket3]
    add_tcp_flags(socket, flows)
    assert flows[0][3] == 'S'
    add_tcp_flags(socket2, flows)
    assert flows[0][3] == 'SA'
    add_tcp_flags(socket3, flows)
    assert flows[0][3] == 'SAR'