#!/usr/bin/env python3
"""Создаёт sample.pcap: синтетический трафик для всех веток print_info.

Все адреса зарезервированы для документации (RFC 5737, RFC 7042), а содержимое
пакетов выдумано, поэтому реального трафика в файле нет.
"""
import struct
import sys

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")
IP_A = bytes([192, 0, 2, 10])
IP_B = bytes([198, 51, 100, 20])
TS_START = 1690000000


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def eth(payload, ethertype=0x0800):
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


def ipv4(proto, payload, ident, options=b""):
    ihl = 5 + len(options) // 4
    head = struct.pack("!BBHHHBBH", 0x40 | ihl, 0, 20 + len(options) + len(payload),
                       ident, 0x4000, 64, proto, 0) + IP_A + IP_B + options
    return head[:10] + struct.pack("!H", checksum(head)) + head[12:] + payload


def udp(sport, dport, data):
    head = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
    pseudo = IP_A + IP_B + struct.pack("!BBH", 0, 17, len(head) + len(data))
    return head[:6] + struct.pack("!H", checksum(pseudo + head + data) or 0xFFFF) + head[8:] + data


def tcp(sport, dport, seq, ack, flags, window, data=b"", options=b""):
    offset = 5 + len(options) // 4
    head = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset << 4, flags,
                       window, 0, 0) + options
    pseudo = IP_A + IP_B + struct.pack("!BBH", 0, 6, len(head) + len(data))
    return head[:16] + struct.pack("!H", checksum(pseudo + head + data)) + head[18:] + data


MSS_WSCALE_SACK = bytes.fromhex("020405b4" "01030307" "0402" "0000")
HTTP = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

ipv4_tcp_short = ipv4(6, b"\x00" * 10, 7)
tcp_options_cut = ipv4(6, tcp(50000, 80, 1, 0, 0x02, 64240, options=MSS_WSCALE_SACK)[:22], 8)

FRAMES = [
    # UDP: большие номера портов проверяют разбор 16-битных значений.
    eth(ipv4(17, udp(53000, 53, b"\x12\x34\x01\x00\x00\x01example"), 1)),
    # TCP SYN с опциями: data offset 8 даёт заголовок 32 байта.
    eth(ipv4(6, tcp(50000, 80, 1000, 0, 0x02, 64240, options=MSS_WSCALE_SACK), 2)),
    # TCP без опций и с данными: заголовок 20 байт, окно 0xFFFF.
    eth(ipv4(6, tcp(50000, 80, 1001, 2001, 0x18, 65535, HTTP), 3)),
    # TCP с опциями и данными: отличает заголовок * 4 от заголовка * 5.
    eth(ipv4(6, tcp(80, 50000, 2001, 1040, 0x18, 29200, b"HTTP/1.1 200 OK\r\n\r\n",
                    options=MSS_WSCALE_SACK), 4)),
    # Заголовок IPv4 с опциями: 24 байта.
    eth(ipv4(17, udp(1234, 5678, b"ipv4-options"), 5, options=b"\x01\x01\x01\x00")),
    # ICMP echo: IPv4 с неизвестным протоколом.
    eth(ipv4(1, b"\x08\x00\xf7\xff\x00\x01\x00\x00", 6)),
    # ARP: неизвестный EtherType.
    eth(bytes.fromhex("000108000604" "0001") + MAC_A + IP_A + bytes(6) + IP_B, 0x0806),
    # Короче заголовка Ethernet.
    MAC_B + MAC_A[:2],
    # Обрезанный заголовок IPv4.
    eth(ipv4(17, b"", 9)[:10]),
    # Обрезанный заголовок UDP.
    eth(ipv4(17, udp(1, 2, b"")[:4], 10)),
    # TCP обрезан до байта data offset.
    eth(ipv4_tcp_short),
    # TCP обрезан внутри опций.
    eth(tcp_options_cut),
]


def main(path):
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(FRAMES):
            out.write(struct.pack("<IIII", TS_START + i, 0, len(frame), len(frame)))
            out.write(frame)
    print(len(FRAMES))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")
