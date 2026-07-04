from InterceptSuite.Extensions.APIs.Logging import ExtensionLogger
import struct


_DNS_PORT = 53
_LAT1     = 'latin-1'

_TYPES = {
    1: 'A', 2: 'NS', 3: 'MD', 4: 'MF', 5: 'CNAME', 6: 'SOA', 7: 'MB',
    8: 'MG', 9: 'MR', 10: 'NULL', 11: 'WKS', 12: 'PTR', 13: 'HINFO',
    14: 'MINFO', 15: 'MX', 16: 'TXT', 17: 'RP', 18: 'AFSDB', 24: 'SIG',
    25: 'KEY', 28: 'AAAA', 29: 'LOC', 33: 'SRV', 35: 'NAPTR', 36: 'KX',
    37: 'CERT', 39: 'DNAME', 41: 'OPT', 42: 'APL', 43: 'DS', 44: 'SSHFP',
    45: 'IPSECKEY', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 49: 'DHCID',
    50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA', 53: 'SMIMEA', 55: 'HIP',
    59: 'CDS', 60: 'CDNSKEY', 61: 'OPENPGPKEY', 62: 'CSYNC', 63: 'ZONEMD',
    64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 108: 'EUI48', 109: 'EUI64',
    249: 'TKEY', 250: 'TSIG', 251: 'IXFR', 252: 'AXFR', 253: 'MAILB',
    254: 'MAILA', 255: 'ANY', 256: 'URI', 257: 'CAA',
}

_CLASSES = {1: 'IN', 2: 'CS', 3: 'CH', 4: 'HS', 254: 'NONE', 255: 'ANY'}

_RCODES = {
    0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP',
    5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET', 8: 'NXRRSET', 9: 'NOTAUTH',
    10: 'NOTZONE', 16: 'BADVERS', 17: 'BADKEY', 18: 'BADTIME',
}

_OPCODES = {0: 'QUERY', 1: 'IQUERY', 2: 'STATUS', 4: 'NOTIFY', 5: 'UPDATE'}

_TYPE_IDS   = {v: k for k, v in _TYPES.items()}
_CLASS_IDS  = {v: k for k, v in _CLASSES.items()}
_RCODE_IDS  = {v: k for k, v in _RCODES.items()}
_OPCODE_IDS = {v: k for k, v in _OPCODES.items()}


def _u16(buf, pos):
    return struct.unpack('>H', buf[pos:pos+2])[0]

def _u32(buf, pos):
    return struct.unpack('>I', buf[pos:pos+4])[0]


def _name(buf, pos, depth=0):
    """Decode a possibly-compressed domain name. Returns (name, next_pos)."""
    labels = []
    jumped = False
    end = pos
    while depth < 32:
        if pos >= len(buf):
            break
        l = buf[pos]
        if l == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if (l & 0xC0) == 0xC0:
            if pos + 2 > len(buf):
                break
            ptr = _u16(buf, pos) & 0x3FFF
            if not jumped:
                end = pos + 2
            pos = ptr
            jumped = True
            depth += 1
            continue
        pos += 1
        labels.append(buf[pos:pos+l].decode('ascii', errors='replace'))
        pos += l
    return '.'.join(labels) or '.', end


def _ipv4(b):
    return '.'.join(str(x) for x in b[:4])

def _ipv6(b):
    import ipaddress
    try:
        return str(ipaddress.IPv6Address(bytes(b[:16])))
    except Exception:
        return b.hex()

def _txt(rd):
    out, i = [], 0
    while i < len(rd):
        l = rd[i]; i += 1
        out.append(rd[i:i+l].decode('utf-8', errors='replace'))
        i += l
    return ' '.join(out)


def _rdata(buf, pos, rtype, rdlen):
    rd = buf[pos:pos+rdlen]
    try:
        if rtype == 1:                   # A
            return _ipv4(rd)
        if rtype == 28:                  # AAAA
            return _ipv6(rd)
        if rtype in (2, 3, 4, 5, 7, 8, 9, 12, 39):   # NS MD MF CNAME MB MG MR PTR DNAME
            return _name(buf, pos)[0]
        if rtype == 6:                   # SOA
            mname, p = _name(buf, pos)
            rname, p = _name(buf, p)
            serial, refresh, retry, expire, minimum = struct.unpack('>IIIII', buf[p:p+20])
            return f'{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}'
        if rtype == 15:                  # MX
            pref = _u16(buf, pos)
            return f'{pref} {_name(buf, pos+2)[0]}'
        if rtype in (16, 99):            # TXT SPF
            return _txt(rd)
        if rtype == 33:                  # SRV
            prio, weight, port = struct.unpack('>HHH', rd[:6])
            return f'{prio} {weight} {port} {_name(buf, pos+6)[0]}'
        if rtype == 35:                  # NAPTR
            order, pref = struct.unpack('>HH', rd[:4])
            p = pos + 4
            parts = []
            for _ in range(3):           # flags, services, regexp
                l = buf[p]; p += 1
                parts.append(buf[p:p+l].decode('ascii', errors='replace'))
                p += l
            return f'{order} {pref} "{parts[0]}" "{parts[1]}" "{parts[2]}" {_name(buf, p)[0]}'
        if rtype == 257:                 # CAA
            flags = rd[0]
            tl = rd[1]
            tag = rd[2:2+tl].decode('ascii', errors='replace')
            val = rd[2+tl:].decode('utf-8', errors='replace')
            return f'{flags} {tag} "{val}"'
        if rtype == 43:                  # DS
            keytag, alg, dtype = struct.unpack('>HBB', rd[:4])
            return f'{keytag} {alg} {dtype} {rd[4:].hex()}'
        if rtype == 46:                  # RRSIG
            tc, alg, lab = struct.unpack('>HBB', rd[:4])
            origttl, exp, inc, keytag = struct.unpack('>IIIH', rd[4:18])
            signer, p = _name(buf, pos+18)
            sig = buf[p:pos+rdlen]
            return f'{_TYPES.get(tc, tc)} {alg} {lab} {origttl} {exp} {inc} {keytag} {signer} {sig.hex()}'
        if rtype == 48:                  # DNSKEY
            flags, proto, alg = struct.unpack('>HBB', rd[:4])
            return f'{flags} {proto} {alg} {rd[4:].hex()}'
        if rtype == 47:                  # NSEC
            nxt, p = _name(buf, pos)
            return f'{nxt} {buf[p:pos+rdlen].hex()}'
        if rtype == 52:                  # TLSA
            u, s, m = rd[0], rd[1], rd[2]
            return f'{u} {s} {m} {rd[3:].hex()}'
        if rtype == 44:                  # SSHFP
            return f'{rd[0]} {rd[1]} {rd[2:].hex()}'
        if rtype in (64, 65):            # SVCB HTTPS
            prio = _u16(rd, 0)
            tgt, p = _name(buf, pos+2)
            return f'{prio} {tgt} {buf[p:pos+rdlen].hex()}'
        if rtype == 41:                  # OPT
            return rd.hex() if rd else ''
    except Exception:
        pass
    return rd.hex()


def _parse_message(msg):
    if len(msg) < 12:
        return ''
    txid   = _u16(msg, 0)
    flags  = _u16(msg, 2)
    qd, an, ns, ar = (_u16(msg, i) for i in (4, 6, 8, 10))

    qr     = (flags >> 15) & 1
    opcode = (flags >> 11) & 0x0F
    aa     = (flags >> 10) & 1
    tc     = (flags >> 9) & 1
    rd     = (flags >> 8) & 1
    ra     = (flags >> 7) & 1
    rcode  = flags & 0x0F

    head = ['response' if qr else 'query',
            _OPCODES.get(opcode, str(opcode)),
            hex(txid)]
    fl = [n for n, v in (('AA', aa), ('TC', tc), ('RD', rd), ('RA', ra)) if v]
    if fl:
        head.append(' '.join(fl))
    if qr:
        head.append(_RCODES.get(rcode, str(rcode)))
    lines = [' '.join(head)]

    pos = 12
    for _ in range(qd):
        name, pos = _name(msg, pos)
        if pos + 4 > len(msg):
            return '\n'.join(lines)
        qtype, qclass = _u16(msg, pos), _u16(msg, pos+2)
        pos += 4
        lines.append(f'{name} {_CLASSES.get(qclass, qclass)} {_TYPES.get(qtype, qtype)}')

    for count in (an, ns, ar):
        for _ in range(count):
            if pos >= len(msg):
                return '\n'.join(lines)
            name, pos = _name(msg, pos)
            if pos + 10 > len(msg):
                return '\n'.join(lines)
            rtype  = _u16(msg, pos)
            rclass = _u16(msg, pos+2)
            ttl    = _u32(msg, pos+4)
            rdlen  = _u16(msg, pos+8)
            pos   += 10
            if rtype == 41:              # OPT pseudo-record (EDNS)
                data = _rdata(msg, pos, rtype, rdlen)
                line = f'OPT {rclass} {ttl}'
                if data:
                    line += f' {data}'
                lines.append(line)
            else:
                data = _rdata(msg, pos, rtype, rdlen)
                lines.append(f'{name} {ttl} {_CLASSES.get(rclass, rclass)} '
                             f'{_TYPES.get(rtype, rtype)} {data}')
            pos += rdlen

    return '\n'.join(lines)


def _split_messages(raw):
    """Return (messages, tcp_framed). TCP DNS has a 2-byte length prefix."""
    # try TCP framing first
    msgs, i, ok = [], 0, True
    while i + 2 <= len(raw):
        mlen = _u16(raw, i)
        if mlen < 12 or i + 2 + mlen > len(raw):
            ok = False
            break
        msgs.append(raw[i+2:i+2+mlen])
        i += 2 + mlen
    if ok and i == len(raw) and msgs:
        return msgs, True
    return [raw], False


# re-encoders (names are written uncompressed)

def _enc_name(name):
    name = name.strip().rstrip('.')
    if not name or name == '.':
        return b'\x00'
    out = b''
    for label in name.split('.'):
        lb = label.encode('ascii')
        if not 1 <= len(lb) <= 63:
            raise ValueError('bad label')
        out += bytes([len(lb)]) + lb
    return out + b'\x00'


def _enc_txt(text):
    b = text.encode('utf-8')
    out = b''
    while True:
        chunk, b = b[:255], b[255:]
        out += bytes([len(chunk)]) + chunk
        if not b:
            break
    return out


def _type_id(tok):
    return _TYPE_IDS[tok] if tok in _TYPE_IDS else int(tok)

def _class_id(tok):
    return _CLASS_IDS[tok] if tok in _CLASS_IDS else int(tok)


def _enc_rdata(rtype, text):
    toks = text.split()
    if rtype == 1:                       # A
        parts = [int(x) for x in toks[0].split('.')]
        if len(parts) != 4 or any(not 0 <= p <= 255 for p in parts):
            raise ValueError('bad ipv4')
        return bytes(parts)
    if rtype == 28:                      # AAAA
        import ipaddress
        return ipaddress.IPv6Address(toks[0]).packed
    if rtype in (2, 3, 4, 5, 7, 8, 9, 12, 39):
        return _enc_name(toks[0])
    if rtype == 6:                       # SOA
        return (_enc_name(toks[0]) + _enc_name(toks[1])
                + struct.pack('>IIIII', *[int(x) for x in toks[2:7]]))
    if rtype == 15:                      # MX
        return struct.pack('>H', int(toks[0])) + _enc_name(toks[1])
    if rtype in (16, 99):                # TXT SPF
        return _enc_txt(text)
    if rtype == 33:                      # SRV
        return struct.pack('>HHH', *[int(x) for x in toks[0:3]]) + _enc_name(toks[3])
    if rtype == 35:                      # NAPTR
        import re
        m = re.match(r'\s*(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+(\S+)', text)
        if not m:
            raise ValueError('bad naptr')
        out = struct.pack('>HH', int(m.group(1)), int(m.group(2)))
        for s in (m.group(3), m.group(4), m.group(5)):
            sb = s.encode('ascii')
            out += bytes([len(sb)]) + sb
        return out + _enc_name(m.group(6))
    if rtype == 257:                     # CAA
        import re
        m = re.match(r'\s*(\d+)\s+(\S+)\s+"(.*)"\s*$', text)
        if not m:
            raise ValueError('bad caa')
        tag = m.group(2).encode('ascii')
        return bytes([int(m.group(1)), len(tag)]) + tag + m.group(3).encode('utf-8')
    if rtype == 43:                      # DS
        return (struct.pack('>HBB', int(toks[0]), int(toks[1]), int(toks[2]))
                + bytes.fromhex(toks[3] if len(toks) > 3 else ''))
    if rtype == 46:                      # RRSIG
        return (struct.pack('>HBB', _type_id(toks[0]), int(toks[1]), int(toks[2]))
                + struct.pack('>IIIH', int(toks[3]), int(toks[4]), int(toks[5]), int(toks[6]))
                + _enc_name(toks[7]) + bytes.fromhex(toks[8] if len(toks) > 8 else ''))
    if rtype == 48:                      # DNSKEY
        return (struct.pack('>HBB', int(toks[0]), int(toks[1]), int(toks[2]))
                + bytes.fromhex(toks[3] if len(toks) > 3 else ''))
    if rtype == 47:                      # NSEC
        return _enc_name(toks[0]) + bytes.fromhex(toks[1] if len(toks) > 1 else '')
    if rtype == 52:                      # TLSA
        return (bytes([int(toks[0]), int(toks[1]), int(toks[2])])
                + bytes.fromhex(toks[3] if len(toks) > 3 else ''))
    if rtype == 44:                      # SSHFP
        return bytes([int(toks[0]), int(toks[1])]) + bytes.fromhex(toks[2] if len(toks) > 2 else '')
    if rtype in (64, 65):                # SVCB HTTPS
        return (struct.pack('>H', int(toks[0])) + _enc_name(toks[1])
                + bytes.fromhex(toks[2] if len(toks) > 2 else ''))
    return bytes.fromhex(toks[0]) if toks else b''


def _enc_header(line, counts):
    toks = line.split()
    qr     = 1 if toks[0] == 'response' else 0
    opcode = _OPCODE_IDS.get(toks[1], None)
    opcode = int(toks[1]) if opcode is None and toks[1].isdigit() else (opcode or 0)
    txid   = int(toks[2], 16)
    rest   = toks[3:]
    aa = tc = rd = ra = 0
    rcode = 0
    for t in rest:
        if   t == 'AA': aa = 1
        elif t == 'TC': tc = 1
        elif t == 'RD': rd = 1
        elif t == 'RA': ra = 1
        elif t in _RCODE_IDS: rcode = _RCODE_IDS[t]
        else: rcode = int(t)
    flags = (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) | (ra << 7) | rcode
    return struct.pack('>HHHHHH', txid, flags, *counts)


def _enc_message(text, counts):
    """Rebuild one DNS message from decoded text. counts = (qd, an, ns, ar)."""
    lines = [l for l in text.split('\n') if l.strip()]
    qd, an, ns, ar = counts
    if len(lines) != 1 + qd + an + ns + ar:
        return None
    out = _enc_header(lines[0], counts)
    idx = 1
    for _ in range(qd):
        toks = lines[idx].split(); idx += 1
        out += _enc_name(toks[0]) + struct.pack('>HH', _type_id(toks[2]), _class_id(toks[1]))
    for _ in range(an + ns + ar):
        line = lines[idx]; idx += 1
        toks = line.split()
        if toks[0] == 'OPT':             # OPT class ttl [hex]
            rdata = bytes.fromhex(toks[3]) if len(toks) > 3 else b''
            out += (b'\x00' + struct.pack('>HHIH', 41, int(toks[1]), int(toks[2]), len(rdata))
                    + rdata)
        else:                            # name ttl class type rdata...
            rtype = _type_id(toks[3])
            rdata = _enc_rdata(rtype, line.split(None, 4)[4] if len(toks) > 4 else '')
            out += (_enc_name(toks[0])
                    + struct.pack('>HHIH', rtype, _class_id(toks[2]), int(toks[1]), len(rdata))
                    + rdata)
    return out


def _looks_like_dns(msg):
    if len(msg) < 12:
        return False
    opcode = (_u16(msg, 2) >> 11) & 0x0F
    if opcode not in _OPCODES:
        return False
    qd, an, ns, ar = (_u16(msg, i) for i in (4, 6, 8, 10))
    if qd > 32 or an > 512 or ns > 512 or ar > 512:
        return False
    return qd + an + ns + ar > 0


def _is_dns(raw, data):
    if not raw:
        return False
    src = data.get('source_port', 0)
    dst = data.get('destination_port', 0)
    if src == _DNS_PORT or dst == _DNS_PORT:
        return len(raw) >= 12
    msgs, _ = _split_messages(raw)
    for msg in msgs:
        if _looks_like_dns(msg):
            return True
    return False


class _DNSHandler:

    def _get_raw(self, data):
        try:
            arr = data.get('raw_data')
            if arr is not None:
                raw = bytes(arr)
                if raw:
                    return raw
        except Exception:
            pass
        try:
            return data.get('data', '').encode(_LAT1)
        except Exception:
            return b''

    def should_show_tab(self, data):
        return _is_dns(self._get_raw(data), data)

    def fetchdata(self, data):
        raw = self._get_raw(data)
        if not raw:
            return ''
        try:
            msgs, _ = _split_messages(raw)
            parts = [_parse_message(m) for m in msgs]
        except Exception:
            return ''
        return '\n\n'.join(p for p in parts if p)

    def updatedata(self, data):
        edited = data.get('edited_data', '')
        if not edited or not edited.strip():
            return None
        raw = self._get_raw(data)
        if not raw:
            return None
        try:
            msgs, tcp = _split_messages(raw)
            orig = '\n\n'.join(p for p in (_parse_message(m) for m in msgs) if p)
            if edited.strip() == orig.strip():
                return None              # unchanged
            chunks = [c for c in edited.split('\n\n') if c.strip()]
            if len(chunks) != len(msgs):
                return None
            result = b''
            for msg, chunk in zip(msgs, chunks):
                if len(msg) < 12:
                    return None
                counts = tuple(_u16(msg, i) for i in (4, 6, 8, 10))
                new_msg = _enc_message(chunk, counts)
                if new_msg is None:
                    return None
                if tcp:
                    result += struct.pack('>H', len(new_msg))
                result += new_msg
        except Exception:
            return None
        return result.decode(_LAT1)


class InterceptSuiteExtension:

    def register_interceptor_api(self, interceptor):
        interceptor.set_extension_name('DNS Decoder')
        interceptor.set_extension_version('1.0.0')
        interceptor.AddDataViewerTab('DNS', _DNSHandler())
        ExtensionLogger.Log('DNS Decoder loaded')
