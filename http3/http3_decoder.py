from InterceptSuite.Extensions.APIs.Logging import ExtensionLogger
import re
import zlib
from urllib.parse import urlsplit

_LAT1 = 'latin-1'
_MAX_TEXT = 1000000          # characters of decoded body shown

# Generated from RFC 7541 appendix B (Huffman) and RFC 9204 appendix A (QPACK static table).
_HUFFMAN = (
    (8184, 13),
    (8388568, 23),
    (268435426, 28),
    (268435427, 28),
    (268435428, 28),
    (268435429, 28),
    (268435430, 28),
    (268435431, 28),
    (268435432, 28),
    (16777194, 24),
    (1073741820, 30),
    (268435433, 28),
    (268435434, 28),
    (1073741821, 30),
    (268435435, 28),
    (268435436, 28),
    (268435437, 28),
    (268435438, 28),
    (268435439, 28),
    (268435440, 28),
    (268435441, 28),
    (268435442, 28),
    (1073741822, 30),
    (268435443, 28),
    (268435444, 28),
    (268435445, 28),
    (268435446, 28),
    (268435447, 28),
    (268435448, 28),
    (268435449, 28),
    (268435450, 28),
    (268435451, 28),
    (20, 6),
    (1016, 10),
    (1017, 10),
    (4090, 12),
    (8185, 13),
    (21, 6),
    (248, 8),
    (2042, 11),
    (1018, 10),
    (1019, 10),
    (249, 8),
    (2043, 11),
    (250, 8),
    (22, 6),
    (23, 6),
    (24, 6),
    (0, 5),
    (1, 5),
    (2, 5),
    (25, 6),
    (26, 6),
    (27, 6),
    (28, 6),
    (29, 6),
    (30, 6),
    (31, 6),
    (92, 7),
    (251, 8),
    (32764, 15),
    (32, 6),
    (4091, 12),
    (1020, 10),
    (8186, 13),
    (33, 6),
    (93, 7),
    (94, 7),
    (95, 7),
    (96, 7),
    (97, 7),
    (98, 7),
    (99, 7),
    (100, 7),
    (101, 7),
    (102, 7),
    (103, 7),
    (104, 7),
    (105, 7),
    (106, 7),
    (107, 7),
    (108, 7),
    (109, 7),
    (110, 7),
    (111, 7),
    (112, 7),
    (113, 7),
    (114, 7),
    (252, 8),
    (115, 7),
    (253, 8),
    (8187, 13),
    (524272, 19),
    (8188, 13),
    (16380, 14),
    (34, 6),
    (32765, 15),
    (3, 5),
    (35, 6),
    (4, 5),
    (36, 6),
    (5, 5),
    (37, 6),
    (38, 6),
    (39, 6),
    (6, 5),
    (116, 7),
    (117, 7),
    (40, 6),
    (41, 6),
    (42, 6),
    (7, 5),
    (43, 6),
    (118, 7),
    (44, 6),
    (8, 5),
    (9, 5),
    (45, 6),
    (119, 7),
    (120, 7),
    (121, 7),
    (122, 7),
    (123, 7),
    (32766, 15),
    (2044, 11),
    (16381, 14),
    (8189, 13),
    (268435452, 28),
    (1048550, 20),
    (4194258, 22),
    (1048551, 20),
    (1048552, 20),
    (4194259, 22),
    (4194260, 22),
    (4194261, 22),
    (8388569, 23),
    (4194262, 22),
    (8388570, 23),
    (8388571, 23),
    (8388572, 23),
    (8388573, 23),
    (8388574, 23),
    (16777195, 24),
    (8388575, 23),
    (16777196, 24),
    (16777197, 24),
    (4194263, 22),
    (8388576, 23),
    (16777198, 24),
    (8388577, 23),
    (8388578, 23),
    (8388579, 23),
    (8388580, 23),
    (2097116, 21),
    (4194264, 22),
    (8388581, 23),
    (4194265, 22),
    (8388582, 23),
    (8388583, 23),
    (16777199, 24),
    (4194266, 22),
    (2097117, 21),
    (1048553, 20),
    (4194267, 22),
    (4194268, 22),
    (8388584, 23),
    (8388585, 23),
    (2097118, 21),
    (8388586, 23),
    (4194269, 22),
    (4194270, 22),
    (16777200, 24),
    (2097119, 21),
    (4194271, 22),
    (8388587, 23),
    (8388588, 23),
    (2097120, 21),
    (2097121, 21),
    (4194272, 22),
    (2097122, 21),
    (8388589, 23),
    (4194273, 22),
    (8388590, 23),
    (8388591, 23),
    (1048554, 20),
    (4194274, 22),
    (4194275, 22),
    (4194276, 22),
    (8388592, 23),
    (4194277, 22),
    (4194278, 22),
    (8388593, 23),
    (67108832, 26),
    (67108833, 26),
    (1048555, 20),
    (524273, 19),
    (4194279, 22),
    (8388594, 23),
    (4194280, 22),
    (33554412, 25),
    (67108834, 26),
    (67108835, 26),
    (67108836, 26),
    (134217694, 27),
    (134217695, 27),
    (67108837, 26),
    (16777201, 24),
    (33554413, 25),
    (524274, 19),
    (2097123, 21),
    (67108838, 26),
    (134217696, 27),
    (134217697, 27),
    (67108839, 26),
    (134217698, 27),
    (16777202, 24),
    (2097124, 21),
    (2097125, 21),
    (67108840, 26),
    (67108841, 26),
    (268435453, 28),
    (134217699, 27),
    (134217700, 27),
    (134217701, 27),
    (1048556, 20),
    (16777203, 24),
    (1048557, 20),
    (2097126, 21),
    (4194281, 22),
    (2097127, 21),
    (2097128, 21),
    (8388595, 23),
    (4194282, 22),
    (4194283, 22),
    (33554414, 25),
    (33554415, 25),
    (16777204, 24),
    (16777205, 24),
    (67108842, 26),
    (8388596, 23),
    (67108843, 26),
    (134217702, 27),
    (67108844, 26),
    (67108845, 26),
    (134217703, 27),
    (134217704, 27),
    (134217705, 27),
    (134217706, 27),
    (134217707, 27),
    (268435454, 28),
    (134217708, 27),
    (134217709, 27),
    (134217710, 27),
    (134217711, 27),
    (134217712, 27),
    (67108846, 26),
    (1073741823, 30),
)

_STATIC = (
    (':authority', ''),
    (':path', '/'),
    ('age', '0'),
    ('content-disposition', ''),
    ('content-length', '0'),
    ('cookie', ''),
    ('date', ''),
    ('etag', ''),
    ('if-modified-since', ''),
    ('if-none-match', ''),
    ('last-modified', ''),
    ('link', ''),
    ('location', ''),
    ('referer', ''),
    ('set-cookie', ''),
    (':method', 'CONNECT'),
    (':method', 'DELETE'),
    (':method', 'GET'),
    (':method', 'HEAD'),
    (':method', 'OPTIONS'),
    (':method', 'POST'),
    (':method', 'PUT'),
    (':scheme', 'http'),
    (':scheme', 'https'),
    (':status', '103'),
    (':status', '200'),
    (':status', '304'),
    (':status', '404'),
    (':status', '503'),
    ('accept', '*/*'),
    ('accept', 'application/dns-message'),
    ('accept-encoding', 'gzip, deflate, br'),
    ('accept-ranges', 'bytes'),
    ('access-control-allow-headers', 'cache-control'),
    ('access-control-allow-headers', 'content-type'),
    ('access-control-allow-origin', '*'),
    ('cache-control', 'max-age=0'),
    ('cache-control', 'max-age=2592000'),
    ('cache-control', 'max-age=604800'),
    ('cache-control', 'no-cache'),
    ('cache-control', 'no-store'),
    ('cache-control', 'public, max-age=31536000'),
    ('content-encoding', 'br'),
    ('content-encoding', 'gzip'),
    ('content-type', 'application/dns-message'),
    ('content-type', 'application/javascript'),
    ('content-type', 'application/json'),
    ('content-type', 'application/x-www-form-urlencoded'),
    ('content-type', 'image/gif'),
    ('content-type', 'image/jpeg'),
    ('content-type', 'image/png'),
    ('content-type', 'text/css'),
    ('content-type', 'text/html; charset=utf-8'),
    ('content-type', 'text/plain'),
    ('content-type', 'text/plain;charset=utf-8'),
    ('range', 'bytes=0-'),
    ('strict-transport-security', 'max-age=31536000'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains'),
    ('strict-transport-security', 'max-age=31536000; includesubdomains; preload'),
    ('vary', 'accept-encoding'),
    ('vary', 'origin'),
    ('x-content-type-options', 'nosniff'),
    ('x-xss-protection', '1; mode=block'),
    (':status', '100'),
    (':status', '204'),
    (':status', '206'),
    (':status', '302'),
    (':status', '400'),
    (':status', '403'),
    (':status', '421'),
    (':status', '425'),
    (':status', '500'),
    ('accept-language', ''),
    ('access-control-allow-credentials', 'FALSE'),
    ('access-control-allow-credentials', 'TRUE'),
    ('access-control-allow-headers', '*'),
    ('access-control-allow-methods', 'get'),
    ('access-control-allow-methods', 'get, post, options'),
    ('access-control-allow-methods', 'options'),
    ('access-control-expose-headers', 'content-length'),
    ('access-control-request-headers', 'content-type'),
    ('access-control-request-method', 'get'),
    ('access-control-request-method', 'post'),
    ('alt-svc', 'clear'),
    ('authorization', ''),
    ('content-security-policy', "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ('early-data', '1'),
    ('expect-ct', ''),
    ('forwarded', ''),
    ('if-range', ''),
    ('origin', ''),
    ('purpose', 'prefetch'),
    ('server', ''),
    ('timing-allow-origin', '*'),
    ('upgrade-insecure-requests', '1'),
    ('user-agent', ''),
    ('x-forwarded-for', ''),
    ('x-frame-options', 'deny'),
    ('x-frame-options', 'sameorigin'),
)


# ── Huffman (RFC 7541 appendix B, used by QPACK) ──────────────────────────────────────────────────────────────

def _build_tree():
    root = [None, None]
    for sym, (code, length) in enumerate(_HUFFMAN):
        node = root
        for i in range(length - 1, -1, -1):
            bit = (code >> i) & 1
            if i == 0:
                node[bit] = sym
            else:
                if node[bit] is None:
                    node[bit] = [None, None]
                node = node[bit]
    return root


_TREE = _build_tree()


def _huff_decode(data):
    out = bytearray()
    node = _TREE
    for byte in data:
        for i in range(7, -1, -1):
            nxt = node[(byte >> i) & 1]
            if nxt is None:
                raise ValueError('bad huffman data')
            if isinstance(nxt, int):
                if nxt == 256:
                    raise ValueError('EOS inside a string')
                out.append(nxt)
                node = _TREE
            else:
                node = nxt
    return bytes(out)                       # leftover bits are padding


# ── integers ──────────────────────────────────────────────────────────────────────────────────────────────

def _qvarint(b, i):
    """QUIC variable-length integer -> (value, next index)."""
    first = b[i]
    n = 1 << (first >> 6)
    if i + n > len(b):
        raise IndexError('truncated varint')
    v = first & 0x3f
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def _pint(b, i, prefix):
    """HPACK/QPACK prefixed integer (the low `prefix` bits of b[i] start it) -> (value, next index)."""
    mask = (1 << prefix) - 1
    v = b[i] & mask
    i += 1
    if v < mask:
        return v, i
    m = 0
    while True:
        byte = b[i]
        i += 1
        v += (byte & 0x7f) << m
        m += 7
        if not byte & 0x80:
            return v, i
        if m > 56:
            raise ValueError('integer too long')


def _pstr(b, i, prefix):
    """String literal: [H flag at bit `prefix`] length(prefix) bytes -> (text, next index)."""
    huff = bool(b[i] & (1 << prefix))
    n, i = _pint(b, i, prefix)
    if i + n > len(b):
        raise IndexError('truncated string')
    raw = bytes(b[i:i + n])
    if huff:
        raw = _huff_decode(raw)
    return raw.decode('utf-8', 'replace'), i + n


# ── QPACK field sections ──────────────────────────────────────────────────────────────────────────────────

def _decode_fields(block):
    """Returns (headers, uses_dynamic_table). headers: list of (name, value)."""
    i = 0
    ric, i = _pint(block, i, 8)                 # required insert count (encoded)
    _delta, i = _pint(block, i, 7)              # delta base (the sign bit is part of the first byte)
    headers = []
    dynamic = ric != 0
    dyn = ''                                    # the dynamic table is built by another stream: no value here
    while i < len(block):
        b = block[i]
        if b & 0x80:                            # indexed field line
            static = bool(b & 0x40)
            idx, i = _pint(block, i, 6)
            if static:
                if idx >= len(_STATIC):
                    raise ValueError('static index out of range')
                headers.append(_STATIC[idx])
            else:
                dynamic = True
                headers.append(('[dynamic table entry %d]' % idx, dyn))
        elif b & 0x40:                          # literal with name reference
            static = bool(b & 0x10)
            idx, i = _pint(block, i, 4)
            value, i = _pstr(block, i, 7)
            if static:
                if idx >= len(_STATIC):
                    raise ValueError('static index out of range')
                headers.append((_STATIC[idx][0], value))
            else:
                dynamic = True
                headers.append(('[dynamic table entry %d]' % idx, value))
        elif b & 0x20:                          # literal with literal name
            name, i = _pstr(block, i, 3)
            value, i = _pstr(block, i, 7)
            headers.append((name, value))
        elif b & 0x10:                          # indexed, post-base
            idx, i = _pint(block, i, 4)
            dynamic = True
            headers.append(('[dynamic table entry (post-base) %d]' % idx, dyn))
        else:                                   # literal with post-base name reference
            idx, i = _pint(block, i, 3)
            value, i = _pstr(block, i, 7)
            dynamic = True
            headers.append(('[dynamic table entry (post-base) %d]' % idx, value))
    return headers, dynamic


# ── HTTP/3 frames and streams ─────────────────────────────────────────────────────────────────────────────

_FRAME_NAMES = {0x00: 'DATA', 0x01: 'HEADERS', 0x03: 'CANCEL_PUSH', 0x04: 'SETTINGS', 0x05: 'PUSH_PROMISE',
                0x07: 'GOAWAY', 0x0d: 'MAX_PUSH_ID', 0xf0700: 'PRIORITY_UPDATE (request)', 0xf0701: 'PRIORITY_UPDATE (push)'}
_SETTING_NAMES = {0x01: 'QPACK_MAX_TABLE_CAPACITY', 0x06: 'MAX_FIELD_SECTION_SIZE', 0x07: 'QPACK_BLOCKED_STREAMS',
                  0x08: 'ENABLE_CONNECT_PROTOCOL', 0x33: 'H3_DATAGRAM', 0xffd277: 'H3_DATAGRAM (draft)',
                  0x2b603742: 'ENABLE_WEBTRANSPORT'}
_STREAM_NAMES = {0x00: 'control stream', 0x01: 'push stream', 0x02: 'QPACK encoder stream', 0x03: 'QPACK decoder stream'}


def _is_grease(v):
    return v >= 0x21 and (v - 0x21) % 0x1f == 0


def _frames(b, i=0):
    """Frames from offset i: list of (type, declared length, payload bytes present, complete?). Stops at garbage."""
    out = []
    while i < len(b):
        try:
            t, j = _qvarint(b, i)
            n, j = _qvarint(b, j)
        except IndexError:
            break
        payload = bytes(b[j:j + n])
        out.append((t, n, payload, len(payload) == n))
        i = j + n
    return out


def _frame_name(t):
    if t in _FRAME_NAMES:
        return _FRAME_NAMES[t]
    return 'GREASE (reserved 0x%x)' % t if _is_grease(t) else 'unknown 0x%x' % t


def _settings(payload):
    out, i = [], 0
    while i < len(payload):
        k, i = _qvarint(payload, i)
        v, i = _qvarint(payload, i)
        name = _SETTING_NAMES.get(k, 'GREASE' if _is_grease(k) else 'unknown 0x%x' % k)
        out.append((name, v))
    return out


def _hdr_get(headers, name):
    for k, v in headers:
        if k == name:
            return v
    return None


def _size(n):
    return '%d B' % n if n < 1024 else '%.1f KB' % (n / 1024)


def _decompress(body, encoding):
    """Returns (text bytes, note). Works on a prefix of the body: whatever decodes is shown."""
    enc = (encoding or '').lower().strip()
    try:
        if enc in ('gzip', 'x-gzip'):
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            return d.decompress(body), None
        if enc == 'deflate':
            try:
                return zlib.decompressobj().decompress(body), None
            except zlib.error:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(body), None
        if enc == 'br':
            try:
                import brotli
            except ImportError:
                return None, 'brotli body not decoded: the `brotli` Python module is not installed in the app\'s Python'
            return brotli.Decompressor().process(body), None
        if enc == 'zstd':
            try:
                import zstandard
            except ImportError:
                return None, 'zstd body not decoded: the `zstandard` Python module is not installed in the app\'s Python'
            return zstandard.ZstdDecompressor().decompressobj().decompress(body), None
    except Exception as e:                        # a body cut short in the middle of a block is normal here
        return None, 'could not decode the %s body (%s)' % (enc, e)
    return body, None


def _printable(b):
    if not b:
        return True
    sample = b[:2000]
    bad = sum(1 for c in sample if c < 9 or (13 < c < 32 and c != 27) or c == 127)
    return bad * 20 < len(sample)


def _hexdump(b, limit=256):
    rows = []
    for off in range(0, min(len(b), limit), 16):
        chunk = b[off:off + 16]
        rows.append('%08x  %-47s  |%s|' % (off, ' '.join('%02x' % c for c in chunk),
                                          ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)))
    return '\n'.join(rows)


def _render_message(frames, total_len, headers):
    """A request or response stream whose first real frame is HEADERS: start line, headers, blank line, body."""
    hdrs = headers[0]
    status = _hdr_get(hdrs, ':status')
    if status is not None:
        lines = ['HTTP/3 %s' % status]
    else:
        lines = ['%s %s://%s%s HTTP/3' % (_hdr_get(hdrs, ':method') or '?', _hdr_get(hdrs, ':scheme') or 'https',
                                           _hdr_get(hdrs, ':authority') or '', _hdr_get(hdrs, ':path') or '')]
    for k, v in hdrs:
        if not k.startswith(':'):
            lines.append('%s: %s' % (k, v))

    body = b''.join(p for t, n, p, c in frames if t == 0x00)
    if body:
        data, _note = _decompress(body, _hdr_get(hdrs, 'content-encoding'))
        if data is None:
            data = body                             # not decodable here: the bytes as they are
        lines.append('')
        if _printable(data):
            text = data.decode('utf-8', 'replace')
            lines.append(text[:_MAX_TEXT])
        else:
            lines.append(_hexdump(data, 1 << 20))
    return '\n'.join(lines)


def _decode(raw):
    """Returns the text for this entry, or None when it is not something this extension can read."""
    if len(raw) < 2:
        return None

    try:
        stype, j = _qvarint(raw, 0)
    except IndexError:
        return None

    # 1. the control stream: stream type 0, then SETTINGS
    if stype == 0x00 and len(raw) >= 3 and raw[1] == 0x04:
        fr = _frames(raw, 1)
        if fr and fr[0][0] == 0x04 and fr[0][3]:
            try:
                st = _settings(fr[0][2])
            except IndexError:
                st = None
            if st is not None:
                lines = ['%s: %d' % (k, v) for k, v in st]
                return '\n'.join(lines)

    # 2. a request/response stream: [reserved frames] HEADERS [DATA ...]. Tried before "reserved stream": a response often
    #    starts with a reserved frame, whose type looks just like a reserved stream type.
    fr = _frames(raw)
    if fr:
        k = 0
        while k < len(fr) and _is_grease(fr[k][0]):
            k += 1
        if k < len(fr) and fr[k][0] == 0x01 and fr[k][3]:
            try:
                headers = _decode_fields(fr[k][2])
            except (IndexError, ValueError):
                headers = None
            if headers is not None:
                names = [h[0] for h in headers[0]]
                if ':method' in names or ':status' in names:
                    return _render_message(fr, len(raw), headers)

    # 3. a reserved ("GREASE") unidirectional stream
    if _is_grease(stype) and len(raw) >= 2:
        return raw[j:j + 200].decode(_LAT1)

    # 4. QPACK encoder/decoder streams carry instructions, not decoded here
    return None


# ── encoding (editing) ────────────────────────────────────────────────────────────────────────────────────────

_STATIC_EXACT = {}
_STATIC_NAME = {}
for _i, (_n, _v) in enumerate(_STATIC):
    _STATIC_EXACT.setdefault((_n, _v), _i)
    _STATIC_NAME.setdefault(_n, _i)


def _enc_varint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return bytes([0x40 | (v >> 8), v & 0xff])
    if v < 1073741824:
        return bytes([0x80 | (v >> 24), (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff])
    return bytes([0xc0 | (v >> 56)] + [(v >> s) & 0xff for s in range(48, -8, -8)])


def _enc_pint(value, prefix, first_bits):
    """HPACK/QPACK prefixed integer: first_bits are the bits above the prefix."""
    mask = (1 << prefix) - 1
    if value < mask:
        return bytes([first_bits | value])
    out = bytearray([first_bits | mask])
    value -= mask
    while value >= 128:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _enc_fields(headers):
    """A QPACK field section using only the static table (required insert count 0) and plain (non-Huffman) strings."""
    out = bytearray(b'\x00\x00')
    for name, value in headers:
        idx = _STATIC_EXACT.get((name, value))
        if idx is not None:
            out += _enc_pint(idx, 6, 0xC0)                       # indexed field line, static
            continue
        vb = value.encode('utf-8')
        nidx = _STATIC_NAME.get(name)
        if nidx is not None:
            out += _enc_pint(nidx, 4, 0x50)                      # literal, name from the static table
        else:
            nb = name.encode('utf-8')
            out += _enc_pint(len(nb), 3, 0x20) + nb              # literal with literal name
        out += _enc_pint(len(vb), 7, 0x00) + vb
    return bytes(out)


def _frame(ftype, payload):
    return _enc_varint(ftype) + _enc_varint(len(payload)) + payload


def _spans(b):
    """Frames from offset 0 as (start, end, type, declared length, complete) - end is clipped to the data."""
    out = []
    i = 0
    while i < len(b):
        try:
            t, j = _qvarint(b, i)
            n, j = _qvarint(b, j)
        except IndexError:
            break
        out.append((i, min(j + n, len(b)), t, n, j + n <= len(b)))
        i = j + n
    return out


def _compress(data, encoding):
    enc = (encoding or '').lower().strip()
    if enc in ('', 'identity'):
        return data
    if enc in ('gzip', 'x-gzip'):
        c = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        return c.compress(data) + c.flush()
    if enc == 'deflate':
        return zlib.compress(data)
    if enc == 'br':
        try:
            import brotli
        except ImportError:
            return None
        return brotli.compress(data)
    if enc == 'zstd':
        try:
            import zstandard
        except ImportError:
            return None
        return zstandard.ZstdCompressor().compress(data)
    return None


def _body_of(frames, hdrs):
    """(text or None, complete) of the body held in these frames, exactly as the tab shows it."""
    data_frames = [f for f in frames if f[0] == 0x00]
    complete = all(f[3] for f in data_frames)
    if not data_frames:
        return '', True
    body = b''.join(f[2] for f in data_frames)
    data, _note = _decompress(body, _hdr_get(hdrs, 'content-encoding'))
    if data is None:
        data = body
    if not _printable(data):
        return None, complete
    text = data.decode('utf-8', 'replace')
    if len(text) > _MAX_TEXT:
        return None, False
    return text, complete


def _message(raw):
    """(frames, index of the HEADERS frame, (headers, dynamic)) for a request/response entry, else None."""
    fr = _frames(raw)
    k = 0
    while k < len(fr) and _is_grease(fr[k][0]):
        k += 1
    if k >= len(fr) or fr[k][0] != 0x01 or not fr[k][3]:
        return None
    try:
        headers = _decode_fields(fr[k][2])
    except (IndexError, ValueError):
        return None
    names = [h[0] for h in headers[0]]
    if ':method' not in names and ':status' not in names:
        return None
    return fr, k, headers


def _parse_edit(text, orig_hdrs):
    """The edited tab text -> (headers incl. pseudo-headers, body text), or None when it is not a valid message."""
    text = text.replace('\r\n', '\n')
    head, _sep, body = text.partition('\n\n')
    lines = head.split('\n')
    start = lines[0].strip()
    pseudo = []
    m = re.match(r'^HTTP/3\s+(\d{3})\b', start)
    if m:
        pseudo = [(':status', m.group(1))]
    else:
        m = re.match(r'^(\S+)\s+(\S+)\s+HTTP/3$', start)
        if not m:
            return None
        method, url = m.group(1), m.group(2)
        if url.startswith('/'):
            scheme, auth, path = _hdr_get(orig_hdrs, ':scheme') or 'https', _hdr_get(orig_hdrs, ':authority') or '', url
        else:
            u = urlsplit(url)
            if not u.scheme or not u.netloc:
                return None
            scheme, auth = u.scheme, u.netloc
            path = (u.path or '/') + ('?' + u.query if u.query else '')
        pseudo = [(':method', method), (':scheme', scheme), (':authority', auth), (':path', path)]
    headers = []
    for ln in lines[1:]:
        if not ln.strip():
            continue
        name, colon, value = ln.partition(':')
        if not colon or not name.strip():
            return None
        headers.append((name.strip().lower(), value.strip()))
    return pseudo + headers, body


def _encode(raw, edited):
    """Raw bytes of the entry with the edit applied, or None when nothing changed / it cannot be applied safely."""
    msg = _message(raw)
    if msg is None:
        return None
    frames, k, (ohdrs, dynamic) = msg
    if dynamic or any(n.startswith('[dynamic') for n, _v in ohdrs):
        return None                                     # the dynamic table is not here: cannot rebuild these headers
    original = _decode(raw)
    if original is None:
        return None
    if edited.replace('\r\n', '\n').strip() == original.replace('\r\n', '\n').strip():
        return None
    parsed = _parse_edit(edited, ohdrs)
    if parsed is None:
        return None
    new_hdrs, new_body = parsed

    spans = _spans(raw)
    after_start = spans[k][1]                            # everything after the HEADERS frame
    after = frames[k + 1:]
    orig_text, complete = _body_of(after, ohdrs)
    same_body = new_body.replace('\r\n', '\n') == (orig_text or '').replace('\r\n', '\n')

    if same_body:
        tail = raw[after_start:]                         # body frames and everything else: byte for byte
    else:
        if orig_text is None or not complete:
            return None                                  # binary, truncated, or continued in later entries
        comp = _compress(new_body.encode('utf-8'), _hdr_get(new_hdrs, 'content-encoding'))
        if comp is None:
            return None
        if any(n == 'content-length' for n, _v in new_hdrs):
            new_hdrs = [(n, str(len(comp)) if n == 'content-length' else v) for n, v in new_hdrs]
        others = b''.join(raw[s:e] for (s, e, ft, ln, c) in spans[k + 1:] if ft != 0x00)
        tail = (_frame(0x00, comp) if comp else b'') + others

    return raw[:spans[k][0]] + _frame(0x01, _enc_fields(new_hdrs)) + tail


class _HTTP3Handler:

    def _raw(self, data):
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
        try:
            return _decode(self._raw(data)) is not None
        except Exception:
            return False

    def fetchdata(self, data):
        try:
            text = _decode(self._raw(data))
        except Exception as e:
            return 'HTTP/3 decoder error: %s' % e
        return text if text is not None else ''

    def updatedata(self, data):
        edited = data.get('edited_data', '')
        if not edited or not edited.strip():
            return None
        raw = self._raw(data)
        if not raw:
            return None
        try:
            out = _encode(raw, edited)
        except Exception:
            return None                          # never send half-built bytes
        return out.decode(_LAT1) if out is not None else None


class InterceptSuiteExtension:

    def register_interceptor_api(self, interceptor):
        interceptor.set_extension_name('HTTP/3 Decoder')
        interceptor.set_extension_version('1.0.0')
        interceptor.AddDataViewerTab('HTTP/3', _HTTP3Handler())
        ExtensionLogger.Log('HTTP/3 Decoder loaded')
