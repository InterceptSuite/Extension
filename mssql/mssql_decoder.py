from InterceptSuite.Extensions.APIs.Logging import ExtensionLogger
import struct
import uuid
from datetime import date, datetime, timedelta

_MSSQL_PORT = 1433
_LAT1       = 'latin-1'
_NULLV      = 'NULL'

# TDS packet types (header byte 0)
_T_SQLBATCH  = 0x01
_T_LOGIN7OLD = 0x02
_T_RPC       = 0x03
_T_TABULAR   = 0x04
_T_ATTENTION = 0x06
_T_BULKLOAD  = 0x07
_T_FEDAUTH   = 0x08
_T_TMREQ     = 0x0E
_T_LOGIN7    = 0x10
_T_SSPI      = 0x11
_T_PRELOGIN  = 0x12

_KNOWN_TYPES = frozenset({
    _T_SQLBATCH, _T_LOGIN7OLD, _T_RPC, _T_TABULAR, _T_ATTENTION,
    _T_BULKLOAD, _T_FEDAUTH, _T_TMREQ, _T_LOGIN7, _T_SSPI, _T_PRELOGIN,
})

# TYPE_INFO categories
_FIXED_LEN = {
    0x1F: 0,   # NULLTYPE
    0x30: 1,   # INT1TYPE
    0x32: 1,   # BITTYPE
    0x34: 2,   # INT2TYPE
    0x38: 4,   # INT4TYPE
    0x3A: 4,   # DATETIM4TYPE
    0x3B: 4,   # FLT4TYPE
    0x3C: 8,   # MONEYTYPE
    0x3D: 8,   # DATETIMETYPE
    0x3E: 8,   # FLT8TYPE
    0x59: 4,   # MONEY4TYPE
    0x7A: 8,   # INT8TYPE
}
_MAXLEN_ONLY = {0x24, 0x26, 0x68, 0x6D, 0x6E, 0x6F}   # GUID INTN BITN FLTN MONEYN DATETIMN
_PRECSCALE   = {0x37, 0x3F, 0x6A, 0x6C}               # DECIMAL NUMERIC DECIMALN NUMERICN
_SCALE_ONLY  = {0x29, 0x2A, 0x2B}                     # TIMEN DATETIME2N DATETIMEOFFSETN
_BIGLEN2     = {0xA5, 0xAD}                           # BIGVARBIN BIGBINARY
_BIGLEN2_COL = {0xA7, 0xAF, 0xE7, 0xEF}                # BIGVARCHR BIGCHAR NVARCHAR NCHAR


# low-level helpers

def _read_b_varchar(buf, pos):
    blen = buf[pos]; pos += 1
    s = buf[pos:pos+blen*2].decode('utf-16-le', errors='replace')
    return s, pos + blen*2


def _read_us_varchar(buf, pos):
    blen = struct.unpack('<H', buf[pos:pos+2])[0]; pos += 2
    s = buf[pos:pos+blen*2].decode('utf-16-le', errors='replace')
    return s, pos + blen*2


def _deobfuscate(b):
    out = bytearray()
    for byte in b:
        byte ^= 0xA5
        byte = ((byte << 4) | (byte >> 4)) & 0xFF
        out.append(byte)
    return bytes(out)


def _obfuscate(b):
    out = bytearray()
    for byte in b:
        byte = ((byte << 4) | (byte >> 4)) & 0xFF
        byte ^= 0xA5
        out.append(byte)
    return bytes(out)


# TYPE_INFO / value parsing (shared by RPC params, COLMETADATA, ROW)

def _read_typeinfo(buf, pos):
    tok = buf[pos]; pos += 1
    info = {'type': tok}
    if tok in _FIXED_LEN:
        info['fixed_len'] = _FIXED_LEN[tok]
        return info, pos
    if tok == 0x28:                       # DATEN - no extra type bytes
        return info, pos
    if tok in _MAXLEN_ONLY:
        info['maxlen'] = buf[pos]; pos += 1
        return info, pos
    if tok in _PRECSCALE:
        info['maxlen']    = buf[pos]; pos += 1
        info['precision'] = buf[pos]; pos += 1
        info['scale']     = buf[pos]; pos += 1
        return info, pos
    if tok in _SCALE_ONLY:
        info['scale'] = buf[pos]; pos += 1
        return info, pos
    if tok in _BIGLEN2:
        info['maxlen'] = struct.unpack('<H', buf[pos:pos+2])[0]; pos += 2
        return info, pos
    if tok in _BIGLEN2_COL:
        info['maxlen']    = struct.unpack('<H', buf[pos:pos+2])[0]; pos += 2
        info['collation'] = buf[pos:pos+5]; pos += 5
        return info, pos
    raise ValueError('unsupported TDS type 0x%02x' % tok)


def _fmt_money8(v):
    hi = int.from_bytes(v[0:4], 'little', signed=True)
    lo = int.from_bytes(v[4:8], 'little', signed=False)
    return f'{((hi << 32) | lo) / 10000:.4f}'


def _fmt_money4(v):
    return f'{struct.unpack("<i", v)[0] / 10000:.4f}'


def _fmt_smalldatetime(v):
    days, mins = struct.unpack('<HH', v)
    return (datetime(1900, 1, 1) + timedelta(days=days, minutes=mins)).strftime('%Y-%m-%d %H:%M:%S')


def _fmt_datetime(v):
    days, ticks = struct.unpack('<ii', v)
    dt = datetime(1900, 1, 1) + timedelta(days=days, seconds=ticks/300.0)
    return dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def _fmt_decimal(v, scale):
    sign = v[0]
    mag  = int.from_bytes(v[1:], 'little', signed=False)
    if sign == 0:
        mag = -mag
    if scale == 0:
        return str(mag)
    s = str(abs(mag)).rjust(scale + 1, '0')
    result = f'{s[:-scale]}.{s[-scale:]}'
    return ('-' if mag < 0 else '') + result


def _fmt_date(b3):
    n = b3[0] | (b3[1] << 8) | (b3[2] << 16)
    try:
        return date.fromordinal(n + 1).isoformat()
    except Exception:
        return f'day{n}'


def _fmt_time(b, scale):
    n = int.from_bytes(b, 'little')
    total = n / (10 ** scale) if scale <= 15 else 0
    h = int(total // 3600)
    rem = total - h*3600
    m = int(rem // 60)
    s = rem - m*60
    return f'{h:02d}:{m:02d}:{s:09.6f}'


def _fmt_fixed(tok, v):
    if tok == 0x32: return '1' if v[0] else '0'
    if tok == 0x30: return str(v[0])
    if tok == 0x34: return str(struct.unpack('<h', v)[0])
    if tok == 0x38: return str(struct.unpack('<i', v)[0])
    if tok == 0x7A: return str(struct.unpack('<q', v)[0])
    if tok == 0x3B: return repr(struct.unpack('<f', v)[0])
    if tok == 0x3E: return repr(struct.unpack('<d', v)[0])
    if tok == 0x3C: return _fmt_money8(v)
    if tok == 0x59: return _fmt_money4(v)
    if tok == 0x3A: return _fmt_smalldatetime(v)
    if tok == 0x3D: return _fmt_datetime(v)
    return v.hex()


def _fmt_varlen(tok, v, info):
    if tok == 0x24:
        return str(uuid.UUID(bytes_le=bytes(v)))
    if tok == 0x26:
        n = len(v)
        if n == 1: return str(v[0])
        if n == 2: return str(struct.unpack('<h', v)[0])
        if n == 4: return str(struct.unpack('<i', v)[0])
        if n == 8: return str(struct.unpack('<q', v)[0])
        return v.hex()
    if tok == 0x68:
        return '1' if v[0] else '0'
    if tok == 0x6D:
        if len(v) == 4: return repr(struct.unpack('<f', v)[0])
        if len(v) == 8: return repr(struct.unpack('<d', v)[0])
        return v.hex()
    if tok == 0x6E:
        if len(v) == 4: return _fmt_money4(v)
        if len(v) == 8: return _fmt_money8(v)
        return v.hex()
    if tok == 0x6F:
        if len(v) == 4: return _fmt_smalldatetime(v)
        if len(v) == 8: return _fmt_datetime(v)
        return v.hex()
    if tok in _PRECSCALE:
        return _fmt_decimal(v, info.get('scale', 0))
    return v.hex()


def _fmt_scaled(tok, v, info):
    scale = info.get('scale', 7)
    if tok == 0x29:                       # TIMEN
        return _fmt_time(v, scale)
    if tok == 0x2A:                       # DATETIME2N: time..(n) + date(3)
        return f'{_fmt_date(v[-3:])} {_fmt_time(v[:-3], scale)}'
    if tok == 0x2B:                       # DATETIMEOFFSETN: time..(n) + date(3) + offset(2)
        offmin = struct.unpack('<h', v[-2:])[0]
        sign = '+' if offmin >= 0 else '-'
        a = abs(offmin)
        return (f'{_fmt_date(v[-5:-2])} {_fmt_time(v[:-5], scale)} '
                f'{sign}{a//60:02d}:{a%60:02d}')
    return v.hex()


def _read_plp_bytes(buf, pos, wide, as_hex):
    total = struct.unpack('<Q', buf[pos:pos+8])[0]; pos += 8
    if total == 0xFFFFFFFFFFFFFFFF:
        return _NULLV, pos
    data = b''
    while True:
        clen = struct.unpack('<I', buf[pos:pos+4])[0]; pos += 4
        if clen == 0:
            break
        data += buf[pos:pos+clen]; pos += clen
    if as_hex:
        return data.hex(), pos
    return data.decode('utf-16-le' if wide else _LAT1, errors='replace'), pos


def _read_value(buf, pos, info):
    tok = info['type']
    if 'fixed_len' in info:
        n = info['fixed_len']
        if n == 0:
            return _NULLV, pos
        v = buf[pos:pos+n]
        return _fmt_fixed(tok, v), pos + n
    if tok == 0x28:                       # DATEN
        blen = buf[pos]; pos += 1
        if blen == 0:
            return _NULLV, pos
        v = buf[pos:pos+blen]
        return _fmt_date(v), pos + blen
    if tok in _MAXLEN_ONLY or tok in _PRECSCALE:
        blen = buf[pos]; pos += 1
        if blen == 0:
            return _NULLV, pos
        v = buf[pos:pos+blen]
        return _fmt_varlen(tok, v, info), pos + blen
    if tok in _SCALE_ONLY:
        blen = buf[pos]; pos += 1
        if blen == 0:
            return _NULLV, pos
        v = buf[pos:pos+blen]
        return _fmt_scaled(tok, v, info), pos + blen
    if tok in _BIGLEN2:
        if info['maxlen'] == 0xFFFF:
            return _read_plp_bytes(buf, pos, False, True)
        l = struct.unpack('<H', buf[pos:pos+2])[0]; pos += 2
        if l == 0xFFFF:
            return _NULLV, pos
        return buf[pos:pos+l].hex(), pos + l
    if tok in _BIGLEN2_COL:
        wide = tok in (0xE7, 0xEF)
        if info['maxlen'] == 0xFFFF:
            return _read_plp_bytes(buf, pos, wide, False)
        l = struct.unpack('<H', buf[pos:pos+2])[0]; pos += 2
        if l == 0xFFFF:
            return _NULLV, pos
        v = buf[pos:pos+l]
        return v.decode('utf-16-le' if wide else _LAT1, errors='replace'), pos + l
    raise ValueError('unsupported TDS value')


# frame parser

def _parse_msgs(raw):
    msgs, i = [], 0
    while i + 8 <= len(raw):
        mtype  = raw[i]
        status = raw[i+1]
        length = struct.unpack('>H', raw[i+2:i+4])[0]
        if length < 8:
            break
        pend = i + length
        payload = raw[i+8:pend] if pend <= len(raw) else raw[i+8:]
        msgs.append({'type': mtype, 'status': status, 'payload': payload,
                     'raw': raw[i:min(pend, len(raw))]})
        if pend > len(raw):
            break
        i = pend
    return msgs


# ALL_HEADERS (used by SQLBatch/RPC/BulkLoad/TMRequest) detection

def _skip_all_headers(pl):
    if len(pl) < 12:
        return 0
    total = struct.unpack('<I', pl[0:4])[0]
    if not (10 <= total <= len(pl)):
        return 0
    hdr_len  = struct.unpack('<I', pl[4:8])[0]
    hdr_type = struct.unpack('<H', pl[8:10])[0]
    if hdr_type != 0x0002 or not (10 <= hdr_len <= total):
        return 0
    return total


# PRELOGIN (0x12)

_PL_NAMES     = {0: 'VERSION', 1: 'ENCRYPTION', 2: 'INSTANCE', 3: 'THREADID',
                 4: 'MARS', 5: 'TRACEID', 6: 'FEDAUTHREQUIRED', 7: 'NONCE'}
_PL_ENC_NAMES = {0: 'OFF', 1: 'ON', 2: 'NOT_SUPPORTED', 3: 'REQUIRED'}


def _dec_prelogin(pl):
    tokens, i = [], 0
    while i + 5 <= len(pl):
        ttype = pl[i]
        if ttype == 0xFF:
            break
        off = struct.unpack('>H', pl[i+1:i+3])[0]
        tl  = struct.unpack('>H', pl[i+3:i+5])[0]
        tokens.append((ttype, off, tl))
        i += 5
    lines = []
    for ttype, off, tl in tokens:
        chunk = pl[off:off+tl]
        name = _PL_NAMES.get(ttype, f'OPT{ttype}')
        if ttype == 0 and tl >= 4:
            val = f'{chunk[0]}.{chunk[1]}.{(chunk[2] << 8) | chunk[3]}'
        elif ttype == 1 and tl >= 1:
            val = _PL_ENC_NAMES.get(chunk[0], str(chunk[0]))
        elif ttype == 2:
            val = chunk.rstrip(b'\x00').decode('ascii', errors='replace')
        elif ttype == 4 and tl >= 1:
            val = 'ON' if chunk[0] else 'OFF'
        elif ttype == 6 and tl >= 1:
            val = 'ON' if chunk[0] else 'OFF'
        else:
            val = chunk.hex()
        lines.append(f'{name}={val}')
    return '\n'.join(lines)


# LOGIN7 (0x10) - includes cleartext-recoverable credentials

_LOGIN7_FIELDS = ['host', 'user', 'pass', 'app', 'server', 'ext',
                  'cltint', 'lang', 'db']


def _login7_layout(pl):
    """Parse fixed header + offset/length block. Returns dict of raw parts."""
    if len(pl) < 94:
        return None
    header = pl[4:36]                      # everything after Length, before offset block
    pos = 36
    offs = {}
    for name in _LOGIN7_FIELDS:
        off = struct.unpack('<H', pl[pos:pos+2])[0]
        cnt = struct.unpack('<H', pl[pos+2:pos+4])[0]
        offs[name] = (off, cnt)
        pos += 4
    client_id = pl[pos:pos+6]; pos += 6
    for name in ['sspi', 'atch', 'chpass']:
        off = struct.unpack('<H', pl[pos:pos+2])[0]
        cnt = struct.unpack('<H', pl[pos+2:pos+4])[0]
        offs[name] = (off, cnt)
        pos += 4
    cb_sspi_long = struct.unpack('<I', pl[pos:pos+4])[0]; pos += 4
    return {'header': header, 'offs': offs, 'client_id': client_id,
            'cb_sspi_long': cb_sspi_long}


def _dec_login7(pl):
    lay = _login7_layout(pl)
    if lay is None:
        return ''
    offs = lay['offs']

    def wstr(name):
        off, cnt = offs[name]
        if cnt == 0:
            return ''
        return pl[off:off+cnt*2].decode('utf-16-le', errors='replace')

    def wstr_obf(name):
        off, cnt = offs[name]
        if cnt == 0:
            return ''
        return _deobfuscate(pl[off:off+cnt*2]).decode('utf-16-le', errors='replace')

    header = lay['header']
    tds_version = struct.unpack('<I', header[0:4])[0]
    packet_size = struct.unpack('<I', header[4:8])[0]
    client_pid  = struct.unpack('<I', header[12:16])[0]
    mac = ':'.join(f'{b:02x}' for b in lay['client_id'])

    lines = [
        f'TDSVersion=0x{tds_version:08X}',
        f'PacketSize={packet_size}',
        f'ClientPID={client_pid}',
        f'Hostname={wstr("host")}',
        f'Username={wstr("user")}',
        f'Password={wstr_obf("pass")}',
        f'AppName={wstr("app")}',
        f'ServerName={wstr("server")}',
        f'ClientLibrary={wstr("cltint")}',
        f'Language={wstr("lang")}',
        f'Database={wstr("db")}',
        f'ClientMAC={mac}',
    ]
    atch = wstr('atch')
    if atch:
        lines.append(f'AttachDBFile={atch}')
    chpass = wstr_obf('chpass')
    if chpass:
        lines.append(f'ChangePassword={chpass}')
    return '\n'.join(lines)


def _parse_kv(text):
    d = {}
    for line in text.split('\n'):
        if '=' in line:
            k, v = line.split('=', 1)
            d[k.strip()] = v
    return d


def _enc_login7(text, pl):
    lay = _login7_layout(pl)
    if lay is None:
        return None
    offs = lay['offs']
    # long SSPI blobs are not supported for re-encoding
    if offs['sspi'][1] == 0xFFFF or lay['cb_sspi_long']:
        return None

    ext_blob  = pl[offs['ext'][0]:offs['ext'][0] + offs['ext'][1]]
    sspi_blob = pl[offs['sspi'][0]:offs['sspi'][0] + offs['sspi'][1]]

    fields = _parse_kv(text)
    base = 94   # header(36) + offset block(58)

    var_data = b''
    new_offs = {}

    def add(name, value, obfuscate=False):
        nonlocal var_data
        b = _obfuscate(value.encode('utf-16-le')) if obfuscate else value.encode('utf-16-le')
        new_offs[name] = (base + len(var_data), len(value))
        var_data += b

    add('host',   fields.get('Hostname', ''))
    add('user',   fields.get('Username', ''))
    add('pass',   fields.get('Password', ''), obfuscate=True)
    add('app',    fields.get('AppName', ''))
    add('server', fields.get('ServerName', ''))
    new_offs['ext'] = (base + len(var_data), len(ext_blob))
    var_data += ext_blob
    add('cltint', fields.get('ClientLibrary', ''))
    add('lang',   fields.get('Language', ''))
    add('db',     fields.get('Database', ''))
    new_offs['sspi'] = (base + len(var_data), len(sspi_blob))
    var_data += sspi_blob
    add('atch',   fields.get('AttachDBFile', ''))
    add('chpass', fields.get('ChangePassword', ''), obfuscate=True)

    offset_block = b''
    for name in _LOGIN7_FIELDS:
        off, cnt = new_offs[name]
        offset_block += struct.pack('<HH', off, cnt)
    offset_block += lay['client_id']
    for name in ['sspi', 'atch', 'chpass']:
        off, cnt = new_offs[name]
        offset_block += struct.pack('<HH', off, cnt)
    offset_block += struct.pack('<I', 0)   # cbSSPILong

    total_len = 4 + len(lay['header']) + len(offset_block) + len(var_data)
    return struct.pack('<I', total_len) + lay['header'] + offset_block + var_data


# SQLBatch (0x01)

def _dec_sqlbatch(pl):
    off = _skip_all_headers(pl)
    return pl[off:].decode('utf-16-le', errors='replace')


def _enc_sqlbatch(text, pl):
    off = _skip_all_headers(pl)
    return pl[:off] + text.encode('utf-16-le')


# RPC Request (0x03)

_RPC_PROCNAMES = {
    1: 'Sp_Cursor', 2: 'Sp_CursorOpen', 3: 'Sp_CursorPrepare',
    4: 'Sp_CursorExecute', 5: 'Sp_CursorPrepExec', 6: 'Sp_CursorUnprepare',
    7: 'Sp_CursorFetch', 8: 'Sp_CursorOption', 9: 'Sp_CursorClose',
    10: 'Sp_ExecuteSql', 11: 'Sp_Prepare', 12: 'Sp_Execute',
    13: 'Sp_PrepExec', 14: 'Sp_PrepExecRpc', 15: 'Sp_Unprepare',
}


def _dec_rpc(pl):
    pos = _skip_all_headers(pl)
    if pos + 2 > len(pl):
        return ''
    namelen = struct.unpack('<H', pl[pos:pos+2])[0]; pos += 2
    if namelen == 0xFFFF:
        procid = struct.unpack('<H', pl[pos:pos+2])[0]; pos += 2
        name = _RPC_PROCNAMES.get(procid, f'#{procid}')
    else:
        name = pl[pos:pos+namelen*2].decode('utf-16-le', errors='replace')
        pos += namelen*2
    lines = [name]
    if pos + 2 > len(pl):
        return '\n'.join(lines)
    pos += 2   # OptionFlags
    try:
        while pos < len(pl):
            plen = pl[pos]; pos += 1
            pname = ''
            if plen:
                pname = pl[pos:pos+plen*2].decode('utf-16-le', errors='replace')
                pos += plen*2
            pos += 1   # StatusFlags
            info, pos = _read_typeinfo(pl, pos)
            val, pos = _read_value(pl, pos, info)
            lines.append(f'{pname}={val}' if pname else f'={val}')
    except Exception:
        pass
    return '\n'.join(lines)


# TabularResult (0x04) - server response token stream

def _dec_error_info(pl, pos):
    tlen = struct.unpack('<H', pl[pos:pos+2])[0]; pos += 2
    start = pos
    number = struct.unpack('<I', pl[pos:pos+4])[0]; pos += 4
    state  = pl[pos]; pos += 1
    cls    = pl[pos]; pos += 1
    msg, pos    = _read_us_varchar(pl, pos)
    server, pos = _read_b_varchar(pl, pos)
    proc, pos   = _read_b_varchar(pl, pos)
    line = struct.unpack('<I', pl[pos:pos+4])[0]; pos += 4
    text = f'Number={number} State={state} Class={cls} Message={msg} Server={server} Proc={proc} Line={line}'
    return text, start + tlen


def _dec_loginack(pl, pos):
    tlen = struct.unpack('<H', pl[pos:pos+2])[0]; pos += 2
    start = pos
    interface = pl[pos]; pos += 1
    tdsver = struct.unpack('<I', pl[pos:pos+4])[0]; pos += 4
    progname, pos = _read_b_varchar(pl, pos)
    progver = pl[pos:pos+4]; pos += 4
    text = (f'Interface={interface} TDSVersion=0x{tdsver:08X} ProgName={progname} '
            f'ProgVersion={progver[0]}.{progver[1]}.{(progver[2] << 8) | progver[3]}')
    return text, start + tlen


_ENVCHANGE_NAMES = {
    1: 'Database', 2: 'Language', 3: 'CharacterSet', 4: 'PacketSize',
    7: 'Collation', 9: 'BeginTx', 10: 'CommitTx', 11: 'RollbackTx',
    13: 'DatabaseMirroring', 17: 'Routing', 20: 'Routing',
}
_ENVCHANGE_BINARY = {9, 10, 11, 12, 18}


def _dec_envchange(pl, pos):
    tlen = struct.unpack('<H', pl[pos:pos+2])[0]; pos += 2
    start = pos
    etype = pl[pos]; pos += 1
    name = _ENVCHANGE_NAMES.get(etype, f'Type{etype}')
    try:
        if etype in _ENVCHANGE_BINARY:
            nlen = pl[pos]; new = pl[pos+1:pos+1+nlen]; p2 = pos + 1 + nlen
            olen = pl[p2]; old = pl[p2+1:p2+1+olen]
            text = f'{name} new=0x{new.hex()} old=0x{old.hex()}'
        else:
            new, p2 = _read_b_varchar(pl, pos)
            old, _  = _read_b_varchar(pl, p2)
            text = f'{name} new={new} old={old}'
    except Exception:
        text = name
    return text, start + tlen


_DONE_NAMES = {0xFD: 'DONE', 0xFE: 'DONEPROC', 0xFF: 'DONEINPROC'}


def _dec_done(pl, pos, tok):
    status   = struct.unpack('<H', pl[pos:pos+2])[0]
    rowcount = struct.unpack('<Q', pl[pos+4:pos+12])[0]
    return f'{_DONE_NAMES.get(tok, "DONE")} status=0x{status:04X} rowcount={rowcount}', pos + 12


def _dec_returnstatus(pl, pos):
    val = struct.unpack('<i', pl[pos:pos+4])[0]
    return f'ReturnStatus={val}', pos + 4


def _dec_colmetadata(pl, pos):
    count = struct.unpack('<H', pl[pos:pos+2])[0]; pos += 2
    if count == 0xFFFF:
        return 'COLMETADATA (no metadata)', pos, []
    cols = []
    for _ in range(count):
        pos += 4   # UserType (TDS 7.2+)
        pos += 2   # Flags
        info, pos = _read_typeinfo(pl, pos)
        colname, pos = _read_b_varchar(pl, pos)
        cols.append((colname, info))
    header = 'COLMETADATA: ' + ', '.join(c[0] for c in cols)
    return header, pos, cols


def _dec_row(pl, pos, cols):
    vals = []
    for name, info in cols:
        v, pos = _read_value(pl, pos, info)
        vals.append(f'{name}={v}')
    return 'ROW: ' + ' '.join(vals), pos


def _dec_tabular(pl):
    pos, lines, cols = 0, [], []
    try:
        while pos < len(pl):
            tok = pl[pos]; pos += 1
            if tok in (0xAA, 0xAB):
                text, pos = _dec_error_info(pl, pos)
                lines.append(('ERROR: ' if tok == 0xAA else 'INFO: ') + text)
            elif tok == 0xAD:
                text, pos = _dec_loginack(pl, pos)
                lines.append('LOGINACK: ' + text)
            elif tok == 0xE3:
                text, pos = _dec_envchange(pl, pos)
                lines.append('ENVCHANGE: ' + text)
            elif tok in (0xFD, 0xFE, 0xFF):
                text, pos = _dec_done(pl, pos, tok)
                lines.append(text)
            elif tok == 0x79:
                text, pos = _dec_returnstatus(pl, pos)
                lines.append(text)
            elif tok == 0x81:
                text, pos, cols = _dec_colmetadata(pl, pos)
                lines.append(text)
            elif tok == 0xD1:
                text, pos = _dec_row(pl, pos, cols)
                lines.append(text)
            else:
                break   # unsupported token (NBCROW, ORDER, SESSIONSTATE, ...)
    except Exception:
        pass
    return '\n'.join(lines)


# dispatch

def _dec_msg(msg):
    t, pl = msg['type'], msg['payload']
    try:
        if t == _T_PRELOGIN: return _dec_prelogin(pl)
        if t == _T_LOGIN7:   return _dec_login7(pl)
        if t == _T_SQLBATCH: return _dec_sqlbatch(pl)
        if t == _T_RPC:      return _dec_rpc(pl)
        if t == _T_TABULAR:  return _dec_tabular(pl)
    except Exception:
        return ''
    return ''   # Attention / BulkLoad / FedAuth / TMRequest / SSPI - not decoded


def _enc_msg(msg, text):
    t, pl = msg['type'], msg['payload']
    try:
        if t == _T_SQLBATCH: return _enc_sqlbatch(text, pl)
        if t == _T_LOGIN7:   return _enc_login7(text, pl)
    except Exception:
        return None
    return None


def _build_msg(msg, new_payload):
    hdr = bytearray(msg['raw'][:8])
    hdr[2:4] = struct.pack('>H', 8 + len(new_payload))
    return bytes(hdr) + new_payload


# protocol detection

def _is_mssql(raw, data):
    src = data.get('source_port', 0)
    dst = data.get('destination_port', 0)
    if src == _MSSQL_PORT or dst == _MSSQL_PORT:
        return len(raw) >= 8
    if len(raw) < 8:
        return False
    mtype  = raw[0]
    status = raw[1]
    length = struct.unpack('>H', raw[2:4])[0]
    window = raw[7]
    if mtype not in _KNOWN_TYPES:
        return False
    if status & 0xE0:
        return False
    if window != 0:
        return False
    return 8 <= length <= len(raw)


# extension handler

class _MSSQLHandler:

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
        return _is_mssql(self._get_raw(data), data)

    def fetchdata(self, data):
        raw = self._get_raw(data)
        if not raw:
            return ''
        try:
            msgs = _parse_msgs(raw)
        except Exception:
            return ''
        parts = [_dec_msg(m) for m in msgs]
        return '\n\n'.join(p for p in parts if p)

    def updatedata(self, data):
        edited = data.get('edited_data', '')
        if not edited or not edited.strip():
            return None
        raw = self._get_raw(data)
        if not raw:
            return None
        try:
            msgs = _parse_msgs(raw)
        except Exception:
            return None

        orig_parts    = [_dec_msg(m) for m in msgs]
        edited_chunks = edited.split('\n\n')

        if len(edited_chunks) != sum(1 for p in orig_parts if p):
            return None

        result, slot = b'', 0
        for i, msg in enumerate(msgs):
            if orig_parts[i]:
                new_payload = _enc_msg(msg, edited_chunks[slot])
                result += _build_msg(msg, new_payload) if new_payload is not None else msg['raw']
                slot += 1
            else:
                result += msg['raw']

        if result == raw:
            return None

        return result.decode(_LAT1)


# extension entry point

class InterceptSuiteExtension:

    def register_interceptor_api(self, interceptor):
        interceptor.set_extension_name('MSSQL Decoder')
        interceptor.set_extension_version('1.0.0')
        interceptor.AddDataViewerTab('MSSQL', _MSSQLHandler())
        ExtensionLogger.Log('MSSQL Decoder loaded')
