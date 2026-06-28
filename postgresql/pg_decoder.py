from InterceptSuite.Extensions.APIs.Logging import ExtensionLogger
import struct

_PG_PORT = 5432
_ENC     = 'utf-8'
_LAT1    = 'latin-1'
_NULLV   = 'NULL'
_U32     = '>I'
_I32     = '>i'
_U16     = '>H'

_PROTO_V3     = 196608
_PROTO_SSL    = 80877103
_PROTO_CANCEL = 131072

_AUTH_NAMES = {
    0: 'AuthOK', 2: 'Kerberos', 3: 'CleartextPassword',
    5: 'MD5Password', 7: 'GSS', 9: 'SSPI',
    10: 'SASL', 11: 'SASLContinue', 12: 'SASLFinal',
}
_TXN_STATUS = {0x49: 'idle', 0x54: 'transaction', 0x45: 'error'}
_COPY_FMT   = {0: 'text', 1: 'binary'}

# frontend (client→server) message type bytes
_FE_TYPES = frozenset({
    0x51,  # Q  Query
    0x50,  # P  Parse
    0x42,  # B  Bind
    0x45,  # E  Execute
    0x44,  # D  Describe
    0x43,  # C  Close
    0x53,  # S  Sync
    0x58,  # X  Terminate
    0x70,  # p  Password
    0x48,  # H  Flush
    0x64,  # d  CopyData
    0x63,  # c  CopyDone
    0x66,  # f  CopyFail
})

# backend (server→client) message type bytes
_BE_TYPES = frozenset({
    0x52,  # R  Authentication
    0x4B,  # K  BackendKeyData
    0x53,  # S  ParameterStatus
    0x5A,  # Z  ReadyForQuery
    0x54,  # T  RowDescription
    0x44,  # D  DataRow
    0x43,  # C  CommandComplete
    0x45,  # E  ErrorResponse
    0x4E,  # N  NoticeResponse
    0x49,  # I  EmptyQueryResponse
    0x6E,  # n  NoData
    0x73,  # s  PortalSuspended
    0x31,  # 1  ParseComplete
    0x32,  # 2  BindComplete
    0x33,  # 3  CloseComplete
    0x41,  # A  NotificationResponse
    0x56,  # V  FunctionCallResponse
    0x74,  # t  ParameterDescription
    0x57,  # W  CopyBothResponse
    0x47,  # G  CopyInResponse
    0x48,  # H  CopyOutResponse
    0x64,  # d  CopyData
    0x63,  # c  CopyDone
})


# low-level helpers

def _cstr(buf, pos):
    """Read a null-terminated UTF-8 string. Returns (string, new_pos)."""
    end = buf.find(b'\x00', pos)
    if end < 0:
        return buf[pos:].decode(_ENC, errors='replace'), len(buf)
    return buf[pos:end].decode(_ENC, errors='replace'), end + 1


def _build_msg(mtype, payload):
    """Build a complete PostgreSQL message: type byte + Int32(len+4) + payload."""
    return bytes([mtype]) + struct.pack(_U32, len(payload) + 4) + payload


# frame parser

def _parse_msgs(raw):
    msgs = []
    i = 0
    # Startup / SSL request have no type byte - check for them first
    if len(raw) >= 8:
        length  = struct.unpack(_U32, raw[:4])[0]
        version = struct.unpack(_U32, raw[4:8])[0]
        if version in (_PROTO_V3, _PROTO_SSL, _PROTO_CANCEL) and 8 <= length <= len(raw):
            msgs.append({
                'kind': 'startup', 'version': version,
                'payload': raw[8:length], 'raw': raw[:length],
            })
            i = length
    while i + 5 <= len(raw):
        mtype  = raw[i]
        length = struct.unpack(_U32, raw[i+1:i+5])[0]
        pend   = i + 1 + length
        payload = raw[i+5:pend] if pend <= len(raw) else raw[i+5:]
        msgs.append({
            'kind': 'msg', 'type': mtype,
            'payload': payload, 'raw': raw[i:min(pend, len(raw))],
        })
        if pend > len(raw):
            break
        i = pend
    return msgs


# decoders
def _dec_startup(msg):
    v = msg['version']
    if v == _PROTO_SSL:
        return 'SSLRequest'
    if v == _PROTO_CANCEL:
        return 'CancelRequest'
    payload, i, pairs = msg['payload'], 0, []
    while i < len(payload):
        key, i = _cstr(payload, i)
        if not key:
            break
        val, i = _cstr(payload, i)
        pairs.append(f'{key}={val}')
    return '\n'.join(pairs)


def _dec_rowdesc(payload):
    if len(payload) < 2:
        return ''
    num = struct.unpack(_U16, payload[:2])[0]
    i, cols = 2, []
    for _ in range(num):
        name, i = _cstr(payload, i)
        cols.append(name)
        i += 18   # tableoid(4) colnum(2) typoid(4) typsize(2) typmod(4) fmt(2)
        if i > len(payload):
            break
    return '\t'.join(cols)


def _dec_datarow(payload):
    if len(payload) < 2:
        return ''
    num = struct.unpack(_U16, payload[:2])[0]
    i, vals = 2, []
    for _ in range(num):
        if i + 4 > len(payload):
            break
        flen = struct.unpack(_I32, payload[i:i+4])[0]
        i += 4
        if flen == -1:
            vals.append(_NULLV)
        elif flen >= 0:
            vals.append(payload[i:i+flen].decode(_ENC, errors='replace'))
            i += flen
    return '\t'.join(vals)


def _dec_bind(payload):
    i = 0
    _, i = _cstr(payload, i)   # portal name (skip)
    _, i = _cstr(payload, i)   # stmt name (skip)
    if i + 2 > len(payload):
        return ''
    nfmt = struct.unpack(_U16, payload[i:i+2])[0]
    i += 2 + nfmt * 2
    if i + 2 > len(payload):
        return ''
    nparams = struct.unpack(_U16, payload[i:i+2])[0]
    i += 2
    params = []
    for _ in range(nparams):
        if i + 4 > len(payload):
            break
        plen = struct.unpack(_I32, payload[i:i+4])[0]
        i += 4
        if plen == -1:
            params.append(_NULLV)
        elif plen >= 0:
            params.append(payload[i:i+plen].decode(_ENC, errors='replace'))
            i += plen
    return '\n'.join(params)


def _dec_errnotice(payload):
    severity = message = ''
    i = 0
    while i < len(payload):
        ft = payload[i]
        if ft == 0:
            break
        i += 1
        val, i = _cstr(payload, i)
        if ft == 0x53:    # S - Severity
            severity = val
        elif ft == 0x4D:  # M - Message
            message = val
    if severity and message:
        return f'{severity}: {message}'
    return message or severity


def _dec_execute(payload):
    portal, i = _cstr(payload, 0)
    max_rows = struct.unpack(_U32, payload[i:i+4])[0] if i + 4 <= len(payload) else 0
    if portal:
        return f'{portal}\n{max_rows}'
    return str(max_rows) if max_rows else ''


def _dec_describe_close(payload):
    if not payload:
        return ''
    ptype = chr(payload[0])
    name, _ = _cstr(payload, 1)
    return f'{ptype} {name}' if name else ptype


def _dec_copy_response(payload):
    if len(payload) < 3:
        return ''
    overall = _COPY_FMT.get(payload[0], str(payload[0]))
    ncols = struct.unpack(_U16, payload[1:3])[0]
    i, col_fmts = 3, []
    for _ in range(ncols):
        if i + 2 > len(payload):
            break
        col_fmts.append(_COPY_FMT.get(struct.unpack(_U16, payload[i:i+2])[0], 'unknown'))
        i += 2
    if col_fmts:
        return overall + '\n' + '\t'.join(col_fmts)
    return overall


def _dec_param_desc(payload):
    if len(payload) < 2:
        return ''
    n = struct.unpack(_U16, payload[:2])[0]
    oids = []
    for j in range(n):
        off = 2 + j * 4
        if off + 4 > len(payload):
            break
        oids.append(str(struct.unpack(_U32, payload[off:off+4])[0]))
    return ' '.join(oids)


def _dec_funcresult(payload):
    if len(payload) < 4:
        return ''
    rlen = struct.unpack(_I32, payload[:4])[0]
    if rlen == -1:
        return _NULLV
    if rlen >= 0 and 4 + rlen <= len(payload):
        return payload[4:4+rlen].decode(_ENC, errors='replace')
    return ''


def _dec_auth(pl):
    if len(pl) >= 4:
        return _AUTH_NAMES.get(struct.unpack(_U32, pl[:4])[0], 'AuthUnknown')
    return ''


def _dec_backendkey(pl):
    if len(pl) >= 4:
        return f'pid={struct.unpack(_U32, pl[:4])[0]}'
    return ''


def _dec_notification(pl):
    if len(pl) >= 4:
        ch, i = _cstr(pl, 4)
        ex, _ = _cstr(pl, i)
        return f'{ch}: {ex}' if ex else ch
    return ''


def _dec_fe(mt, pl):
    if mt == 0x51:             # Q  Simple Query
        s, _ = _cstr(pl, 0)
        return s
    if mt == 0x50:             # P  Parse - show query text
        _, i = _cstr(pl, 0)
        s, _ = _cstr(pl, i)
        return s
    if mt == 0x42:             # B  Bind - show parameter values
        return _dec_bind(pl)
    if mt == 0x70:             # p  Password
        s, _ = _cstr(pl, 0)
        return s
    if mt == 0x45:             # E  Execute
        return _dec_execute(pl)
    if mt in (0x44, 0x43):    # D  Describe / C  Close
        return _dec_describe_close(pl)
    if mt == 0x64:             # d  CopyData
        return pl.decode(_ENC, errors='replace')
    if mt == 0x66:             # f  CopyFail
        s, _ = _cstr(pl, 0)
        return s
    return ''                  # S Sync / X Terminate / H Flush / c CopyDone - no content


def _dec_be(mt, pl):
    if mt == 0x54:             # T  RowDescription
        return _dec_rowdesc(pl)
    if mt == 0x44:             # D  DataRow
        return _dec_datarow(pl)
    if mt == 0x43:             # C  CommandComplete
        s, _ = _cstr(pl, 0)
        return s
    if mt in (0x45, 0x4E):    # E  ErrorResponse / N  NoticeResponse
        return _dec_errnotice(pl)
    if mt == 0x5A:             # Z  ReadyForQuery
        return _TXN_STATUS.get(pl[0] if pl else 0, '')
    if mt == 0x52:             # R  Authentication
        return _dec_auth(pl)
    if mt == 0x53:             # S  ParameterStatus
        k, i = _cstr(pl, 0)
        v, _ = _cstr(pl, i)
        return f'{k}={v}'
    if mt == 0x4B:             # K  BackendKeyData
        return _dec_backendkey(pl)
    if mt == 0x41:             # A  NotificationResponse
        return _dec_notification(pl)
    if mt == 0x74:             # t  ParameterDescription
        return _dec_param_desc(pl)
    if mt in (0x47, 0x48, 0x57):  # G CopyInResponse / H CopyOutResponse / W CopyBothResponse
        return _dec_copy_response(pl)
    if mt == 0x64:             # d  CopyData
        return pl.decode(_ENC, errors='replace')
    if mt == 0x56:             # V  FunctionCallResponse
        return _dec_funcresult(pl)
    return ''                  # 1 2 3 n I s - ack/status frames, no content


def _dec_msg(msg, is_fe):
    if msg['kind'] == 'startup':
        return _dec_startup(msg)
    mt, pl = msg['type'], msg['payload']
    return _dec_fe(mt, pl) if is_fe else _dec_be(mt, pl)


# re-encoders

def _enc_datarow(text, original):
    vals = text.split('\t')
    if len(original) < 2 or struct.unpack(_U16, original[:2])[0] != len(vals):
        return None
    body = struct.pack(_U16, len(vals))
    for v in vals:
        if v == _NULLV:
            body += struct.pack(_I32, -1)
        else:
            enc = v.encode(_ENC)
            body += struct.pack(_I32, len(enc)) + enc
    return _build_msg(0x44, body)


def _bind_split(original):
    """Parse a Bind payload into (prefix, fmt_block, result_fmts, nparams)."""
    i = 0
    end = original.find(b'\x00', i)
    portal = original[i:end+1]
    i = end + 1
    end = original.find(b'\x00', i)
    stmt = original[i:end+1]
    i = end + 1
    if i + 2 > len(original):
        return None
    nfmt = struct.unpack(_U16, original[i:i+2])[0]
    fmt_block = original[i:i+2+nfmt*2]
    i += 2 + nfmt * 2
    if i + 2 > len(original):
        return None
    nparams = struct.unpack(_U16, original[i:i+2])[0]
    i += 2
    j = i
    for _ in range(nparams):
        if j + 4 > len(original):
            break
        plen = struct.unpack(_I32, original[j:j+4])[0]
        j += 4
        if plen > 0:
            j += plen
    return portal + stmt, fmt_block, original[j:], nparams


def _enc_bind(text, original):
    parts = _bind_split(original)
    if parts is None:
        return None
    prefix, fmt_block, result_fmts, _ = parts
    new_params = text.split('\n')
    body = prefix + fmt_block + struct.pack(_U16, len(new_params))
    for p in new_params:
        if p == _NULLV:
            body += struct.pack(_I32, -1)
        else:
            enc = p.encode(_ENC)
            body += struct.pack(_I32, len(enc)) + enc
    return _build_msg(0x42, body + result_fmts)


def _enc_parse(text, original):
    null_pos = original.find(b'\x00')
    stmt_name = original[:null_pos+1] if null_pos >= 0 else b'\x00'
    _, i = _cstr(original, 0)
    _, end = _cstr(original, i)
    body = stmt_name + text.encode(_ENC) + b'\x00' + original[end:]
    return _build_msg(0x50, body)


def _enc_execute(text):
    lines = text.split('\n', 1)
    portal = lines[0].strip()
    try:
        max_rows = int(lines[1].strip()) if len(lines) > 1 else 0
    except ValueError:
        max_rows = 0
    return _build_msg(0x45, portal.encode(_ENC) + b'\x00' + struct.pack(_U32, max_rows))


def _enc_describe_close(mt, text, original):
    ptype = original[0] if original else ord('S')
    parts = text.split(' ', 1)
    if parts[0] in ('S', 'P'):
        ptype = ord(parts[0])
        name  = parts[1] if len(parts) > 1 else ''
    else:
        name = text
    return _build_msg(mt, bytes([ptype]) + name.encode(_ENC) + b'\x00')


def _enc_funcresult(text):
    if text == _NULLV:
        return _build_msg(0x56, struct.pack(_I32, -1))
    enc = text.encode(_ENC)
    return _build_msg(0x56, struct.pack(_I32, len(enc)) + enc)


def _enc_fe(mt, pl, text):
    if mt == 0x51:             # Q  Simple Query
        return _build_msg(0x51, text.encode(_ENC) + b'\x00')
    if mt == 0x50:             # P  Parse
        return _enc_parse(text, pl)
    if mt == 0x42:             # B  Bind
        return _enc_bind(text, pl)
    if mt == 0x70:             # p  Password
        return _build_msg(0x70, text.encode(_ENC) + b'\x00')
    if mt == 0x45:             # E  Execute
        return _enc_execute(text)
    if mt in (0x44, 0x43):    # D  Describe / C  Close
        return _enc_describe_close(mt, text, pl)
    if mt == 0x64:             # d  CopyData
        return _build_msg(0x64, text.encode(_ENC))
    if mt == 0x66:             # f  CopyFail
        return _build_msg(0x66, text.encode(_ENC) + b'\x00')
    return None


def _enc_be(mt, pl, text):
    if mt == 0x43:             # C  CommandComplete
        return _build_msg(0x43, text.encode(_ENC) + b'\x00')
    if mt == 0x44:             # D  DataRow
        return _enc_datarow(text, pl)
    if mt == 0x64:             # d  CopyData
        return _build_msg(0x64, text.encode(_ENC))
    if mt == 0x56:             # V  FunctionCallResponse
        return _enc_funcresult(text)
    return None


def _enc_msg(msg, text, is_fe):
    if msg['kind'] == 'startup':
        return msg['raw']
    mt, pl = msg['type'], msg['payload']
    return _enc_fe(mt, pl, text) if is_fe else _enc_be(mt, pl, text)


# protocol detection

def _is_pg(raw, data):
    src = data.get('source_port', 0)
    dst = data.get('destination_port', 0)
    if src == _PG_PORT or dst == _PG_PORT:
        return len(raw) >= 5

    if len(raw) < 8:
        return False

    length  = struct.unpack(_U32, raw[:4])[0]
    version = struct.unpack(_U32, raw[4:8])[0]
    if version in (_PROTO_V3, _PROTO_SSL, _PROTO_CANCEL) and 8 <= length <= len(raw):
        return True

    mtype  = raw[0]
    length = struct.unpack(_U32, raw[1:5])[0]
    if (mtype in _FE_TYPES or mtype in _BE_TYPES) and 4 <= length <= len(raw):
        return True

    return False


# extension handler

class _PGHandler:

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

    def _is_fe(self, data):
        return data.get('direction', '').startswith('Client')

    def should_show_tab(self, data):
        return _is_pg(self._get_raw(data), data)

    def fetchdata(self, data):
        raw = self._get_raw(data)
        if not raw:
            return ''
        is_fe = self._is_fe(data)
        try:
            msgs = _parse_msgs(raw)
        except Exception:
            return ''
        parts = [_dec_msg(m, is_fe) for m in msgs]
        return '\n\n'.join(p for p in parts if p)

    def updatedata(self, data):
        edited = data.get('edited_data', '')
        if not edited or not edited.strip():
            return None
        raw = self._get_raw(data)
        if not raw:
            return None
        is_fe = self._is_fe(data)
        try:
            msgs = _parse_msgs(raw)
        except Exception:
            return None

        orig_parts    = [_dec_msg(m, is_fe) for m in msgs]
        edited_chunks = edited.split('\n\n')

        if len(edited_chunks) != sum(1 for p in orig_parts if p):
            return None

        result, slot = b'', 0
        for i, msg in enumerate(msgs):
            if orig_parts[i]:
                reenc = _enc_msg(msg, edited_chunks[slot], is_fe)
                result += reenc if reenc is not None else msg['raw']
                slot += 1
            else:
                result += msg['raw']

        # If re-encoded bytes are identical to original, report no change.
        # This prevents C# UTF-8 re-encoding from corrupting binary packets
        # when the user forwards without actually editing anything.
        if result == raw:
            return None

        return result.decode(_LAT1)


# extension entry point

class InterceptSuiteExtension:

    def register_interceptor_api(self, interceptor):
        interceptor.set_extension_name('PostgreSQL Decoder')
        interceptor.set_extension_version('1.0.0')
        interceptor.AddDataViewerTab('PostgreSQL', _PGHandler())
        ExtensionLogger.Log('PostgreSQL Decoder loaded')
