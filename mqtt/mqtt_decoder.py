from InterceptSuite.Extensions.APIs.Logging import ExtensionLogger
import struct


_MQTT_PORT  = 1883
_MQTTS_PORT = 8883
_ENC        = 'utf-8'
_LAT1       = 'latin-1'


# low-level helpers

def _u16be(buf, pos):
    return struct.unpack('>H', buf[pos:pos+2])[0]

def _str16(buf, pos):
    l = _u16be(buf, pos)
    return buf[pos+2:pos+2+l].decode(_ENC, errors='replace'), pos+2+l

def _bytes16(buf, pos):
    l = _u16be(buf, pos)
    return buf[pos+2:pos+2+l], pos+2+l

def _enc_str16(s):
    b = s.encode(_ENC)
    return struct.pack('>H', len(b)) + b

def _enc_bytes16(b):
    return struct.pack('>H', len(b)) + b

def _dec_remlen(buf, pos):
    mult, val = 1, 0
    for _ in range(4):
        if pos >= len(buf):
            return 0, pos
        b = buf[pos]; pos += 1
        val += (b & 0x7F) * mult
        mult *= 128
        if not (b & 0x80):
            break
    return val, pos

def _enc_remlen(n):
    out = b''
    while True:
        b = n % 128
        n //= 128
        if n:
            b |= 0x80
        out += bytes([b])
        if not n:
            break
    return out


# frame parser

def _parse_packets(raw):
    pkts, i = [], 0
    while i < len(raw):
        hdr   = raw[i]
        ptype = (hdr >> 4) & 0x0F
        if ptype < 1 or ptype > 14:
            break
        rem, end = _dec_remlen(raw, i + 1)
        pend = end + rem
        pkts.append({
            'hdr':     hdr,
            'type':    ptype,
            'flags':   hdr & 0x0F,
            'payload': raw[end:pend],
            'raw':     raw[i:pend],
        })
        if pend > len(raw):
            break
        i = pend
    return pkts


# decoders
def _dec_connect(pl):
    if len(pl) < 10:
        return ''
    _, pos = _str16(pl, 0)            # protocol name
    pos   += 1                         # protocol level
    flags  = pl[pos]; pos += 1
    pos   += 2                         # keep alive
    client_id, pos = _str16(pl, pos)
    parts = [client_id]
    if flags & 0x04:                   # will flag
        will_topic, pos = _str16(pl, pos)
        will_msg,   pos = _bytes16(pl, pos)
        parts += [will_topic, will_msg.decode(_ENC, errors='replace')]
    if flags & 0x80:                   # username flag
        username, pos = _str16(pl, pos)
        parts.append(username)
    if flags & 0x40:                   # password flag
        password, pos = _bytes16(pl, pos)
        parts.append(password.decode(_ENC, errors='replace'))
    return '\n'.join(parts)


def _dec_connack(pl):
    if len(pl) < 2:
        return ''
    return str(pl[1])


def _dec_publish(pl, fl):
    qos = (fl >> 1) & 0x03
    if len(pl) < 2:
        return ''
    topic, pos = _str16(pl, 0)
    if qos > 0:
        pos += 2                       # skip packet identifier
    msg = pl[pos:].decode(_ENC, errors='replace')
    return topic + '\n' + msg if msg else topic


def _dec_pid(pl):
    return str(_u16be(pl, 0)) if len(pl) >= 2 else ''


def _dec_subscribe(pl):
    if len(pl) < 2:
        return ''
    pos, subs = 2, []                  # skip packet identifier
    while pos + 2 <= len(pl):
        topic, pos = _str16(pl, pos)
        if pos >= len(pl):
            break
        qos = pl[pos]; pos += 1
        subs.append(f'{topic} {qos}')
    return '\n'.join(subs)


def _dec_suback(pl):
    if len(pl) < 2:
        return ''
    return '\n'.join(str(b) for b in pl[2:])


def _dec_unsubscribe(pl):
    if len(pl) < 2:
        return ''
    pos, topics = 2, []                # skip packet identifier
    while pos + 2 <= len(pl):
        topic, pos = _str16(pl, pos)
        topics.append(topic)
    return '\n'.join(topics)


def _dec_packet(pkt):
    t, fl, pl = pkt['type'], pkt['flags'], pkt['payload']
    if t == 1:             return _dec_connect(pl)
    if t == 2:             return _dec_connack(pl)
    if t == 3:             return _dec_publish(pl, fl)
    if t in (4,5,6,7,11): return _dec_pid(pl)
    if t == 8:             return _dec_subscribe(pl)
    if t == 9:             return _dec_suback(pl)
    if t == 10:            return _dec_unsubscribe(pl)
    return ''              # PINGREQ PINGRESP DISCONNECT - no content


# re-encoders

def _enc_connect(text, pl):
    if len(pl) < 10:
        return None
    pname_len  = _u16be(pl, 0)
    pos        = 2 + pname_len         # skip protocol name
    level      = pl[pos]; pos += 1
    flags      = pl[pos]; pos += 1
    keep_alive = _u16be(pl, pos)
    _, pos     = _str16(pl, pos + 2)   # skip original client_id

    expected = (1
                + (2 if flags & 0x04 else 0)
                + (1 if flags & 0x80 else 0)
                + (1 if flags & 0x40 else 0))
    lines = (text + '\n' * expected).split('\n')

    idx       = 0
    client_id = lines[idx]; idx += 1

    var_hdr       = pl[:2+pname_len] + bytes([level, flags]) + struct.pack('>H', keep_alive)
    payload_bytes = _enc_str16(client_id)

    if flags & 0x04:
        will_topic = lines[idx]; idx += 1
        will_msg   = lines[idx] if idx < len(lines) else ''; idx += 1
        payload_bytes += _enc_str16(will_topic) + _enc_bytes16(will_msg.encode(_ENC))

    if flags & 0x80:
        username = lines[idx] if idx < len(lines) else ''; idx += 1
        payload_bytes += _enc_str16(username)

    if flags & 0x40:
        password = lines[idx] if idx < len(lines) else ''; idx += 1
        payload_bytes += _enc_bytes16(password.encode(_ENC))

    return var_hdr + payload_bytes


def _enc_connack(text, pl):
    if len(pl) < 2:
        return None
    try:
        rc = int(text.strip())
    except ValueError:
        return None
    return bytes([pl[0], rc & 0xFF])


def _enc_publish(text, pl, fl):
    qos    = (fl >> 1) & 0x03
    lines  = text.split('\n', 1)
    topic  = lines[0]
    msg    = lines[1].encode(_ENC) if len(lines) > 1 else b''
    new_pl = _enc_str16(topic)
    if qos > 0:
        tlen    = _u16be(pl, 0)
        new_pl += pl[2+tlen:2+tlen+2]  # preserve original packet identifier
    return new_pl + msg


def _enc_subscribe(text, pl):
    if len(pl) < 2:
        return None
    new_pl = pl[:2]                    # preserve packet identifier
    for line in text.split('\n'):
        parts = line.rsplit(' ', 1)
        topic = parts[0]
        try:
            qos = int(parts[1]) & 0x03 if len(parts) > 1 else 0
        except ValueError:
            qos = 0
        new_pl += _enc_str16(topic) + bytes([qos])
    return new_pl


def _enc_unsubscribe(text, pl):
    if len(pl) < 2:
        return None
    new_pl = pl[:2]                    # preserve packet identifier
    for topic in text.split('\n'):
        new_pl += _enc_str16(topic)
    return new_pl


def _enc_packet(pkt, text):
    t, fl, pl, hdr = pkt['type'], pkt['flags'], pkt['payload'], pkt['hdr']
    new_pl = None
    if t == 1:   new_pl = _enc_connect(text, pl)
    elif t == 2: new_pl = _enc_connack(text, pl)
    elif t == 3: new_pl = _enc_publish(text, pl, fl)
    elif t == 8: new_pl = _enc_subscribe(text, pl)
    elif t == 10: new_pl = _enc_unsubscribe(text, pl)
    if new_pl is None:
        return pkt['raw']
    return bytes([hdr]) + _enc_remlen(len(new_pl)) + new_pl


# protocol detection

def _is_mqtt(raw, data):
    src = data.get('source_port', 0)
    dst = data.get('destination_port', 0)
    if src in (_MQTT_PORT, _MQTTS_PORT) or dst in (_MQTT_PORT, _MQTTS_PORT):
        return len(raw) >= 2
    if len(raw) < 2:
        return False
    ptype = (raw[0] >> 4) & 0x0F
    if ptype < 1 or ptype > 14:
        return False
    rem, end = _dec_remlen(raw, 1)
    return end + rem <= len(raw)


# extension handler

class _MQTTHandler:

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
        return _is_mqtt(self._get_raw(data), data)

    def fetchdata(self, data):
        raw = self._get_raw(data)
        if not raw:
            return ''
        try:
            pkts = _parse_packets(raw)
        except Exception:
            return ''
        parts = [_dec_packet(p) for p in pkts]
        return '\n\n'.join(p for p in parts if p)

    def updatedata(self, data):
        edited = data.get('edited_data', '')
        if not edited or not edited.strip():
            return None
        raw = self._get_raw(data)
        if not raw:
            return None
        try:
            pkts = _parse_packets(raw)
        except Exception:
            return None

        orig_parts    = [_dec_packet(p) for p in pkts]
        edited_chunks = edited.split('\n\n')

        if len(edited_chunks) != sum(1 for p in orig_parts if p):
            return None

        result, slot = b'', 0
        for i, pkt in enumerate(pkts):
            if orig_parts[i]:
                result += _enc_packet(pkt, edited_chunks[slot])
                slot   += 1
            else:
                result += pkt['raw']

        if result == raw:
            return None

        return result.decode(_LAT1)


# extension entry point

class InterceptSuiteExtension:

    def register_interceptor_api(self, interceptor):
        interceptor.set_extension_name('MQTT Decoder')
        interceptor.set_extension_version('1.0.0')
        interceptor.AddDataViewerTab('MQTT', _MQTTHandler())
        ExtensionLogger.Log('MQTT Decoder loaded')
