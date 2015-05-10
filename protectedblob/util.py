import base64


def namedtuple_to_dict_with_base64_bytes(t):
    r = {}
    for k, v in t._asdict().items():
        if isinstance(v, bytes):
            r[k] = base64.b64encode(v).decode('utf-8')
        else:
            r[k] = v
    return r


def dict_to_namedtuple_with_base64_fields(d, t_type, base64_fields=None):
    assert isinstance(d, dict)
    if set(d.keys()) != set(t_type._fields):
        raise ValueError(
            'key mismatch: %s vs %s' % (d.keys(), t_type._fields))

    decoded_dict = {}
    for k, v in d.items():
        if base64_fields and k in base64_fields:
            decoded_dict[k] = base64.b64decode(v)
        else:
            decoded_dict[k] = v
    return t_type(**decoded_dict)


def time_constant_compare(b1, b2):
    assert isinstance(b1, bytes)
    assert isinstance(b2, bytes)
    if len(b1) != len(b2):
        return False
    result = 1
    for x, y in zip(b1, b2):
        result &= int(x == y)
    return result == 1
