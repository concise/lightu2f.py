# TODO: some serious refactoring

__all__ = (
    'set_application_identity',
    'create_registration_request',
    'handle_registration_response',
    'create_authentication_request',
    'handle_authentication_response',
)

import base64
import hashlib
import hmac
import json
import os
import sys

G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

O = None

def neg(P):
    assert is_valid_point(P)
    if P is None:
        return None
    else:
        return P[0], -P[1] % p

def add(P1, P2):
    assert is_valid_point(P1)
    assert is_valid_point(P2)
    if P1 is None:
        return P2
    elif P2 is None:
        return P1
    elif P1[0] != P2[0]:
        return AFFINE_POINT_ADDITION(P1, P2)
    elif P1[1] == P2[1] != 0:
        return AFFINE_POINT_DOUBLING(P1)
    else:
        return None

def mul(k, P):
    assert type(k) is int
    assert is_valid_point(P)
    k = k % n
    if k == 0 or P is None:
        return None
    elif k == 1:
        return P
    elif k == n - 1:
        return P[0], -P[1] % p
    else:
        return MontgomeryLadderScalarMultiply_ver2(k, P)

def point_from_octetstring(octetstring):
    if type(octetstring) is not bytes:
        raise ValueError
    elif len(octetstring) == 1 and octetstring[0] == 0x00:
        return None
    elif len(octetstring) == 65 and octetstring[0] == 0x04:
        x = int.from_bytes(octetstring[1:33], byteorder='big', signed=False)
        y = int.from_bytes(octetstring[33:65], byteorder='big', signed=False)
        assert is_valid_point((x, y))
        return x, y
    elif len(octetstring) == 33 and octetstring[0] in {0x02, 0x03}:
        y_parity = octetstring[0] & 1
        x = int.from_bytes(octetstring[1:33], byteorder='big', signed=False)
        y = y_candidates_from_x(x)[y_parity]
        return x, y
    else:
        raise ValueError

#-----------------------------------------------------------------------------

def ecdsa_double_scalar_multiplication(t, u, Q):
    assert type(t) is int and 0 <= t <= n - 1
    assert type(u) is int and 1 <= u <= n - 1
    assert is_valid_point(Q) and Q is not None
    tG = mul(t, G)
    uQ = mul(u, Q)
    R = add(tG, uQ)
    return R

def y_candidates_from_x(xP):
    assert type(xP) is int
    y_squared = (xP * xP * xP + a * xP + b) % p
    y = pow(y_squared, (p + 1) // 4, p)
    if y * y % p != y_squared:
        raise ValueError
    return (y, p - y) if (y & 1 == 0) else (p - y, y)

def is_valid_point(P):
    return (P is None or (type(P) is tuple and len(P) == 2 and
            type(P[0]) is int and 0 <= P[0] <= p - 1 and
            type(P[1]) is int and 0 <= P[1] <= p - 1 and
            (P[0] * P[0] * P[0] + a * P[0] + b - P[1] * P[1]) % p == 0))

#-----------------------------------------------------------------------------

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

_4b_ = 4 * b % p

def inv_mod_p(n):
    return pow(n, p - 2, p)

def AFFINE_POINT_ADDITION(P1, P2):
    x1, y1 = P1
    x2, y2 = P2
    v = ((y2 - y1) * inv_mod_p(x2 - x1)) % p
    x3 = (v * v - x1 - x2) % p
    y3 = (v * (x1 - x3) - y1) % p
    return x3, y3

def AFFINE_POINT_DOUBLING(P1):
    x1, y1 = P1
    w = ((3 * x1 * x1 + a) * inv_mod_p(2 * y1)) % p
    x4 = (w * w - 2 * x1) % p
    y4 = (w * (x1 - x4) - y1) % p
    return x4, y4

def msb_first_bit_string(n):
    return tuple(map(int,bin(n)[2:]))

def MontgomeryLadderScalarMultiply(k, P):
    if k > n // 2:
        flipped = True
        k = n - k
    else:
        flipped = False
    xP, yP = P
    X1, X2, Z = CoZIdDbl(xP, yP)
    for bit in msb_first_bit_string(k)[1:]:
        if bit == 1:
            X1, X2, Z = CoZDiffAddDbl(X1, X2, Z, xD=xP)
        else:
            X2, X1, Z = CoZDiffAddDbl(X2, X1, Z, xD=xP)
    X, Y, Z = CoZRecover(X1, X2, Z, xD=xP, yD=yP)
    iZ = inv_mod_p(Z)
    return (X * iZ) % p, ((Y * iZ) % p if not flipped else (-Y * iZ) % p)

def MontgomeryLadderScalarMultiply_ver2(k, P):
    if k > n // 2:
        flipped = True
        k = n - k
    else:
        flipped = False
    xP, yP = P
    X1, X2, Z = CoZIdDbl(xP, yP)
    xD = xP
    TD = (xD * Z) % p
    Ta = (a * Z * Z) % p
    Tb = (4 * b * Z * Z * Z) % p
    for bit in msb_first_bit_string(k)[1:]:
        if bit == 1:
            X1, X2, TD, Ta, Tb = CoZDiffAddDbl_alg6(X1, X2, TD, Ta, Tb)
        else:
            X2, X1, TD, Ta, Tb = CoZDiffAddDbl_alg6(X2, X1, TD, Ta, Tb)
    X, Y, Z = CoZRecover_alg8(X1, X2, TD, Ta, Tb, xD=xP, yD=yP)
    iZ = inv_mod_p(Z)
    return (X * iZ) % p, ((Y * iZ) % p if not flipped else (-Y * iZ) % p)

def CoZIdDbl(x, y):
    Z  = ( 4 * y * y      ) % p
    X1 = ( Z * x          ) % p
    t  = ( 3 * x * x + a  ) % p
    X2 = ( t * t - 2 * X1 ) % p
    return X1, X2, Z

def CoZDiffAddDbl(X1, X2, Z, xD):
    R2 = ( Z * Z     ) % p
    R3 = ( a * R2    ) % p
    R1 = ( Z * R2    ) % p
    R2 = ( _4b_ * R1 ) % p
    R1 = ( X2 * X2   ) % p
    R5 = ( R1 - R3   ) % p
    R4 = ( R5 * R5   ) % p
    R1 = ( R1 + R3   ) % p
    R5 = ( X2 * R1   ) % p
    R5 = ( R5 + R5   ) % p
    R5 = ( R5 + R5   ) % p
    R5 = ( R5 + R2   ) % p
    R1 = ( R1 + R3   ) % p
    R3 = ( X1 * X1   ) % p
    R1 = ( R1 + R3   ) % p
    X1 = ( X1 - X2   ) % p
    X2 = ( X2 + X2   ) % p
    R3 = ( X2 * R2   ) % p
    R4 = ( R4 - R3   ) % p
    R3 = ( X1 * X1   ) % p
    R1 = ( R1 - R3   ) % p
    X1 = ( X1 + X2   ) % p
    X2 = ( X1 * R1   ) % p
    X2 = ( X2 + R2   ) % p
    R2 = ( Z * R3    ) % p
    Z  = ( xD * R2   ) % p
    X2 = ( X2 - Z    ) % p
    X1 = ( R5 * X2   ) % p
    X2 = ( R3 * R4   ) % p
    Z  = ( R2 * R5   ) % p
    return X1, X2, Z

def CoZRecover(X1, X2, Z, xD, yD):
    R1 = ( xD * Z    ) % p
    R2 = ( X1 - R1   ) % p
    R3 = ( R2 * R2   ) % p
    R4 = ( R3 * X2   ) % p
    R2 = ( R1 * X1   ) % p
    R1 = ( X1 + R1   ) % p
    X2 = ( Z * Z     ) % p
    R3 = ( a * X2    ) % p
    R2 = ( R2 + R3   ) % p
    R3 = ( R2 * R1   ) % p
    R3 = ( R3 - R4   ) % p
    R3 = ( R3 + R3   ) % p
    R1 = ( yD + yD   ) % p
    R1 = ( R1 + R1   ) % p
    R2 = ( R1 * X1   ) % p
    X1 = ( R2 * X2   ) % p
    R2 = ( X2 * Z    ) % p
    Z  = ( R2 * R1   ) % p
    R4 = ( _4b_ * R2 ) % p
    X2 = ( R4 + R3   ) % p
    return X1, X2, Z




def ecdsa_verify_signature(publickey, message, signature):
    assert type(publickey) is bytes
    assert type(message) is bytes
    assert type(signature) is bytes

    try:
        Q = point_from_octetstring(publickey)
    except ValueError:
        return False
    if Q is None:
        return False

    try:
        r, s = parse_signature(signature)
    except ASN1Error:
        return False
    except ValueError:
        return False

    e = message_preprocessing(message)

    # Compute si = (s^(-1) mod n) and then compute (t, u) = (e*si, r*si)
    si = pow(s, n - 2, n)
    t = (e * si) % n
    u = (r * si) % n

    # Compute R = (t*G + u*Q)
    R = ecdsa_double_scalar_multiplication(t, u, Q)
    if R is None:
        return False

    # Compute r2 = the x coordinate of R mode n
    r2 = R[0] % n
    return r == r2

def mysha256(msg):
    digester = hashlib.sha256()
    digester.update(msg)
    digest = digester.digest()
    return digest

def message_preprocessing(msg):
    digest = mysha256(msg)
    return octet_string_to_unsigned_integer(digest)

def first_octet_num_value_in_an_octet_string(octet):
    return octet[0]

def octet_string_to_unsigned_integer(octet_string):
    return int.from_bytes(octet_string, byteorder='big')


def parse_signature(sig):
    r, s = parse_ASN1_SEQUENCE_of_two_INTEGERs(sig)
    if (1 <= r <= n - 1) and (1 <= s <= n - 1):
        return r, s
    else:
        raise ValueError














class ASN1Error(BaseException):
    pass

def parse_ASN1_SEQUENCE_of_two_INTEGERs(octetstring):
    sequence_elements = parse_ASN1_SEQUENCE(octetstring)
    if len(sequence_elements) != 2:
        raise ASN1Error
    octets1, octets2 = sequence_elements
    int1 = parse_ASN1_INTEGER(octets1)
    int2 = parse_ASN1_INTEGER(octets2)
    return int1, int2

def parse_ASN1_SEQUENCE(octetstring):
    if type(octetstring) is not bytes:
        raise ASN1Error
    T, L, V, X = destruct_leading_TLV_octets_from(octetstring)
    if len(X) != 0:
        raise ASN1Error
    if T != b'\x30':
        raise ASN1Error
    sequence_elements = ()
    X = V
    while len(X) != 0:
        T, L, V, X = destruct_leading_TLV_octets_from(X)
        sequence_elements += (T + L + V,)
    return sequence_elements

def parse_ASN1_BITSTRING_as_octet_string(octetstring):
    if type(octetstring) is not bytes:
        raise ASN1Error
    T, L, V, X = destruct_leading_TLV_octets_from(octetstring)
    if len(X) != 0:
        raise ASN1Error
    if T != b'\x03':
        raise ASN1Error
    if V[0] != 0x00:
        raise ASN1Error
    return V[1:]

# ----------------------------------------------------------------------------

def parse_ASN1_INTEGER(octetstring):
    if type(octetstring) is not bytes:
        raise ASN1Error
    T, L, V, X = destruct_leading_TLV_octets_from(octetstring)
    if len(X) != 0:
        raise ASN1Error
    if T != b'\x02':
        raise ASN1Error
    if len(V) >= 2 and V[0] == 0x00 and V[1] <= 0x7f:
        raise ASN1Error
    return octet_string_to_signed_integer(V)

def octet_string_to_signed_integer(octet_string):
    assert type(octet_string) is bytes

    l = len(octet_string)
    if l == 0:
        return 0

    v = first_octet_num_value_in_an_octet_string(octet_string)
    if v <= 0x7f:
        return octet_string_to_unsigned_integer(octet_string)
    else:
        return octet_string_to_unsigned_integer(octet_string) - (1 << (8 * l))


def destruct_leading_TLV_octets_from(stream):
    X = stream
    T, X = destruct_leading_T_octet_from(X)
    L, X = destruct_leading_L_octets_from(X)
    V, X = destruct_leading_V_octets_from(X, L=L)
    return T, L, V, X

def destruct_leading_T_octet_from(stream):
    if len(stream) == 0:
        raise ASN1Error
    else:
        return stream[:1], stream[1:]

def destruct_leading_L_octets_from(stream):
    if len(stream) == 0:
        raise ASN1Error
    elif stream[0] < 0x80:
        return stream[:1], stream[1:]
    elif stream[0] == 0x80:
        raise ASN1Error
    elif stream[0] > 0x80:
        return destruct_leading_long_L_octets_from(stream)

def destruct_leading_long_L_octets_from(stream):
    length = stream[0] - 0x7f
    if len(stream) < length:
        raise ASN1Error
    L, _ = stream[:length], stream[length:]
    if (length == 2 and L[1] >= 0x80) or (length > 2 and L[1] != 0x00):
        return L, _
    else:
        raise ASN1Error

def destruct_leading_V_octets_from(stream, L):
    length = get_length_from_L_octets(L)
    if len(stream) < length:
        raise ASN1Error
    else:
        return stream[:length], stream[length:]

def get_length_from_L_octets(L):
    if len(L) == 0:
        raise ASN1Error
    elif len(L) == 1 and L[0] <= 0x7f:
        return L[0]
    elif len(L) == 2 and L[0] == 0x81 and L[1] >= 0x80:
        return L[1]
    elif len(L) == L[0] - 0x7f and L[0] >= 0x82 and L[1] != 0x00:
        return octet_string_to_unsigned_integer(L[1:])
    else:
        raise ASN1Error

def CoZDiffAddDbl_alg6(X1, X2, TD, Ta, Tb):
    R2 = (X1 - X2) % p
    R1 = (R2 * R2) % p
    R2 = (X2 * X2) % p
    R3 = (R2 - Ta) % p
    R4 = (R3 * R3) % p
    R5 = (X2 + X2) % p
    R3 = (R5 * Tb) % p
    R4 = (R4 - R3) % p
    R5 = (R5 + R5) % p
    R2 = (R2 + Ta) % p
    R3 = (R5 * R2) % p
    R3 = (R3 + Tb) % p
    R5 = (X1 + X2) % p
    R2 = (R2 + Ta) % p
    R2 = (R2 - R1) % p
    X2 = (X1 * X1) % p
    R2 = (R2 + X2) % p
    X2 = (R5 * R2) % p
    X2 = (X2 + Tb) % p
    X1 = (R3 * X2) % p
    X2 = (R1 * R4) % p
    R2 = (R1 * R3) % p
    R3 = (R2 * Tb) % p
    R4 = (R2 * R2) % p
    R1 = (TD * R2) % p
    R2 = (Ta * R4) % p
    Tb = (R3 * R4) % p
    X1 = (X1 - R1) % p
    TD = R1
    Ta = R2
    return X1, X2, TD, Ta, Tb

def CoZRecover_alg8(X1, X2, TD, Ta, Tb, xD, yD):
    R1 = (TD * X1) % p
    R2 = (R1 + Ta) % p
    R3 = (X1 + TD) % p
    R4 = (R2 * R3) % p
    R3 = (X1 - TD) % p
    R2 = (R3 * R3) % p
    R3 = (R2 * X2) % p
    R4 = (R4 - R3) % p
    R4 = (R4 + R4) % p
    R4 = (R4 + Tb) % p
    R2 = (TD * TD) % p
    R3 = (X1 * R2) % p
    R1 = (xD * R3) % p
    R3 = (yD + yD) % p
    R3 = (R3 + R3) % p
    X1 = (R3 * R1) % p
    R1 = (R2 * TD) % p
    Z  = (R3 * R1) % p
    R2 = (xD * xD) % p
    R3 = (R2 * xD) % p
    X2 = (R3 * R4) % p
    return X1, X2, Z


class ASN1Error(BaseException):
    pass

def parse_ASN1_SEQUENCE_of_two_INTEGERs(octetstring):
    sequence_elements = parse_ASN1_SEQUENCE(octetstring)
    if len(sequence_elements) != 2:
        raise ASN1Error
    octets1, octets2 = sequence_elements
    int1 = parse_ASN1_INTEGER(octets1)
    int2 = parse_ASN1_INTEGER(octets2)
    return int1, int2

def parse_ASN1_SEQUENCE(octetstring):
    if type(octetstring) is not bytes:
        raise ASN1Error
    T, L, V, X = destruct_leading_TLV_octets_from(octetstring)
    if len(X) != 0:
        raise ASN1Error
    if T != b'\x30':
        raise ASN1Error
    sequence_elements = ()
    X = V
    while len(X) != 0:
        T, L, V, X = destruct_leading_TLV_octets_from(X)
        sequence_elements += (T + L + V,)
    return sequence_elements

def parse_ASN1_BITSTRING_as_octet_string(octetstring):
    if type(octetstring) is not bytes:
        raise ASN1Error
    T, L, V, X = destruct_leading_TLV_octets_from(octetstring)
    if len(X) != 0:
        raise ASN1Error
    if T != b'\x03':
        raise ASN1Error
    if V[0] != 0x00:
        raise ASN1Error
    return V[1:]

# ----------------------------------------------------------------------------

def parse_ASN1_INTEGER(octetstring):
    if type(octetstring) is not bytes:
        raise ASN1Error
    T, L, V, X = destruct_leading_TLV_octets_from(octetstring)
    if len(X) != 0:
        raise ASN1Error
    if T != b'\x02':
        raise ASN1Error
    if len(V) >= 2 and V[0] == 0x00 and V[1] <= 0x7f:
        raise ASN1Error
    return int.from_bytes(V, byteorder='big', signed=True)

def destruct_leading_TLV_octets_from(stream):
    X = stream
    T, X = destruct_leading_T_octet_from(X)
    L, X = destruct_leading_L_octets_from(X)
    V, X = destruct_leading_V_octets_from(X, L=L)
    return T, L, V, X

def destruct_leading_T_octet_from(stream):
    if len(stream) == 0:
        raise ASN1Error
    else:
        return stream[:1], stream[1:]

def destruct_leading_L_octets_from(stream):
    if len(stream) == 0:
        raise ASN1Error
    elif stream[0] < 0x80:
        return stream[:1], stream[1:]
    elif stream[0] == 0x80:
        raise ASN1Error
    elif stream[0] > 0x80:
        return destruct_leading_long_L_octets_from(stream)

def destruct_leading_long_L_octets_from(stream):
    length = stream[0] - 0x7f
    if len(stream) < length:
        raise ASN1Error
    L, _ = stream[:length], stream[length:]
    if (length == 2 and L[1] >= 0x80) or (length > 2 and L[1] != 0x00):
        return L, _
    else:
        raise ASN1Error

def destruct_leading_V_octets_from(stream, L):
    length = get_length_from_L_octets(L)
    if len(stream) < length:
        raise ASN1Error
    else:
        return stream[:length], stream[length:]

def get_length_from_L_octets(L):
    if len(L) == 0:
        raise ASN1Error
    elif len(L) == 1 and L[0] <= 0x7f:
        return L[0]
    elif len(L) == 2 and L[0] == 0x81 and L[1] >= 0x80:
        return L[1]
    elif len(L) == L[0] - 0x7f and L[0] >= 0x82 and L[1] != 0x00:
        return int.from_bytes(L[1:], byteorder='big', signed=False)
    else:
        raise ASN1Error

class X509Error(BaseException):
    pass

def ecdsa_extract_publickey_octetstring_from_certificate(certificate):
    try:
        tbscert, _, _ = parse_ASN1_SEQUENCE(certificate)
        _, _, _, _, _, _, pk_info, *_ = parse_ASN1_SEQUENCE(tbscert)
        alg, pk_bits = parse_ASN1_SEQUENCE(pk_info)
        pk_octets = parse_ASN1_BITSTRING_as_octet_string(pk_bits)
        ensure_good_subjectpublickeyinfo_algorithm_field_(alg)
        ensure_good_ecdsa_publickey_(pk_octets)
        return pk_octets
    except ASN1Error:
        pass
    except ValueError:
        pass
    raise X509Error

def ensure_good_subjectpublickeyinfo_algorithm_field_(alg):
    if alg == bytes.fromhex('301306072a8648ce3d020106082a8648ce3d030107'):
        return
    raise X509Error

def ensure_good_ecdsa_publickey_(pk_octets):
    try:
        p = point_from_octetstring(pk_octets)
        if p is not O:
            return
    except ValueError:
        pass
    raise X509Error

APPLICATION_IDENTITY = None

U2F_VERSION = 'U2F_V2'

class U2FException(BaseException):
    pass

def wb64encode(x):
    return base64.urlsafe_b64encode(x).decode().strip('=')

def wb64decode(x):
    if len(x) % 4 != 0:
        return wb64decode(x + '=')
    return base64.urlsafe_b64decode(x)

def json_serialize(obj):
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def json_deserialize(s):
    return json.loads(s)

def hmac_sha256(key, msg):
    hmac_signer = hmac.new(key, digestmod='sha256')
    hmac_signer.update(msg)
    return hmac_signer.digest()

def generate_random(n):
    return os.urandom(n)


def set_application_identity(x):
    assert type(x) is str
    global APPLICATION_IDENTITY
    APPLICATION_IDENTITY = x

def quick_hack(inner_func):
    def proxy_func(*args, **kwargs):
        try:
            assert type(APPLICATION_IDENTITY) is str
            return inner_func(*args, **kwargs)
        except:
            raise
    return proxy_func

# Token[] -> Request
@quick_hack
def create_registration_request(registered_tokens):
    challenge_wb64 = wb64encode(generate_random(32))
    return json_serialize({
        'type': 'u2f_register_request',
        'registerRequests': [{
            'version': U2F_VERSION,
            'appId': APPLICATION_IDENTITY,
            'challenge': challenge_wb64,
        }],
        'signRequests': [{
            'version': U2F_VERSION,
            'appId': APPLICATION_IDENTITY,
            'challenge': challenge_wb64,
            'keyHandle': wb64encode(t[65:]),
        } for t in registered_tokens],
    })



# (Request, Response) -> Pair<Token, TokenAttestationCertificate>
@quick_hack
def handle_registration_response(request, response):
    request_object  = json_deserialize(request)
    response_object = json_deserialize(response)

    # get the challenge randomness from myself
    challenge_wb64  = request_object['registerRequests'][0]['challenge']

    # parse client data from the U2F client
    client_data     = wb64decode(response_object['clientData'])
    client_data_obj = json_deserialize(client_data.decode())
    assert client_data_obj['typ'] == 'navigator.id.finishEnrollment'
    assert client_data_obj['challenge'] == challenge_wb64
    assert client_data_obj['origin'] == APPLICATION_IDENTITY
    cid_pubkey = (client_data_obj['cid_pubkey']
            if 'cid_pubkey' in client_data_obj else None)

    # parse raw registration response from the U2F security key
    raw_register_response = wb64decode(response_object['registrationData'])
    assert raw_register_response[0] == 0x05
    user_public_key = raw_register_response[1:66]
    khlen = raw_register_response[66]
    key_handle = raw_register_response[67:67+khlen]
    T, L, V, X = destruct_leading_TLV_octets_from(
            raw_register_response[67+khlen:])
    attestation_certificate = T + L + V
    attestation_public_key = (
            ecdsa_extract_publickey_octetstring_from_certificate(
                    attestation_certificate))
    signature = X

    # construct signature base byte-string
    app_param = mysha256(APPLICATION_IDENTITY.encode())
    cha_param = mysha256(client_data)
    signature_base = (
            b'\x00' + app_param + cha_param + key_handle + user_public_key)
    assert True == ecdsa_verify_signature(
            attestation_public_key, signature_base, signature)
    return (user_public_key + key_handle, attestation_certificate, cid_pubkey)

# Token[] -> Request
@quick_hack
def create_authentication_request(registered_tokens):
    challenge_wb64 = wb64encode(generate_random(32))
    return json_serialize({
        'type': 'u2f_sign_request',
        'signRequests': [{
            'version': U2F_VERSION,
            'appId': APPLICATION_IDENTITY,
            'challenge': challenge_wb64,
            'keyHandle': wb64encode(t[65:]),
        } for t in registered_tokens],
    })

# (Token[], Request, Response) -> Pair<Token, TokenAuthenticationCounter>
@quick_hack
def handle_authentication_response(registered_tokens, request, response):
    request_object  = json_deserialize(request)
    response_object = json_deserialize(response)

    # get the challenge randomness from myself
    challenge_wb64  = request_object['signRequests'][0]['challenge']

    # parse key handle
    token_candidates = []
    key_handle = wb64decode(response_object['keyHandle'])
    for i, t in enumerate(registered_tokens):
        if key_handle == t[65:]:
            token_candidates.append((t[:65], i))
    assert len(token_candidates) >= 1

    # parse client data from the U2F client
    client_data     = wb64decode(response_object['clientData'])
    client_data_obj = json_deserialize(client_data.decode())
    assert client_data_obj['typ'] == 'navigator.id.getAssertion'
    assert client_data_obj['challenge'] == challenge_wb64
    assert client_data_obj['origin'] == APPLICATION_IDENTITY
    cid_pubkey = (client_data_obj['cid_pubkey']
            if 'cid_pubkey' in client_data_obj else None)

    # parse raw authentication response from the U2F security key
    raw_auth_response = wb64decode(response_object['signatureData'])
    user_presence = raw_auth_response[0:1]
    counter = raw_auth_response[1:5]
    signature = raw_auth_response[5:]

    # construct signature base byte-string
    app_param = mysha256(APPLICATION_IDENTITY.encode())
    cha_param = mysha256(client_data)
    signature_base = app_param + user_presence + counter + cha_param

    # signature verification
    the_correct_token_index = None
    for k, i in token_candidates:
        if True == ecdsa_verify_signature(
            k, signature_base, signature
        ):
            the_correct_token_index = i
            break
    assert the_correct_token_index is not None
    return (registered_tokens[i], int.from_bytes(counter, 'big'), cid_pubkey)
