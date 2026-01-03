import hashlib
import secrets
import time
from dataclasses import dataclass


USE_GMPY2 = False
try:
    import gmpy2  # type: ignore
    USE_GMPY2 = True
except Exception:
    USE_GMPY2 = False


class Counter:
    def __init__(self):
        self.powmods = 0
        self.invs = 0


CTR = Counter()


def powmod(a: int, e: int, m: int) -> int:
    CTR.powmods += 1                         # Counted modular exponentiation
    if USE_GMPY2:
        return int(gmpy2.powmod(a, e, m))
    return pow(a, e, m)


def invmod(a: int, m: int) -> int:
    CTR.invs += 1                    # Counted modular inverse
    if USE_GMPY2:
        inv = gmpy2.invert(a, m)
        if inv == 0:
            raise ValueError("No modular inverse exists")
        return int(inv)
    return pow(a, -1, m)


def int_len_bytes(n: int) -> int:
    return (n.bit_length() + 7) // 8


def int_to_fixed_bytes(x: int, n: int) -> bytes:
    L = int_len_bytes(n)
    return int(x).to_bytes(L, "big")


def fixed_bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


# hash/KDF and XOR stream cipher  (simple for demo)
def H_bytes(*parts: bytes, out_len=32) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()[:out_len]


def H_int_mod_q(q: int, *parts: bytes) -> int:
    return int.from_bytes(H_bytes(*parts, out_len=32), "big") % q


def kdf_stream(key: bytes, nbytes: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(key + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:nbytes]


def xor_stream_encrypt(key: bytes, m: bytes) -> bytes:
    stream = kdf_stream(key, len(m))
    return bytes(a ^ b for a, b in zip(m, stream))


def xor_stream_decrypt(key: bytes, c: bytes) -> bytes:
    return xor_stream_encrypt(key, c)


# Group parameters + demo safe-prime-ish generation
@dataclass
class Group:
    p: int
    q: int
    g: int


# 質數檢測 for 離散對數群
def is_probable_prime(n: int, k: int = 16) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # write n-1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


# 回傳 p, q, g
def make_demo_group(bits=512) -> Group:
    if bits < 256:
        raise ValueError("Use >=256 bits for a meaningful demo.")
    while True:
        q = secrets.randbits(bits - 1) | 1
        q |= (1 << (bits - 2))  # force size
        p = 2 * q + 1
        if is_probable_prime(q) and is_probable_prime(p):
            # g=2 often works for safe prime; demo simplification.
            return Group(p=p, q=q, g=2)



# Key generation
@dataclass
class KeyPair:
    x: int  # secret
    y: int  # public


def keygen(G: Group) -> KeyPair:
    x = secrets.randbelow(G.q - 1) + 1
    y = powmod(G.g, x, G.p)
    return KeyPair(x=x, y=y)



# Schnorr signature (DLP-based, subgroup order q)
def schnorr_sign(G: Group, sk: int, msg: bytes) -> tuple[int, int]:
    k = secrets.randbelow(G.q - 1) + 1
    r = powmod(G.g, k, G.p)  # commitment
    r_bytes = r.to_bytes(int_len_bytes(G.p), "big")
    e = H_int_mod_q(G.q, msg, r_bytes)
    s = (k + e * sk) % G.q
    return e, s


def schnorr_verify(G: Group, pk: int, msg: bytes, sig: tuple[int, int]) -> bool:
    e, s = sig
    y_inv_e = powmod(pk, (G.q - e) % G.q, G.p)
    v = (powmod(G.g, s, G.p) * y_inv_e) % G.p
    v_bytes = v.to_bytes(int_len_bytes(G.p), "big")
    e2 = H_int_mod_q(G.q, msg, v_bytes)
    return e2 == e



# ElGamal hybrid encryption
def elgamal_encrypt(G: Group, pkB: int, plaintext: bytes) -> tuple[int, bytes]:
    k = secrets.randbelow(G.q - 1) + 1
    c1 = powmod(G.g, k, G.p)
    shared = powmod(pkB, k, G.p)
    key = H_bytes(shared.to_bytes(int_len_bytes(G.p), "big"))
    c2 = xor_stream_encrypt(key, plaintext)
    return c1, c2


def elgamal_decrypt(G: Group, skB: int, ct: tuple[int, bytes]) -> bytes:
    c1, c2 = ct
    shared = powmod(c1, skB, G.p)
    key = H_bytes(shared.to_bytes(int_len_bytes(G.p), "big"))
    return xor_stream_decrypt(key, c2)



# Traditional: Sign-then-Encrypt (Schnorr + ElGamal)
def sign_then_encrypt(G: Group, skA: int, pkB: int, msg: bytes) -> tuple[int, bytes]:
    e, s = schnorr_sign(G, skA, msg)
    Lq = int_len_bytes(G.q)

    payload = msg + b"||" + e.to_bytes(Lq, "big") + s.to_bytes(Lq, "big")   # Demo payload format: msg || e || s
    return elgamal_encrypt(G, pkB, payload)


def decrypt_then_verify(G: Group, pkA: int, skB: int, ct: tuple[int, bytes]) -> tuple[bytes, bool]:
    payload = elgamal_decrypt(G, skB, ct)
    try:
        msg, rest = payload.split(b"||", 1)
        Lq = int_len_bytes(G.q)
        if len(rest) < 2 * Lq:
            return b"", False
        e = fixed_bytes_to_int(rest[:Lq]) % G.q
        s = fixed_bytes_to_int(rest[Lq:2 * Lq]) % G.q
        ok = schnorr_verify(G, pkA, msg, (e, s))
        return msg, ok
    except Exception:
        return b"", False



# Signcryption (SCS1-like) 
def signcrypt_scs1(G: Group, skA: int, pkA: int, pkB: int, msg: bytes) -> tuple[bytes, int, int]:
    # 1) choose x, compute shared k = yb^x mod p
    x = secrets.randbelow(G.q - 1) + 1
    k = powmod(pkB, x, G.p)

    k_bytes = k.to_bytes(int_len_bytes(G.p), "big")
    k1 = H_bytes(b"K1", k_bytes)
    k2 = H_bytes(b"K2", k_bytes)

    # 2) r = KH_{k2}(m) (mod q)
    r = H_int_mod_q(G.q, k2, msg)

    # 3) s = x / (r + xa) mod q
    denom = (r + skA) % G.q
    s = (x * invmod(denom, G.q)) % G.q

    # 4) c = Enc_{k1}(m)
    c = xor_stream_encrypt(k1, msg)

    # Send (c, r, s)
    return c, r, s


def unsigncrypt_scs1(G: Group, pkA: int, skB: int, ct: tuple[bytes, int, int]) -> tuple[bytes, bool]:
    c, r, s = ct

    base = (pkA * powmod(G.g, r, G.p)) % G.p
    exp = (s * skB) % G.q
    k = powmod(base, exp, G.p)

    k_bytes = k.to_bytes(int_len_bytes(G.p), "big")
    k1 = H_bytes(b"K1", k_bytes)
    k2 = H_bytes(b"K2", k_bytes)

    msg = xor_stream_decrypt(k1, c)
    r2 = H_int_mod_q(G.q, k2, msg)
    return msg, (r2 == r)


#  demonstration
def run_once(G: Group, msg: bytes):
    alice = keygen(G)
    bob = keygen(G)

    # 1) Traditional pipeline
    CTR.powmods = 0
    CTR.invs = 0
    t0 = time.perf_counter()
    ct1 = sign_then_encrypt(G, alice.x, bob.y, msg)
    m1, ok1 = decrypt_then_verify(G, alice.y, bob.x, ct1)
    t1 = time.perf_counter()
    pow1, inv1, time1 = CTR.powmods, CTR.invs, (t1 - t0)

    # 2) Signcryption pipeline
    CTR.powmods = 0
    CTR.invs = 0
    t2 = time.perf_counter()
    ct2 = signcrypt_scs1(G, alice.x, alice.y, bob.y, msg)
    m2, ok2 = unsigncrypt_scs1(G, alice.y, bob.x, ct2)
    t3 = time.perf_counter()
    pow2, inv2, time2 = CTR.powmods, CTR.invs, (t3 - t2)

    # Sanity checks
    assert m1 == msg and ok1, "Traditional pipeline failed"
    assert m2 == msg and ok2, "Signcryption pipeline failed"

    print("=== Results ===")
    print(
        f"[Traditional: Schnorr + ElGamal] powmods={pow1}, invs={inv1}, time={time1:.6f}s")
    print(
        f"[Signcryption: SCS1-like]     powmods={pow2}, invs={inv2}, time={time2:.6f}s")
    if pow1 > 0:
        print(f"Powmod reduction: {(pow1 - pow2) / pow1 * 100:.1f}%")
    print(f"USE_GMPY2={USE_GMPY2}")


if __name__ == "__main__":
    G = make_demo_group(bits=512)
    msg = b"Hello, signcryption demo!"
    run_once(G, msg)
