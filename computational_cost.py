import os
import hashlib
import hmac
from dataclasses import dataclass


try:
    import gmpy2
    _HAS_GMPY2 = True
    print("[INFO] gmpy2 detected → using accelerated big integer arithmetic.")
except Exception:
    gmpy2 = None
    _HAS_GMPY2 = False
    print("[INFO] gmpy2 not available → falling back to Python built-in integers.")


@dataclass
class Cost:
    modexp: int = 0
    inv: int = 0
    modmul: int = 0

    def __add__(self, other: "Cost") -> "Cost":
        return Cost(
            modexp=self.modexp + other.modexp,
            inv=self.inv + other.inv,
            modmul=self.modmul + other.modmul,
        )

    def __str__(self) -> str:
        return f"modexp={self.modexp}, inv={self.inv}, modmul={self.modmul}"


_COST = Cost()


def reset_cost():
    global _COST
    _COST = Cost()


def get_cost() -> Cost:
    return _COST


def mulmod(a: int, b: int, mod: int) -> int:
    global _COST
    _COST.modmul += 1
    return (a * b) % mod


def powmod(base: int, exp: int, mod: int) -> int:
    global _COST
    _COST.modexp += 1
    if _HAS_GMPY2:
        return int(gmpy2.powmod(gmpy2.mpz(base), gmpy2.mpz(exp), gmpy2.mpz(mod)))
    return pow(base, exp, mod)


def modinv(a: int, m: int) -> int:
    global _COST
    _COST.inv += 1
    if _HAS_GMPY2:
        inv = gmpy2.invert(gmpy2.mpz(a), gmpy2.mpz(m))
        if inv == 0:
            raise ValueError("Inverse does not exist")
        return int(inv)
    return pow(a, -1, m)


def hr(title: str = ""):
    line = "=" * 70
    print("\n" + line)
    if title:
        print(title)
        print("-" * 70)


def fmt_int(x: int) -> str:
    return f"{x} (0x{x:x}, bits={x.bit_length()})"


def fmt_bytes(b: bytes, maxlen: int = 80) -> str:
    hx = b.hex()
    if len(hx) > maxlen:
        hx = hx[:maxlen] + "..."
    return f"len={len(b)} bytes, hex={hx}"



def int_to_bytes(x: int) -> bytes:
    if x == 0:
        return b"\x00"
    return x.to_bytes((x.bit_length() + 7) // 8, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def kdf_split(k_int: int, k1_len=32, k2_len=32) -> tuple[bytes, bytes]:
    kb = int_to_bytes(k_int)
    digest = hashlib.sha512(kb).digest()
    k1 = digest[:k1_len]
    k2 = digest[k1_len:k1_len + k2_len]
    return k1, k2


def KH(k2: bytes, m: bytes, out_bits: int | None, q: int) -> int:
    mac = hmac.new(k2, m, hashlib.sha256).digest()
    r_int = bytes_to_int(mac)
    if out_bits is not None:
        r_int = r_int >> max(0, (len(mac) * 8 - out_bits))
    return r_int % q


def aesgcm_encrypt(key: bytes, plaintext: bytes, verbose: bool = False) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return xor_stream_encrypt(key, plaintext)

    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    packed = nonce + ct
    return packed


def aesgcm_decrypt(key: bytes, ciphertext: bytes, verbose: bool = False) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return xor_stream_decrypt(key, ciphertext)

    nonce, ct = ciphertext[:12], ciphertext[12:]
    return AESGCM(key).decrypt(nonce, ct, associated_data=None)


def xor_stream_encrypt(key: bytes, plaintext: bytes) -> bytes:
    out = bytearray()
    counter = 0
    i = 0
    while i < len(plaintext):
        counter_bytes = counter.to_bytes(4, "big")
        ks = hashlib.sha256(key + counter_bytes).digest()
        chunk = plaintext[i:i + len(ks)]
        out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
        i += len(ks)
        counter += 1
    return bytes(out)


def xor_stream_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return xor_stream_encrypt(key, ciphertext)


@dataclass
class GroupParams:
    p: int
    q: int
    g: int

@dataclass
class KeyPair:
    x: int
    y: int

def keygen(params: GroupParams) -> KeyPair:
    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    y = powmod(params.g, x, params.p)
    return KeyPair(x=x, y=y)


def signcrypt_SCS1_verbose(params: GroupParams, alice: KeyPair, bob_pub: int, m: bytes,
                           r_bits: int | None = None) -> tuple[bytes, int, int]:

    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    k = powmod(bob_pub, x, params.p)

    k1, k2 = kdf_split(k)

    r = KH(k2, m, out_bits=r_bits, q=params.q)

    denom = (r + alice.x) % params.q
    s = (x * modinv(denom, params.q)) % params.q

    c = aesgcm_encrypt(k1, m, verbose=True)
    return c, r, s


def unsigncrypt_SCS1_verbose(params: GroupParams, alice_pub: int, bob: KeyPair,
                             c: bytes, r: int, s: int,
                             r_bits: int | None = None) -> bytes:
    g_r = powmod(params.g, r, params.p)
    base = (alice_pub * g_r) % params.p

    exp = (s * bob.x) % params.q
    k = powmod(base, exp, params.p)

    k1, k2 = kdf_split(k)

    m = aesgcm_decrypt(k1, c, verbose=True)
    r_check = KH(k2, m, out_bits=r_bits, q=params.q)

    if r_check != r:
        raise ValueError("Verification failed: r != KH_{k2}(m)")
    return m


def signcrypt_SCS2_verbose(params: GroupParams, alice: KeyPair, bob_pub: int, m: bytes,
                           r_bits: int | None = None) -> tuple[bytes, int, int]:
    x = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1

    k = powmod(bob_pub, x, params.p)

    k1, k2 = kdf_split(k)

    r = KH(k2, m, out_bits=r_bits, q=params.q)

    denom = (1 + (alice.x * r) % params.q) % params.q
    s = (x * modinv(denom, params.q)) % params.q
    c = aesgcm_encrypt(k1, m, verbose=True)

    return c, r, s


def unsigncrypt_SCS2_verbose(params: GroupParams, alice_pub: int, bob: KeyPair,
                             c: bytes, r: int, s: int,
                             r_bits: int | None = None) -> bytes:

    ya_r = powmod(alice_pub, r, params.p)
    base = (params.g * ya_r) % params.p

    exp = (s * bob.x) % params.q

    k = powmod(base, exp, params.p)

    k1, k2 = kdf_split(k)

    m = aesgcm_decrypt(k1, c, verbose=True)
    r_check = KH(k2, m, out_bits=r_bits, q=params.q)

    if r_check != r:
        raise ValueError("Verification failed: r != KH_{k2}(m)")
    return m

# ElGamal Signature-then-Encryption (StE) for cost comparison

def H_to_int(m: bytes, q: int) -> int:
    return bytes_to_int(hashlib.sha256(m).digest()) % q


def elgamal_sign(params: GroupParams, alice: KeyPair, m: bytes) -> tuple[int, int]:
    h = H_to_int(m, params.q)
    k = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1

    r = powmod(params.g, k, params.p)
    xr = (alice.x * (r % params.q)) % params.q
    num = (h - xr) % params.q
    s = (num * modinv(k, params.q)) % params.q
    return r, s


def elgamal_verify(params: GroupParams, alice_pub: int, m: bytes, r: int, s: int) -> bool:
    h = H_to_int(m, params.q)
    left = powmod(params.g, h, params.p)

    y_r = powmod(alice_pub, r % params.q, params.p)
    r_s = powmod(r, s, params.p)
    right = mulmod(y_r, r_s, params.p)
    return left == right


def encode_sigma(m: bytes, r: int, s: int, p: int) -> int:
    # demo-only: hash(m||r||s) -> integer mod p
    blob = m + b"|" + int_to_bytes(r) + b"|" + int_to_bytes(s)
    M = bytes_to_int(hashlib.sha512(blob).digest()) % p
    if M == 0:
        M = 1
    return M


def elgamal_encrypt(params: GroupParams, bob_pub: int, M: int) -> tuple[int, int]:
    k = int.from_bytes(os.urandom(64), "big") % (params.q - 1) + 1
    C1 = powmod(params.g, k, params.p)
    K = powmod(bob_pub, k, params.p)
    C2 = mulmod(K, M % params.p, params.p)
    return C1, C2


def elgamal_decrypt(params: GroupParams, bob: KeyPair, C1: int, C2: int) -> int:
    K = powmod(C1, bob.x, params.p)
    M = mulmod(C2, modinv(K, params.p), params.p)
    return M


def compare_costs(params: GroupParams, alice: KeyPair, bob: KeyPair, m: bytes, r_bits: int | None = 80):

    # -------------------------
    # SCS1
    # -------------------------
    reset_cost()
    c1, r1, s1 = signcrypt_SCS1_verbose(params, alice, bob.y, m, r_bits=r_bits)
    cost_scs1_sender = get_cost()

    reset_cost()
    _ = unsigncrypt_SCS1_verbose(params, alice.y, bob, c1, r1, s1, r_bits=r_bits)
    cost_scs1_receiver = get_cost()

    # -------------------------
    # SCS2
    # -------------------------
    reset_cost()
    c2, r2, s2 = signcrypt_SCS2_verbose(params, alice, bob.y, m, r_bits=r_bits)
    cost_scs2_sender = get_cost()

    reset_cost()
    _ = unsigncrypt_SCS2_verbose(params, alice.y, bob, c2, r2, s2, r_bits=r_bits)
    cost_scs2_receiver = get_cost()

    # -------------------------
    # StE (ElGamal sign then ElGamal encrypt)
    # -------------------------
    reset_cost()
    r_sig, s_sig = elgamal_sign(params, alice, m)
    M = encode_sigma(m, r_sig, s_sig, params.p)
    C1, C2 = elgamal_encrypt(params, bob.y, M)
    cost_ste_sender = get_cost()

    reset_cost()
    _M = elgamal_decrypt(params, bob, C1, C2)
    ok = elgamal_verify(params, alice.y, m, r_sig, s_sig)
    cost_ste_receiver = get_cost()

    # -------------------------
    # Print
    # -------------------------
    hr("結果（公開金鑰核心成本：modexp / inv / modmul）")
    print("[SCS1] Sender  :", cost_scs1_sender)
    print("[SCS1] Receiver:", cost_scs1_receiver)
    print("[SCS2] Sender  :", cost_scs2_sender)
    print("[SCS2] Receiver:", cost_scs2_receiver)
    print("[StE ] Sender  :", cost_ste_sender)
    print("[StE ] Receiver:", cost_ste_receiver)
    print("[StE ] Verify OK?:", ok)

    hr("總成本（Sender + Receiver）")
    print("[SCS1] Total:", cost_scs1_sender + cost_scs1_receiver)
    print("[SCS2] Total:", cost_scs2_sender + cost_scs2_receiver)
    print("[StE ] Total:", cost_ste_sender + cost_ste_receiver)

    ste_modexp = (cost_ste_sender + cost_ste_receiver).modexp
    scs1_modexp = (cost_scs1_sender + cost_scs1_receiver).modexp
    scs2_modexp = (cost_scs2_sender + cost_scs2_receiver).modexp

    saving_scs1 = (ste_modexp - scs1_modexp) / ste_modexp * 100
    saving_scs2 = (ste_modexp - scs2_modexp) / ste_modexp * 100

    hr("節省比例（以 modular exponentiation 為主）")
    print(f"[SCS1] Saving: {saving_scs1:.2f}% "
          f"(from {ste_modexp} → {scs1_modexp} modexp)")
    print(f"[SCS2] Saving: {saving_scs2:.2f}% "
          f"(from {ste_modexp} → {scs2_modexp} modexp)")


def find_toy_params() -> GroupParams:
    p = 467
    q = 233
    # find g with order q modulo p
    for h in range(2, p - 1):
        g = pow(h, (p - 1) // q, p)  # not counted (setup)
        if g != 1 and pow(g, q, p) == 1:
            return GroupParams(p=p, q=q, g=g)
    raise RuntimeError("Failed to find toy params.")



def demo(verbose_bits: int | None = 80):
    params = find_toy_params()

    reset_cost()  # avoid counting keygen into later sections
    alice = keygen(params)
    bob = keygen(params)
    reset_cost()  # reset after keygen for clean demo sections


    m = b"Hello, signcryption!"
    
    # --- SCS1 ---
    c1, r1, s1 = signcrypt_SCS1_verbose(params, alice, bob.y, m, r_bits=verbose_bits)
    m1 = unsigncrypt_SCS1_verbose(params, alice.y, bob, c1, r1, s1, r_bits=verbose_bits)

    # --- SCS2 ---
    c2, r2, s2 = signcrypt_SCS2_verbose(params, alice, bob.y, m, r_bits=verbose_bits)
    m2 = unsigncrypt_SCS2_verbose(params, alice.y, bob, c2, r2, s2, r_bits=verbose_bits)


    # --- Cost compare ---
    compare_costs(params, alice, bob, m, r_bits=verbose_bits)


if __name__ == "__main__":
    demo(verbose_bits=80)
