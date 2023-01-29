import struct
import typing
from .const import SS, KC


def SeedG(val):
    return SS[3][(val >> 24) & 0xff] ^ SS[2][(val >> 16) & 0xff] ^ SS[1][(val >> 8) & 0xff] ^ SS[0][(val >> 0) & 0xff]


def SeedRoundKey(userKey: bytes):
    A, B, C, D = struct.unpack(">IIII", userKey)
    roundKey = [0 for _ in range(32)]

    for i in range(16):
        roundKey[i * 2 + 0] = SeedG(A + C - KC[i])
        roundKey[i * 2 + 1] = SeedG(B - D + KC[i])

        if (i % 2 == 0):
            T0 = A
            A = (A >> 8) | (B << 24)
            B = (B >> 8) | (T0 << 24)
        else:
            T0 = C
            C = (C << 8) | (D >> 24)
            D = (D << 8) | (T0 >> 24)
    return roundKey


def SeedEncrypt(roundKey: typing.List[int], inputData: bytes):
    L0, L1, R0, R1 = struct.unpack(">IIII", inputData)

    for i in range(16):
        T0 = R0 ^ roundKey[i * 2 + 0]
        T1 = R1 ^ roundKey[i * 2 + 1]

        T1 ^= T0
        T1 = SeedG(T1)
        T0 += T1
        T0 = SeedG(T0)
        T1 += T0
        T1 = SeedG(T1)
        T0 += T1

        L0 ^= T0
        L1 ^= T1

        [L0, R0] = [R0, L0]
        [L1, R1] = [R1, L1]

    return struct.pack(">IIII", R0 & 0xffffffff, R1 & 0xffffffff, L0 & 0xffffffff, L1 & 0xffffffff)


def SeedDecrypt(roundKey: typing.List[int], inputData: bytes):
    L0, L1, R0, R1 = struct.unpack(">IIII", inputData)

    for i in range(16):
        T0 = R0 ^ roundKey[(15-i) * 2 + 0]
        T1 = R1 ^ roundKey[(15-i) * 2 + 1]

        T1 ^= T0
        T1 = SeedG(T1)
        T0 += T1
        T0 = SeedG(T0)
        T1 += T0
        T1 = SeedG(T1)
        T0 += T1

        L0 ^= T0
        L1 ^= T1

        [L0, R0] = [R0, L0]
        [L1, R1] = [R1, L1]

    return struct.pack(">IIII", R0 & 0xffffffff, R1 & 0xffffffff, L0 & 0xffffffff, L1 & 0xffffffff)


def SeedCBCDecrypt(roundKey, iv, data):
    assert len(data) % 16 == 0

    for i in range(len(data)//16):
        out = SeedDecrypt(roundKey, data[i*16:i*16+16])
        plain = bytes(map(lambda v: v[0] ^ v[1], zip(iv, out)))
        iv = data[i*16:i*16+16]

        yield plain


def SeedCBCEncrypt(roundKey, iv, data):
    assert len(data) % 16 == 0

    for i in range(len(data)//16):
        plainXor = bytes(
            map(lambda v: v[0] ^ v[1], zip(iv, data[i*16:i*16+16])))
        cipher = SeedEncrypt(roundKey, plainXor)
        iv = cipher

        yield cipher
