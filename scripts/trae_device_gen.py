"""生成 Trae 客户端 storage.json 里的设备身份（B0 验证用）。

只写两个键，够 device_identity_for / device_secret_by_device_id 读：
  telemetry.machineId                     -> 任意 64 hex
  iCubeAuthInfo://icube-dc:<deviceId>     -> tc 信封（含私钥+公钥 PEM）

tc 信封格式（复刻 icube.rs 的 seal_envelope）：
  raw = magic(6) || salt(32) || AES128CBC(PKCS7, sha512(body) || body)
  key,iv = derive(sha512(salt) || pepper)
  pepper = WOE_T ^ VOE_T
"""

import base64
import hashlib
import json
import re
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

REPO = Path(r"F:\AI\qoder-trae-workbuddy-switch")
ICUBE_RS = REPO / "crates/buddy-switch-core/src/modules/trae/icube.rs"

TC_HEADER = bytes([116, 99, 5, 16, 0, 0])
RANDOM_LEN = 32
SHA512_LEN = 64


def load_pepper() -> bytes:
    src = ICUBE_RS.read_text(encoding="utf-8")

    def table(name: str) -> bytes:
        m = re.search(rf"const {name}: \[u8; 64\] = \[(.*?)\];", src, re.S)
        if not m:
            raise SystemExit(f"找不到常量 {name}")
        nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
        if len(nums) != 64:
            raise SystemExit(f"{name} 长度 {len(nums)} != 64")
        return bytes(nums)

    pepper = bytes(a ^ b for a, b in zip(table("WOE_T"), table("VOE_T")))
    if pepper[:6] != bytes([77, 212, 194, 230, 184, 49]):
        raise SystemExit(f"pepper 自检失败: {list(pepper[:6])}")
    return pepper


def derive_keys(salt: bytes, pepper: bytes) -> tuple[bytes, bytes]:
    joined = hashlib.sha512(salt).digest() + pepper
    digest = hashlib.sha512(joined).digest()
    return digest[:16], digest[16:32]


def seal(plain: bytes, pepper: bytes) -> str:
    salt = secrets.token_bytes(RANDOM_LEN)
    key, iv = derive_keys(salt, pepper)
    body = hashlib.sha512(plain).digest() + plain
    pad = 16 - (len(body) % 16)
    body += bytes([pad]) * pad
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    cipher = enc.update(body) + enc.finalize()
    return base64.b64encode(TC_HEADER + salt + cipher).decode()


def main() -> None:
    variant_dir = sys.argv[1] if len(sys.argv) > 1 else "Trae CN"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("out")

    pepper = load_pepper()

    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    device_id = str(secrets.randbelow(10**15, ) + 10**15)  # 16 位十进制，与真机同形
    machine_id = secrets.token_hex(32)

    plain = json.dumps(
        {"privateKeyPEM": private_pem, "publicKeyPEM": public_pem},
        ensure_ascii=False,
    )
    envelope = seal(plain.encode(), pepper)

    storage = {
        "telemetry.machineId": machine_id,
        f"iCubeAuthInfo://icube-dc:{device_id}": envelope,
    }

    target = out_dir / variant_dir / "User" / "globalStorage"
    target.mkdir(parents=True, exist_ok=True)
    path = target / "storage.json"
    path.write_text(json.dumps(storage, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"variant_dir = {variant_dir}")
    print(f"device_id   = {device_id}")
    print(f"machine_id  = {machine_id}")
    print(f"envelope    = {len(envelope)} chars")
    print(f"written     = {path.resolve()}")

    # 自检：解回来必须与原文一致
    raw = base64.b64decode(envelope)
    assert raw[:6] == TC_HEADER, "magic 不符"
    salt, cipher = raw[6:38], raw[38:]
    k, iv = derive_keys(salt, pepper)
    dec = Cipher(algorithms.AES(k), modes.CBC(iv)).decryptor()
    padded = dec.update(cipher) + dec.finalize()
    pad = padded[-1]
    padded = padded[:-pad]
    tag, body = padded[:SHA512_LEN], padded[SHA512_LEN:]
    assert hashlib.sha512(body).digest() == tag, "SHA512 校验失败"
    assert json.loads(body) == json.loads(plain), "明文不一致"
    print("selfcheck   = OK")


if __name__ == "__main__":
    main()
