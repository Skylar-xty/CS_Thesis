'''
    身份伪造攻击
'''
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

def perform_identity_forgery_attack(attacker_name="99"):
    """
        🚨 身份伪造攻击：构造伪造证书（由非可信 CA 签发），发送给 TA 验证接口。
        Parameters:
            attacker_name (str): 伪造证书中声明的 veh_id
    """
    print(f"⚠️ 正在模拟身份伪造攻击者：Vehicle {attacker_name}")
    # 1. 构造伪造 CA 与攻击者公钥
    fake_ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2. 构建伪造证书（伪签名）
    fake_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, attacker_name),
        ]))
        .issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"FakeCA"),
        ]))
        .public_key(attacker_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .sign(fake_ca_private_key, hashes.SHA256())
    )

    # 3. 导出 PEM 证书
    fake_cert_pem = fake_cert.public_bytes(serialization.Encoding.PEM).decode()

    # 4. 发送给 TA 服务端验证接口
    url = "http://localhost:5000/verify_certificate"
    res = requests.post(url, json={"certificate": fake_cert_pem})
    print("📤 伪造证书响应结果:", res.json())
