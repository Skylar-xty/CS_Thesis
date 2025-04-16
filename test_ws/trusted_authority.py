from flask import Flask, request, jsonify
import sqlite3

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ObjectIdentifier
import os
from blspy import PrivateKey, AugSchemeMPL

### 🚗 5. 证书认证机构（CA）功能
class CertificateAuthority:
    def __init__(self):
        """ 生成 CA 私钥与根证书 """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # 生成 CA 根证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoV Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, "IoV Root CA"),
        ])

        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .sign(self.private_key, hashes.SHA256())
        )
    def issue_certificate(self, vehicle_id, ecc_public_key, bls_public_key):
        """ CA 颁发证书，包含 ECC 和 BLS 公钥 """
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IoV Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"Vehicle-{vehicle_id}"),
        ])
        # 定义自定义 OID（建议用 1.3.6.1.4.1.xxxx.yyyy 格式）
        BLS_PUBLIC_KEY_OID = ObjectIdentifier("1.3.6.1.4.1.99999.1")
        # 将 BLS 公钥转换为字节格式
        bls_public_key_bytes = bytes(bls_public_key)

        # 生成 X.509 证书
        certificate = x509.CertificateBuilder().subject_name(subject)\
            .issuer_name(self.certificate.subject)\
            .public_key(ecc_public_key)\
            .add_extension(
                x509.UnrecognizedExtension(BLS_PUBLIC_KEY_OID, bls_public_key_bytes),
                critical=False
            )\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.datetime.utcnow())\
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))\
            .sign(self.private_key, hashes.SHA256())

        return certificate
    def verify_certificate(self, certificate):
        """验证该证书是否由 CA 自身签发"""
        try:
            # 使用 CA 的公钥验证证书签名
            self.certificate.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),   # 用 RSA 的 padding模式
                certificate.signature_hash_algorithm
                # ec.ECDSA(certificate.signature_hash_algorithm)
            )
            return True
        except Exception as e:
            print("❌ 证书验证失败:", e)
            return False
    # def verify_certificate(self, certificate):
    #     """ 验证证书是否由 CA 颁发 """
    #     try:
    #         certificate.public_key().verify(
    #             certificate.signature,
    #             certificate.tbs_certificate_bytes,
    #             ec.ECDSA(hashes.SHA256())
    #         )
    #         return True
    #     except:
    #         return False

ca = CertificateAuthority()

app = Flask(__name__)

# 🚀 1. 初始化数据库（存储信任值）
def connect_db():
    conn = sqlite3.connect("trust_db.sqlite")
    return conn

def init_db():
    conn = connect_db()
    cursor = conn.cursor()
    # **🗑️ 清空 `vehicles` 表，防止主键冲突**
    cursor.execute("DROP TABLE IF EXISTS vehicles")

    cursor.execute('''CREATE TABLE IF NOT EXISTS vehicles (
                        veh_id TEXT PRIMARY KEY,
                        trust_score REAL DEFAULT 1.0,
                        anomaly_driving INTEGER DEFAULT 0,
                        collision INTEGER DEFAULT 0,
                        data_reliability REAL DEFAULT 1.0,
                        data_consistency REAL DEFAULT 1.0,
                        valid_certification INTEGER DEFAULT 1,
                        neighbor_trust REAL DEFAULT 1.0,
                        ecc_public_key BLOB,
                        bls_public_key BLOB,
                        certificate BLOB
                      )''')
    conn.commit()
    conn.close()

init_db()  # 初始化数据库


### 🚗 3. 车辆注册（包含证书）
@app.route("/register_vehicle", methods=["POST"])
def register_vehicle():
    data = request.json
    veh_id = data["veh_id"]
    ecc_public_key_pem = data["ecc_public_key"]
    bls_public_key_hex = data["bls_public_key"]

    # 解析 ECC 公钥
    ecc_public_key = serialization.load_pem_public_key(ecc_public_key_pem.encode())

    # 解析 BLS 公钥
    bls_public_key = AugSchemeMPL.key_gen(bytes.fromhex(bls_public_key_hex)).get_g1()

    # CA 颁发证书
    certificate = ca.issue_certificate(veh_id, ecc_public_key, bls_public_key)

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO vehicles (veh_id, trust_score, anomaly_driving, collision, 
                      data_reliability, data_consistency, valid_certification, neighbor_trust, 
                      ecc_public_key, bls_public_key, certificate)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                   (veh_id, 1.0, 0, 0, 1.0, 1.0, 1, 1.0, ecc_public_key_pem, bls_public_key_hex, certificate.public_bytes(encoding=serialization.Encoding.PEM)))
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"✅ 车辆 {veh_id} 注册成功，证书已颁发"}), 200

# 🚗 3. 查询某辆车的信任值和位置信息
@app.route("/get_vehicle_info", methods=["GET"])
def get_vehicle_info():
    veh_id = request.args.get("veh_id")  # 查询目标车辆
    
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vehicles WHERE veh_id=?", (veh_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return jsonify({
            "veh_id": result[0], 
            "trust_score": result[1],
            "anomaly_driving": result[2],
            "collision": result[3],
            "data_reliability": result[4],
            "data_consistency": result[5],
            "valid_certification": result[6],
            "neighbor_trust": result[7]
        })
    else:
        return jsonify({"error": "车辆未注册"}), 404

# 🚗 4. 更新车辆信任值（发生违规时）
@app.route("/update_trust_factors", methods=["POST"])
def update_trust():
    data = request.json
    veh_id = data["veh_id"]

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''UPDATE vehicles SET 
                      trust_score=?, anomaly_driving=?, collision=?, 
                      data_reliability=?, data_consistency=?, valid_certification=?, neighbor_trust=? 
                      WHERE veh_id=?''',
                   (data["trust_score"], data["anomaly_driving"], data["collision"], 
                    data["data_reliability"], data["data_consistency"], 
                    data["valid_certification"], data["neighbor_trust"], veh_id))
    conn.commit()
    conn.close()

    return jsonify({"message": f"✅ 车辆 {veh_id} 信任值更新成功"}), 200

### 🚗 4. 查询车辆证书
@app.route("/get_vehicle_certificate", methods=["GET"])
def get_vehicle_certificate():
    veh_id = request.args.get("veh_id")

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT certificate FROM vehicles WHERE veh_id=?", (veh_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({"certificate": result[0].decode()}), 200
    else:
        return jsonify({"error": "车辆未注册或证书不存在"}), 404


### 🚗 6. 证书验证 API
@app.route("/verify_certificate", methods=["POST"])
def verify_certificate():
    data = request.json
    cert_pem = data["certificate"]

    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        if ca.verify_certificate(cert):
            return jsonify({"message": "✅ 证书有效"}), 200
        else:
            return jsonify({"error": "❌ 证书无效"}), 400
    except:
        return jsonify({"error": "❌ 证书解析失败"}), 400

if __name__ == "__main__":
# import os

# # 🚀 1. 运行服务器之前，删除旧数据库
# if os.path.exists("trust_db.sqlite"):
#     print("🗑️ 删除旧的 trust_db.sqlite...")
#     os.remove("trust_db.sqlite")

    # 运行服务器
    app.run(debug=True, port=5000)
