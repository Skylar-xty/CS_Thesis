from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature
from blspy import PrivateKey, AugSchemeMPL
import os

class Vehicle:
    def __init__(self, vehId, vehType, maxSpeed, length, width, initialTrustScore, commRange, certificate=None):
        # Static attributes
        self.id = vehId
        self.type = vehType
        self.maxSpeed = maxSpeed
        self.length = length
        self.width = width
        self.initialTrustScore = initialTrustScore
        self.commRange = commRange

        self.certificate = certificate  # Digital certificate for authenticatio

        # Dynamic attributes
        self.position = (0, 0)
        self.speed = 0
        self.route = []
        self.trustScore = initialTrustScore
        self.malicious = False  # Indicates whether this vehicle is malicious

        # Cryptographic keys
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        # BLS 群阶（group order）
        # GROUP_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffffffffffff

        # def generate_valid_bls_key():
        #     """ 生成合法的 BLS 私钥（小于群阶） """
        #     while True:
        #         rand_num = int.from_bytes(os.urandom(32), "big") % GROUP_ORDER
        #         if rand_num > 0:  # 确保私钥不为 0
        #             return PrivateKey.from_bytes(rand_num.to_bytes(32, "big"))
        seed: bytes = bytes([0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                        19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                        12, 62, 89, 110, 182, 9,   44, 20,  254, 22])
        # BLS keys
        # self.bls_private_key = PrivateKey.from_seed(os.urandom(32))
        self.bls_private_key = AugSchemeMPL.key_gen(seed)
        self.bls_public_key = self.bls_private_key.get_g1()


    # Basic: Update attributes and Display infomation             
    def update_dynamic_attributes(self, traci):
        """Update dynamic attributes if the vehicle exists in the network."""
        if self.is_in_network(traci):
            self.position = traci.vehicle.getPosition(self.id)
            self.speed = traci.vehicle.getSpeed(self.id)
            self.route = traci.vehicle.getRoute(self.id)
        else:
            print(f"Vehicle {self.id} is not yet in the network.")

    def is_in_network(self, traci):
        """Check if the vehicle is currently in the network."""
        return self.id in traci.vehicle.getIDList()
    
    def display_info(self):
        """Display the current vehicle information."""
        if self.position:
            info = (f"ID: {self.id}, Type: {self.type}, MaxSpeed: {self.maxSpeed}, "
                    f"Length: {self.length}, Width: {self.width}, TrustScore: {self.trustScore}, "
                    f"CommRange: {self.commRange}, Position: {self.position}, Speed: {self.speed}, "
                    f"Malicious: {self.malicious}")
        else:
            info = f"ID: {self.id} has not yet entered the network."
        print(info)
    
    # P1: PKI
    # ECC + AES-GCM Encryption-Decryption
    def encrypt_message(self, recipient_public_key, message):
        """Encrypt a message using recipient's public key. ECC + AES-GCM"""
        # shared_key = self.private_key.exchange(ec.ECDH(), recipient_public_key)
        # kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vehicle encryption")
        # encryption_key = kdf.derive(shared_key)
        # ciphertext = aes_key_wrap(encryption_key, message.encode())
        # return ciphertext
        shared_key = self.private_key.exchange(ec.ECDH(), recipient_public_key)
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vehicle encryption")
        aes_key = kdf.derive(shared_key)

        # 使用 AES-GCM 加密
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
        return nonce + ciphertext

    def decrypt_message(self, sender_public_key, ciphertext):
        """Decrypt a message using sender's public key. ECC + AES-GCM"""
        # shared_key = self.private_key.exchange(ec.ECDH(), sender_public_key)
        # kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vehicle encryption")
        # decryption_key = kdf.derive(shared_key)
        # message = aes_key_unwrap(decryption_key, ciphertext)
        # return message.decode()
        shared_key = self.private_key.exchange(ec.ECDH(), sender_public_key)
        kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vehicle encryption")
        aes_key = kdf.derive(shared_key)

        aesgcm = AESGCM(aes_key)
        nonce = ciphertext[:12]
        encrypted_message = ciphertext[12:]
        return aesgcm.decrypt(nonce, encrypted_message, None).decode()

    # BLS Signature
    def bls_sign(self, message):
        """使用 BLS 签名消息"""
        message_bytes = message.encode()
        signature = AugSchemeMPL.sign(self.bls_private_key, message_bytes)
        return signature

    def bls_verify(self, message, signature, public_key):
        """验证 BLS 签名"""
        try:
            message_bytes = message.encode()
            # signature_obj = AugSchemeMPL.from_bytes(signature)
            signature_obj = signature
            ok: bool = AugSchemeMPL.verify(public_key, message_bytes, signature_obj)
            return ok
        except:
            return False  

    def get_public_keys(self):
        """返回 ECC 和 BLS 公钥"""
        return {
            "ecc": self.public_key,
            "bls": self.bls_public_key
        }    

    # # Cryptographic operations
    # def sign_message(self, message):
    #     """Sign a message using the private key."""
    #     signature = self.private_key.sign(
    #         message.encode(),
    #         ec.ECDSA(hashes.SHA256())
    #     )
    #     return signature

    # def verify_signature(self, message, signature, public_key):
    #     """Verify a message's signature using the given public key."""
    #     try:
    #         public_key.verify(signature, message.encode(), ec.ECDSA(hashes.SHA256()))
    #         return True
    #     except InvalidSignature:
    #         return False

    # P2: Trust management
    # Malicious behavior simulation
    def simulate_malicious_behavior(self):
        """Simulate malicious behavior by reducing trust score."""
        self.malicious = True
        self.trustScore -= 50
        print(f"Vehicle {self.id} is now marked as malicious.")

    # Trust management
    def update_trust_score(self, behavior_score):
        """Update the trust score based on behavior."""
        self.trustScore += behavior_score
        if self.trustScore < 50:
            print(f"🚨 Vehicle {self.id} is isolated due to low trust score {self.trustScore}.")
            self.isolate()

    def isolate(self):
        """Isolate the vehicle."""
        print(f"Vehicle {self.id} is being isolated from the network.")

