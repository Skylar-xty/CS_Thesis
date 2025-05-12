'''
    身份伪造攻击，重放攻击
'''
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta
import json
import time

# 身份伪造攻击
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

# 重放攻击
def perform_replay_attack(captured_message=None, delay=500):
    """
    🚨 重放攻击：延迟重新发送一条旧的合法消息
    Parameters:
        captured_message (dict): 捕获的原始合法消息（包含 timestamp 和签名）
        delay (int): 延迟秒数再重发，模拟攻击
    """
    if not captured_message:
        # 示例默认捕获数据（你应从真实通信中抓取）
        captured_message = {
            "veh_id": "13",
            "location": "104.95,37.99",
            "speed": 30,
            "event": "normal",
            "timestamp": time.time(),  # 原始发送时间（模拟）
            "signature": "PLACEHOLDER_SIGNATURE"  # 必须替换为真实签名
        }

    print(f"⚠️ 正在模拟重放攻击：将延迟 {delay} 秒后重发消息")
    time.sleep(delay)

    try:
        url = "http://localhost:5000/receive_data"
        res = requests.post(url, json=captured_message)
        print("📤 重放攻击响应结果:", res.json())
    except Exception as e:
        print("❌ 重放攻击请求失败:", str(e))

captured_for_replay = [] # 存储捕获的项目 {sender_id, receiver_id, message_content, nonce, signature, ciphertext, sender_bls_pk, sender_ecc_pk}

def capture_for_replay(sender_id, receiver_id, message_content, nonce, signature, ciphertext,
                       sender_bls_pk_for_receiver_verify, sender_ecc_pk_for_receiver_decrypt):
    global captured_for_replay
    print(f"😈 [攻击者] 捕获从 {sender_id} 到 {receiver_id} 的消息用于重放。Nonce: {nonce.split('-')[0]}...")
    captured_for_replay.append({
        "sender_id": sender_id, "receiver_id": receiver_id,
        "message_content": message_content, "nonce": nonce,
        "signature": signature, "ciphertext": ciphertext,
        "sender_bls_pk": sender_bls_pk_for_receiver_verify,
        "sender_ecc_pk": sender_ecc_pk_for_receiver_decrypt
    })

def perform_replay_attack_detailed(vehicles_map, specific_packet_index=0, clear_receiver_nonce_cache=False):
    global captured_for_replay
    if not captured_for_replay or specific_packet_index >= len(captured_for_replay):
        print("😈 [攻击者] 没有捕获到消息 (或索引无效) 可供重放。")
        return False

    packet = captured_for_replay[specific_packet_index]
    original_sender_id = packet["sender_id"]
    original_receiver_id = packet["receiver_id"]

    if original_receiver_id not in vehicles_map or original_sender_id not in vehicles_map:
        print(f"😈 [攻击者] 原始发送方 {original_sender_id} 或接收方 {original_receiver_id} 不在车辆映射中。")
        return False

    receiver_obj = vehicles_map[original_receiver_id]
    
    if clear_receiver_nonce_cache: # 用于测试：重置接收方对此Nonce的记忆
        if original_sender_id in receiver_obj.recently_processed_nonces and \
           packet["nonce"] in receiver_obj.recently_processed_nonces[original_sender_id]:
            del receiver_obj.recently_processed_nonces[original_sender_id][packet["nonce"]]
            print(f"  [攻击者-调试] 已从 {original_receiver_id} 的缓存中清除针对 {original_sender_id} 的 Nonce {packet['nonce'].split('-')[0]}...")

    print(f"\n😈 [攻击者] 尝试重放捕获的数据包 #{specific_packet_index} 从 {original_sender_id} 到 {original_receiver_id}。")
    print(f"  重放 Nonce: {packet['nonce'].split('-')[0]}...")
    print(f"  重放内容: '{packet['message_content']}'")
    time.sleep(0.1) # 模拟一点延迟

    # 直接模拟接收方的处理步骤以进行此攻击演示
    # 1. 接收方检查Nonce
    if receiver_obj.is_nonce_replayed(original_sender_id, packet["nonce"]):
        print(f"👍 防御成功：{original_receiver_id} 检测到来自 {original_sender_id} 的 Nonce {packet['nonce'].split('-')[0]}... 的重放。")
        return True # 攻击被防御
    else:
        print(f"⚠️ {original_receiver_id} 未将 Nonce {packet['nonce'].split('-')[0]}... 检测为重放。继续验证...")

    # 2. 接收方验证签名 (使用原始发送方的BLS公钥)
    is_sig_valid = receiver_obj.bls_verify(
        packet["message_content"], packet["nonce"],
        packet["signature"], packet["sender_bls_pk"]
    )
    if not is_sig_valid:
        print(f"😈 [攻击者] {original_receiver_id} 对重放签名的验证失败。(对于纯重放有效签名而言不应发生)")
        return False # 由于其他原因攻击失败

    print(f"  [攻击者] {original_receiver_id} 验证重放签名通过。")

    # 3. 接收方解密消息
    try:
        decrypted_msg = receiver_obj.decrypt_message(
            packet["sender_ecc_pk"], packet["ciphertext"]
        )
        print(f"  [攻击者] {original_receiver_id} 将重放消息解密为: '{decrypted_msg}'")
        if decrypted_msg == packet["message_content"]:
            print(f"👹 攻击成功 (Nonce检查失败或被绕过)：{original_receiver_id} 处理了重放消息！")
            return False # 攻击成功，因为Nonce检查未能阻止它
        else:
            print(f"😈 [攻击者] 解密消息内容不匹配。(对于纯重放而言不应发生)")
            return False
    except Exception as e:
        print(f"😈 [攻击者] {original_receiver_id} 解密重放消息失败: {e}")
        return False
    return False 


# 使用已吊销证书进行通信（Revoked Certificate Attack)
def perform_revoked_certificate_attack(
    attacker_id, # 尝试使用已吊销证书的车辆ID
    victim_receiver_id, # 攻击者尝试与之通信的车辆ID
    vehicles_map, # main.py 中的 vehicles 字典
    # 以下函数需要从 main.py 传递过来，或者通过其他方式调用
    main_perform_secure_communication_func,
    ta_revoke_certificate_url="http://localhost:5000/revoke_certificate",
    main_get_certificate_func=None, # 可选，用于检查证书是否真的没了
    main_verify_certificate_func=None # 可选，用于验证TA是否正确拒绝
):
    """
    模拟使用已吊销证书进行通信的攻击。
    """
    print(f"\n--- 开始模拟已吊销证书攻击 ---")
    print(f"  攻击者: {attacker_id}, 目标接收者: {victim_receiver_id}")

    if attacker_id not in vehicles_map or victim_receiver_id not in vehicles_map:
        print(f"  ❌ 攻击中止：攻击者 {attacker_id} 或接收者 {victim_receiver_id} 未在车辆字典中初始化。")
        return

    # 步骤 0: (可选) 确保攻击者和受害者都已注册且有有效证书
    # 这里我们假设它们在仿真开始时已经注册了。
    # 也可以在此处进行一次成功的通信来验证初始状态。
    print(f"  [阶段0] 假设 {attacker_id} 和 {victim_receiver_id} 已注册并有有效证书。")
    # if main_perform_secure_communication_func:
    #     print(f"    尝试一次正常通信 (attacker: {attacker_id} -> receiver: {victim_receiver_id}) 以确保初始设置正确...")
    #     initial_comm_success = main_perform_secure_communication_func(attacker_id, victim_receiver_id, "初始测试消息")
    #     if not initial_comm_success:
    #         print(f"    ⚠️ 初始通信失败，吊销证书攻击测试可能不准确。")
    #         # return # 可以选择在这里中止

    # 步骤 1: TA 吊销攻击者的证书
    print(f"\n  [阶段1] 请求TA吊销车辆 {attacker_id} 的证书...")
    try:
        response = requests.post(ta_revoke_certificate_url, json={"veh_id": attacker_id}, timeout=5)
        if response.status_code == 200:
            print(f"    ✅ TA确认车辆 {attacker_id} 的证书已吊销/标记为无效。 ({response.json().get('message')})")
            # 可以选择在本地车辆对象中也标记一下，但这仅为模拟，真实决策依赖TA
            if attacker_id in vehicles_map:
                vehicles_map[attacker_id].valid_certification = 0 # 模拟本地状态更新
                vehicles_map[attacker_id].trustScore = 0 # 通常吊销会导致信任清零
        else:
            print(f"    ❌ TA吊销证书 {attacker_id} 失败: {response.status_code} - {response.text}")
            print(f"  ❌ 攻击中止：无法吊销证书。")
            return
    except requests.exceptions.RequestException as e:
        print(f"    ❌ 连接TA吊销接口 ({ta_revoke_certificate_url}) 失败: {e}")
        print(f"  ❌ 攻击中止：无法连接TA。")
        return

    # 稍作等待，确保TA状态已更新（如果TA有缓存机制）
    time.sleep(1)

    # （可选）验证证书确实被吊销了 (通过再次查询或验证)
    if main_get_certificate_func and main_verify_certificate_func:
        print(f"\n  [验证吊销] 尝试获取并验证 {attacker_id} 已吊销的证书...")
        revoked_cert_pem = main_get_certificate_func(attacker_id)
        if revoked_cert_pem:
            if not main_verify_certificate_func(revoked_cert_pem, attacker_id):
                print(f"    ✅ 验证确认：TA现在认为车辆 {attacker_id} 的证书无效。")
            else:
                print(f"    ⚠️ 验证警告：TA仍然认为车辆 {attacker_id} 的证书有效！吊销可能未生效或验证逻辑有误。")
        else:
            print(f"    ℹ️ 车辆 {attacker_id} 的证书已无法从TA获取 (可能表示已移除或吊销)。")


    # 步骤 2: 攻击者尝试使用其（现在已吊销的）证书与受害者通信
    print(f"\n  [阶段2] 攻击者 {attacker_id} (证书应已吊销) 尝试与 {victim_receiver_id} 进行安全通信...")
    
    # 在调用 perform_secure_communication 之前，接收者 victim_receiver_id 可能缓存了 attacker_id 的证书状态。
    # 需要清除这个缓存以强制重新向TA验证。
    if victim_receiver_id in vehicles_map and hasattr(vehicles_map[victim_receiver_id], 'verified_certificates'):
        if attacker_id in vehicles_map[victim_receiver_id].verified_certificates:
            del vehicles_map[victim_receiver_id].verified_certificates[attacker_id]
            print(f"清除了接收者 {victim_receiver_id} 对攻击者 {attacker_id} 证书的本地验证缓存。")

    if main_perform_secure_communication_func:
        communication_attempt_succeeded = main_perform_secure_communication_func(
            attacker_id, victim_receiver_id,
            f"来自 {attacker_id} (证书已吊销) 的消息"
        )

        if communication_attempt_succeeded:
            print(f"  👹 攻击可能成功！车辆 {attacker_id} 使用已吊销证书与 {victim_receiver_id} 通信成功了！这是一个严重的防御漏洞。")
        else:
            print(f"  👍 防御可能成功！车辆 {attacker_id} 使用已吊销证书与 {victim_receiver_id} 的通信被阻止了。")
    else:
        print("  无法执行通信尝试，因为未提供 perform_secure_communication 函数。")
    
    print("--- 已吊销证书攻击模拟结束 ---")
