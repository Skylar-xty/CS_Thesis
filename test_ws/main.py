from sumolib import checkBinary
import traci
import time
import requests
from property import Vehicle
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
# 确保 attack_one.py 中有这些函数，并且它们与这里的调用签名一致
from attack_one import (
    perform_identity_forgery_attack,
    captured_for_replay, # 这是列表，应该从 attack_one.py 导入
    capture_for_replay,
    perform_replay_attack_detailed,
    perform_revoked_certificate_attack
)
import threading
from monitor_new import POIMonitor, LYING_SPEED_DIFF_THRESHOLD, LYING_LOC_DIFF_THRESHOLD
import argparse # 新增
import json     # 新增

sumoBinary = checkBinary('sumo-gui')

EXPERIMENT = 'test1'
RED = [255, 0, 0]
EDGE_ID = 'closed'
all_VEHICLES = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
                '11', '12', '13', '14', '15', '16', '17', '18', '19']

all_sensor = []
poi_positions = []

# 全局状态变量 (将在每次运行main_entry时重置)
vehicles = {}
registered_vehicles = []
recent_messages = {}

register_done = False # 将在 run_simulation_with_scenario 中管理

# --- 测试场景定义 ---
class TestScenario:
    NONE = "none"
    IDENTITY_FORGERY = "identity_forgery"
    REPLAY_ATTACK = "replay_attack"
    ABNORMAL_BEHAVIOR = "abnormal_behavior"
    REVOKED_CERTIFICATE = "revoked_certificate" # 新增场景
    LYING_ATTACK = "lying_attack"

# --- 全局配置 (可根据需要调整) ---
# 用于在 perform_secure_communication 中决定是否激活捕获逻辑的车辆ID
# 如果此车辆在 vehicles 字典中，则成功的通信会被捕获
attacker_vehicle_id_for_capture_logic = "13"
# 或者使用一个布尔标志
enable_global_packet_capture = True # 设置为True以捕获所有成功的安全通信，无论特定车辆是否存在

# 特定攻击场景的车辆ID (确保这些车辆会出现在仿真中并注册)
identity_forgery_attacker = "3"  # 假设车辆3存在并会注册
abnormal_behavior_vehicle = "0" # 假设车辆0存在并会注册
replay_attack_sender = "0"
replay_attack_receiver = "1"
revoked_cert_attacker_id = "2" # 选择一个车辆进行证书吊销攻击
revoked_cert_victim_id = "4"   # 该车辆的通信对象

lying_attacker_id = "5"
target_receiver_for_lying_attack = "1"

# 谎报攻击计数器
lying_attack_transmission_count = 0
MAX_LYING_TRANSMISSIONS = 3

# 💡 后台监测线程逻辑
def monitor_thread_fn(monitor):
    while shouldContinueSim(): # 使用 shouldContinueSim 检查 traci 状态
        try:
            if vehicles and recent_messages: # 确保有数据可监控
                 monitor.scan_all(vehicles, recent_messages)
        except Exception as e:
            print(f"[MONITOR_THREAD_ERROR] {e}")
            break # 发生错误时退出线程以避免无限循环打印错误
        time.sleep(0.1) # 稍微增加间隔，减少CPU占用

def startSim(route_file_name=f'./config/{EXPERIMENT}/modified_routes2_newlong.rou.xml'): # 允许指定路由文件
    """Starts the simulation."""
    traci.start(
        [
            sumoBinary,
            '--net-file', f'./config/{EXPERIMENT}/net.net.xml',
            '--route-files', route_file_name,
            '--delay', '200',
            '--gui-settings-file', './config/viewSettings.xml',
            '--additional-files', f'./config/{EXPERIMENT}/poi.add.xml',
            '--log', "sumo_log.txt",
            '--start'
        ])

def shouldContinueSim():
    """Checks that the simulation should continue running."""
    try:
        return traci.simulation.getMinExpectedNumber() > 0
    except traci.exceptions.TraCIException: # TraCIException 通常意味着SUMO已关闭
        return False


def register_vehicle(veh_id_to_register): # 重命名参数以避免与全局变量冲突
    """向 TA 服务器注册车辆"""
    url = "http://localhost:5000/register_vehicle"
    if veh_id_to_register not in vehicles:
        print(f"❌ 车辆 {veh_id_to_register} 未在本地车辆字典中初始化，无法注册！")
        return False # 返回布尔值表示成功与否
    
    current_vehicle = vehicles[veh_id_to_register]
    ecc_public_key_pem = current_vehicle.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    data = {
        "veh_id": veh_id_to_register,
        "ecc_public_key": ecc_public_key_pem,
        "bls_public_key": bytes(current_vehicle.bls_public_key).hex()
    }
    try:
        response = requests.post(url, json=data, timeout=5) # 添加超时
        if response.status_code == 200:
            print(f"✅ 车辆 {veh_id_to_register} 注册成功。")
            if veh_id_to_register not in registered_vehicles: # 避免重复添加
                registered_vehicles.append(veh_id_to_register)
            return True
        else:
            print(f"❌ 车辆 {veh_id_to_register} 注册失败: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ 注册车辆 {veh_id_to_register} 时发生网络错误: {e}")
        return False


def get_vehicle_info(veh_id_query):
    """ 🔍 查询目标车辆的信任值 """
    url = f"http://localhost:5000/get_vehicle_info?veh_id={veh_id_query}"
    try:
        response = requests.get(url, timeout=3) # 短一点的超时
        if response.status_code == 200:
            data = response.json()
            # print(f"🚗 车辆 {veh_id_query} 信息: 信任值 {data.get('trust_score','N/A')}") # 使用 .get 避免 KeyError
            return data
        else:
            # print(f"❌ 车辆 {veh_id_query} 信息查询失败 (状态码: {response.status_code})")
            return None
    except requests.exceptions.RequestException as e:
        print(f"❌ 查询车辆 {veh_id_query} 信息时发生网络错误: {e}")
        return None


def get_certificate(veh_id_query):
    """ 查询目标车辆的证书 """
    url = f"http://localhost:5000/get_vehicle_certificate?veh_id={veh_id_query}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            # print(f"📜 成功获取车辆 {veh_id_query} 的证书。")
            return data.get("certificate") # 使用 .get
        else:
            # print(f"❌ 车辆 {veh_id_query} 证书查询失败 (状态码: {response.status_code})")
            return None
    except requests.exceptions.RequestException as e:
        print(f"❌ 查询车辆 {veh_id_query} 证书时发生网络错误: {e}")
        return None

def verify_certificate(certificate_pem, veh_id_being_verified=None): # 参数名更清晰
    """ 🚗 向 TA 服务器发送证书验证请求 """
    url = "http://localhost:5000/verify_certificate"
    data = {"certificate": certificate_pem}
    if veh_id_being_verified:
        data["veh_id"] = veh_id_being_verified # TA可能用这个ID来做额外的交叉检查
    try:
        response = requests.post(url, json=data, timeout=3)
        if response.status_code == 200:
            # print(f"✅ 证书 (关联车辆: {veh_id_being_verified or '未知'}) 验证成功。")
            return True
        else:
            print(f"❌ 证书 (关联车辆: {veh_id_being_verified or '未知'}) 验证失败: {response.status_code} - {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ 验证证书时发生网络错误: {e}")
        return False


def perform_secure_communication(sender_id, receiver_id, message_payload=None, capture_this_comm=False,current_scenario_for_attack=None, lying_attacker_id_for_attack=None):
    global attacker_vehicle_id_for_capture_logic, enable_global_packet_capture # 引用全局变量
    global lying_attack_transmission_count, MAX_LYING_TRANSMISSIONS # 引用全局计数器
    if sender_id not in vehicles or receiver_id not in vehicles:
        print(f"🚨 通信失败：车辆 {sender_id} 或 {receiver_id} 未在本地车辆字典中初始化。")
        return False
    if sender_id not in registered_vehicles or receiver_id not in registered_vehicles:
        print(f"🚨 通信失败：车辆 {sender_id} 或 {receiver_id} 未向TA注册。")
        return False

    sender = vehicles[sender_id]
    receiver = vehicles[receiver_id]

    actual_message_content = message_payload if message_payload is not None else f"来自车辆 {sender_id} 的数据请求@{int(time.time())}"
    # actual_message_content = f"场景六：正常通信与信任管理测试，来自车辆{sender_id}"
    # --- 谎报攻击逻辑 ---
    if current_scenario_for_attack == TestScenario.LYING_ATTACK and sender_id == lying_attacker_id_for_attack:
        if lying_attack_transmission_count < MAX_LYING_TRANSMISSIONS:
            if sender_id in vehicles and sender.is_in_network(traci): # 确保攻击者车辆在网
                actual_pos = traci.vehicle.getPosition(sender_id) # 使用traci获取最新实际位置
                actual_speed = traci.vehicle.getSpeed(sender_id)   # 使用traci获取最新实际速度

                # 伪造数据 (示例：基于实际值增加/减少一个较大量)
                # LYING_SPEED_DIFF_THRESHOLD = 5.0 (from monitor_new.py)
                # LYING_LOC_DIFF_THRESHOLD = 10.0 (from monitor_new.py)
                
                fake_pos_x = actual_pos[0] + (LYING_LOC_DIFF_THRESHOLD + 5) # 谎报 X 坐标 (超过阈值)
                fake_pos_y = actual_pos[1] - (LYING_LOC_DIFF_THRESHOLD + 5) # 谎报 Y 坐标
                fake_speed = actual_speed + (LYING_SPEED_DIFF_THRESHOLD + 5)  # 谎报速度 (超过阈值)

                message_payload_dict = {
                    "original_message": f"来自车辆 {sender_id} 的(欺骗性)数据请求@{int(time.time())}",
                    "claimed_location": (fake_pos_x, fake_pos_y), # monitor_new.py 将解析这个
                    "claimed_speed": fake_speed                  # monitor_new.py 将解析这个
                }
                actual_message_content = json.dumps(message_payload_dict, ensure_ascii=False) # 转换为JSON字符串
                print(f"😈 [Lying Attack #{lying_attack_transmission_count + 1}/{MAX_LYING_TRANSMISSIONS}] 车辆 {sender_id} 正在向 {receiver_id} 发送谎报数据:")               
                print(f"  伪造位置: ({fake_pos_x:.2f}, {fake_pos_y:.2f}), 伪造速度: {fake_speed:.2f} m/s")
                print(f"  (实际位置: ({actual_pos[0]:.2f}, {actual_pos[1]:.2f}), 实际速度: {actual_speed:.2f} m/s)")
                lying_attack_transmission_count += 1
            else:
                # 如果攻击者不在网络中，则退回到正常消息，或直接失败
                print(f"⚠️ [Lying Attack] 攻击者 {sender_id} 不在网络中，无法发送谎报数据。发送常规消息。")
                actual_message_content = message_payload if message_payload is not None else f"来自车辆 {sender_id} 的数据请求@{int(time.time())}"
        else: # 已达到最大谎报次数
            print(f"ℹ️ [Lying Attack] 车辆 {sender_id} 已达到最大谎报次数 ({MAX_LYING_TRANSMISSIONS})。此次发送常规/真实消息。")
            # 此处可以构造一个真实的JSON消息结构，如果monitor期望所有消息都是JSON
            # 为简单起见，我们发送一个通用字符串，monitor_new.py的JSON解析会优雅处理非JSON
            actual_message_content = f"来自车辆 {sender_id} 的常规数据请求 (已完成谎报)@{int(time.time())}"

    else:
        # actual_message_content = message_payload if message_payload is not None else f"来自车辆 {sender_id} 的数据请求@{int(time.time())}"
        actual_message_content = f"场景六：正常通信与信任管理测试，来自车辆{sender_id}"

    # --- 谎报攻击逻辑结束 ---

    # 更新 recent_messages 供监控器使用
    if hasattr(sender, 'position') and hasattr(sender, 'speed'): # 确保属性存在
        recent_messages[sender_id] = {
            "location": sender.position, "speed": sender.speed, "timestamp": time.time(),
            "message": actual_message_content, "receiver_id": receiver_id
        }

    # 1. 接收方基于发送方信任度判断
    sender_trust_info = get_vehicle_info(sender_id)
    # 确保 receiver.trust_threshold 存在且有效
    receiver_trust_threshold_val = receiver.trust_threshold # 默认0.3
    if not sender_trust_info or sender_trust_info.get("trust_score", -1) < receiver_trust_threshold_val:
        print(f"🚫 {receiver_id} 拒绝来自 {sender_id} (TS: {sender_trust_info.get('trust_score', 'N/A') if sender_trust_info else '未知'}) 的通信：发送方信任值低于阈值 {receiver_trust_threshold_val:.2f}")
        return False
    # print(f"✅ {sender_id} (TS: {sender_trust_info['trust_score']:.2f}) 与 {receiver_id} (接收方信任阈值: {receiver_trust_threshold_val:.2f}) 开始安全通信...")

    # 2. 接收方验证发送方的证书
    if not receiver.has_verified_certificate(sender_id):
        sender_cert_pem = get_certificate(sender_id)
        if not sender_cert_pem:
            print(f"🚫 通信中止 ({receiver_id} -> {sender_id}): 无法获取发送方 {sender_id} 的证书。")
            return False
        if not verify_certificate(sender_cert_pem, sender_id):
            print(f"🚫 通信中止 ({receiver_id} -> {sender_id}): 发送方 {sender_id} 的证书无效。")
            return False
        receiver.set_verified_certificate(sender_id, True)
        # print(f"📜 {receiver_id} 成功验证了 {sender_id} 的证书。")

    # 3. 发送方获取接收方的证书以提取公钥
    receiver_cert_pem = get_certificate(receiver_id)
    if not receiver_cert_pem:
        print(f"🚫 通信中止 ({sender_id} -> {receiver_id}): 无法获取接收方 {receiver_id} 的证书以进行加密。")
        return False
    try:
        receiver_cert_obj = x509.load_pem_x509_certificate(receiver_cert_pem.encode(), default_backend())
        receiver_ecc_public_key = receiver_cert_obj.public_key()
    except Exception as e:
        print(f"🚫 通信中止 ({sender_id} -> {receiver_id}): 解析接收方 {receiver_id} 证书或提取公钥失败: {e}")
        return False
    
    # 公钥健全性检查
    if not (receiver.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo) ==
            receiver_ecc_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)):
        print(f"🚨 严重警告：接收者 {receiver_id} 本地公钥与其证书中的公钥不匹配！通信中止。（请检查bug）")
        return False

    # 4. 准备Nonce, 消息签名 (发送方操作)
    message_nonce = str(uuid.uuid4())
    signature = sender.bls_sign(actual_message_content, message_nonce) # message_payload 是原始消息
    print(f"车辆 {sender_id} 发出消息: '{actual_message_content[:30]}...' (Nonce: {message_nonce.split('-')[0]}...), 已签名")

    # === 接收方操作 ===
    # 5. 检查Nonce是否重放
    if receiver.is_nonce_replayed(sender_id, message_nonce):
        print(f"🚫 REPLAY DETECTED by {receiver_id}! Nonce: {message_nonce.split('-')[0]}... from {sender_id} 已被处理过。通信中止。")
        return False
    # print(f"✅ {receiver_id} 收到来自 {sender_id} 的新 Nonce: {message_nonce.split('-')[0]}...")

    # 6. 验证BLS签名
    if not receiver.bls_verify(actual_message_content, message_nonce, signature, sender.bls_public_key):
        print(f"❌ {receiver_id} 验证来自 {sender_id} 的签名失败 (消息+Nonce)。通信中止。")
        return False
    # print(f"✅ {receiver_id} 成功验证来自 {sender_id} 的签名 (消息+Nonce)。")

    # 7. 加密和解密
    try:
        ciphertext = sender.encrypt_message(receiver_ecc_public_key, actual_message_content)
        decrypted_message = receiver.decrypt_message(sender.public_key, ciphertext)

        if decrypted_message == actual_message_content:
            print(f"✅ 安全通信成功: '{actual_message_content[:30]}...' (来自 {sender_id} to {receiver_id})")
            
            # --- 为重放攻击演示捕获数据 ---
            should_capture_this_time = False
            if enable_global_packet_capture: # 如果全局捕获开启
                should_capture_this_time = True
            elif attacker_vehicle_id_for_capture_logic in vehicles: # 或者特定车辆在场时捕获
                should_capture_this_time = True
            
            if capture_this_comm or should_capture_this_time: # 也允许函数调用时强制捕获
                print(f" [数据捕获] 正在从 {sender_id} 发往 {receiver_id} 的通信中捕获数据包 (Nonce: {message_nonce.split('-')[0]}...)")
                capture_for_replay(
                    sender_id, receiver_id, actual_message_content, message_nonce,
                    signature, ciphertext,
                    sender.bls_public_key, sender.public_key
                )
            return True
        else:
            print(f"❓ 解密后的消息与原始消息不匹配。完整性可能受损。")
            return False
    except Exception as e:
        print(f"❌ 在安全通信过程中的加密/解密环节失败 ({sender_id} to {receiver_id}): {e}")
        return False
    return False


def perform_simulated_abnormal_behavior(veh_id_attacker, current_step): # 重命名参数
    """模拟车辆的异常驾驶行为，由监控器检测"""
    if veh_id_attacker not in vehicles or veh_id_attacker not in traci.vehicle.getIDList():
        return

    global poi_positions # 确保可以访问全局的poi_positions
    if not poi_positions:
        # print(f"[异常行为模拟] Step {current_step}: 无POI信息，无法执行基于POI的异常行为。")
        return

    target_poi_pos = poi_positions[0] # 假设攻击第一个POI
    try:
        veh_pos = traci.vehicle.getPosition(veh_id_attacker)
        distance_to_poi = ((veh_pos[0] - target_poi_pos[0])**2 + (veh_pos[1] - target_poi_pos[1])**2)**0.5

        if distance_to_poi < 30: # 30米范围内触发
            print(f"📢 [异常行为] 车辆 {veh_id_attacker} 接近POI，执行超速和闯红灯 (Step: {current_step})。")
            traci.vehicle.setSpeedMode(veh_id_attacker, 0)
            traci.vehicle.setSpeed(veh_id_attacker, 25) # 超速
            traci.vehicle.setColor(veh_id_attacker, (255, 0, 0, 255))
            # POIMonitor 会在其扫描周期内检测
    except traci.exceptions.TraCIException as e:
        print(f"❌ 设置车辆 {veh_id_attacker} 异常行为失败 (Step: {current_step}): {e}")


def recover_abnormal_behavior(veh_id_to_recover): # 重命名参数
    if veh_id_to_recover in vehicles and veh_id_to_recover in traci.vehicle.getIDList():
        try:
            # 仅当车辆远离POI一段距离后才恢复，避免在POI附近立即恢复然后又触发
            global poi_positions
            if not poi_positions:
                # print(f"[行为恢复] 车辆 {veh_id_to_recover}: 无POI信息，直接尝试恢复。")
                pass # 继续执行恢复
            else:
                target_poi_pos = poi_positions[0]
                veh_pos = traci.vehicle.getPosition(veh_id_to_recover)
                distance_to_poi = ((veh_pos[0] - target_poi_pos[0])**2 + (veh_pos[1] - target_poi_pos[1])**2)**0.5
                # if distance_to_poi < 40: # 如果还在POI附近，则不恢复
                #     # print(f"[行为恢复] 车辆 {veh_id_to_recover} 仍在POI附近 ({distance_to_poi:.1f}m)，暂不恢复。")
                #     return
            
            print(f"✅ 车辆 {veh_id_to_recover} 行为已尝试恢复正常。")
            traci.vehicle.setSpeedMode(veh_id_to_recover, 31)
            traci.vehicle.setSpeed(veh_id_to_recover, -1)
            # 恢复颜色可以更复杂，例如基于车辆类型
            original_color = getattr(vehicles[veh_id_to_recover], 'original_color', (0, 255, 0, 255)) # 假设有原始颜色
            traci.vehicle.setColor(veh_id_to_recover, original_color)
            # 如果有 isrecovered 标志，也应更新
            if hasattr(vehicles[veh_id_to_recover], 'isrecovered'):
                vehicles[veh_id_to_recover].isrecovered = True

        except traci.exceptions.TraCIException as e:
            print(f"❌ 恢复车辆 {veh_id_to_recover} 行为失败: {e}")


# --- 新的仿真主循环 ---
def run_simulation_with_scenario(current_scenario):
    step = 0
    global register_done # 允许修改全局变量
    global poi_positions, all_sensor # 确保这些是已初始化的

    # 初始化POI位置
    if not poi_positions:
        for poi_id_init in traci.poi.getIDList():
            if traci.poi.getType(poi_id_init) == "sensor_unit":
                all_sensor.append(poi_id_init)
                x, y = traci.poi.getPosition(poi_id_init)
                poi_positions.append((x,y))
                print(f"📢 (run_simulation) sensor {poi_id_init} inited at ({x:.2f},{y:.2f})")
                if all_sensor: break # 暂时只需要一个主要的POI用于测试

    monitor = POIMonitor(poi_positions)
    monitor_thread = threading.Thread(target=monitor_thread_fn, args=(monitor,), daemon=True)
    monitor_thread.start()
    print("[INFO] 监控线程已启动。")

    # 仿真阶段控制
    REGISTRATION_PHASE_DURATION_STEPS = 30
    NORMAL_COMM_PHASE_DURATION_STEPS = 40 # 为捕获数据留出更多时间
    ATTACK_PHASE_START_OFFSET = 5        # 正常通信结束后多少步开始攻击
    # 为TestScenario.NONE场景定义通信车辆对和频率
    NONE_SCENARIO_COMM_INTERVAL = 10 # 每10步通信一次
    # 可以定义多对车辆进行测试
    none_scenario_comm_pairs = [("0", "1"), ("2", "3")] # 示例车辆对

    print(f"[INFO] 仿真开始。注册阶段将持续约 {REGISTRATION_PHASE_DURATION_STEPS} 步。")

    while shouldContinueSim():
        current_active_vehicles = traci.vehicle.getIDList()

        # --- 阶段 1: 车辆初始化和注册 ---
        if not register_done:
            newly_departed_ids = traci.simulation.getDepartedIDList()
            for veh_id in newly_departed_ids:
                if veh_id not in vehicles:
                    vehicles[veh_id] = Vehicle(veh_id, 'passenger', 33.33, 4.5, 2.0, 1.0, 150)
                    print(f"🚗 新车辆 {veh_id} 已初始化 (Step: {step})。")
                
                if veh_id not in registered_vehicles:
                    # print(f"  车辆 {veh_id} 尝试注册...") 
                    if not register_vehicle(veh_id): # 如果注册失败，可以记录或重试
                        print(f"⚠️ 车辆 {veh_id} 注册失败，将在后续步骤中重试或忽略。")
            
            if step >= REGISTRATION_PHASE_DURATION_STEPS or \
               (len(all_VEHICLES) > 0 and len(registered_vehicles) >= len(all_VEHICLES) // 2 and len(registered_vehicles) > 0) : # 注册一半以上或达到步数
                print(f"🚩 注册阶段结束 (Step: {step})。已注册车辆: {len(registered_vehicles)} / {len(vehicles)} (在场景中)。")
                register_done = True
                if not registered_vehicles: print("警告：没有车辆成功注册！后续测试可能失败。")

        # --- 阶段 2: 正常通信 / 攻击执行 ---
        else: # register_done is True
            if current_scenario == TestScenario.NONE:
                # 场景NONE: 专注于执行和测试 perform_secure_communication
                if step % NONE_SCENARIO_COMM_INTERVAL == 0:
                    for sender_id, receiver_id in none_scenario_comm_pairs:
                        if sender_id in registered_vehicles and receiver_id in registered_vehicles:
                            # 确保车辆仍在仿真中
                            if sender_id in current_active_vehicles and receiver_id in current_active_vehicles:
                                print(f"\n[SCENARIO_NONE - 通信测试] Step {step}: 触发 '{sender_id}' 与 '{receiver_id}' 安全通信")
                                perform_secure_communication(
                                    sender_id, receiver_id,
                                    f"SCENARIO_NONE Test Message @ Step {step} from {sender_id} to {receiver_id}",
                                    capture_this_comm=False # 在NONE场景下通常不需要捕获
                                )
                        # else:
                            # print(f"[SCENARIO_NONE - 通信测试] Step {step}: 车辆对 ({sender_id}, {receiver_id}) 中有车辆未注册或不存在，跳过通信。")
            
            else: # 其他攻击场景
                # A. 正常通信阶段 (为重放攻击捕获数据)
                # 此阶段在注册完成后，攻击开始前运行
                normal_comm_start_step = REGISTRATION_PHASE_DURATION_STEPS + 1
                normal_comm_end_step = normal_comm_start_step + NORMAL_COMM_PHASE_DURATION_STEPS
                
                if normal_comm_start_step <= step < normal_comm_end_step:
                    if step % 7 == 0: # 通信频率
                        if replay_attack_sender in registered_vehicles and replay_attack_receiver in registered_vehicles:
                            print(f"\n[正常通信阶段] Step {step}: 触发 {replay_attack_sender} 和 {replay_attack_receiver} 之间通信 (用于捕获)")
                            perform_secure_communication(
                                replay_attack_sender, replay_attack_receiver,
                                f"捕获消息 {step} from {replay_attack_sender} to {replay_attack_receiver}",
                                capture_this_comm=True # 显式要求捕获
                            )
                
                # B. 攻击执行阶段
                attack_trigger_step = normal_comm_end_step + ATTACK_PHASE_START_OFFSET

                # 根据命令行选择的场景执行特定攻击
                if current_scenario == TestScenario.IDENTITY_FORGERY:
                    if step == attack_trigger_step:
                        print(f"\n--- 测试场景: {TestScenario.IDENTITY_FORGERY} (Step: {step}) ---")
                        if identity_forgery_attacker in registered_vehicles:
                            perform_identity_forgery_attack(attacker_name=identity_forgery_attacker)
                        else:
                            print(f"  无法执行身份伪造：攻击者 {identity_forgery_attacker} 未注册或不存在。")
                
                elif current_scenario == TestScenario.REPLAY_ATTACK:
                    if step == attack_trigger_step:
                        print(f"\n--- 测试场景: {TestScenario.REPLAY_ATTACK} (第一次尝试) (Step: {step}) ---")
                        if len(captured_for_replay) > 0:
                            perform_replay_attack_detailed(vehicles, specific_packet_index=0, clear_receiver_nonce_cache=True)
                        else:
                            print("  尚无捕获的数据包可供重放 (第一次尝试)。")
                    
                    if step == attack_trigger_step + 10: # 给第一次重放一些时间，然后再次尝试
                        print(f"\n--- 测试场景: {TestScenario.REPLAY_ATTACK} (第二次尝试相同Nonce) (Step: {step}) ---")
                        if len(captured_for_replay) > 0:
                            attack_defended = perform_replay_attack_detailed(vehicles, specific_packet_index=0, clear_receiver_nonce_cache=False)
                            if attack_defended: print("  ✅ 对数据包0的重放攻击在第二次尝试时被成功防御。")
                            else: print("  ❌ 对数据包0的重放攻击在第二次尝试时未被防御！检查Nonce逻辑。")
                        else:
                            print("  尚无捕获的数据包可供重放 (第二次尝试)。")

                elif current_scenario == TestScenario.ABNORMAL_BEHAVIOR:
                    abnormal_behavior_duration = 30 # 异常行为持续步数
                    if attack_trigger_step <= step < (attack_trigger_step + abnormal_behavior_duration):
                        if abnormal_behavior_vehicle in current_active_vehicles:
                            if step % 3 == 0: # 控制异常行为的频率
                                # print(f"[INFO] Step {step}: 尝试触发车辆 {abnormal_behavior_vehicle} 的异常行为。")
                                perform_simulated_abnormal_behavior(abnormal_behavior_vehicle, step)
                    elif step == (attack_trigger_step + abnormal_behavior_duration):
                        if abnormal_behavior_vehicle in current_active_vehicles:
                            print(f"--- 测试场景: {TestScenario.ABNORMAL_BEHAVIOR} (尝试恢复行为 @ Step {step}) ---")
                            recover_abnormal_behavior(abnormal_behavior_vehicle)
                elif current_scenario == TestScenario.REVOKED_CERTIFICATE:
                    if step == attack_trigger_step:
                        print(f"\n--- 测试场景: {TestScenario.REVOKED_CERTIFICATE} (Step: {step}) ---")
                        if revoked_cert_attacker_id in registered_vehicles and revoked_cert_victim_id in registered_vehicles:
                            perform_revoked_certificate_attack(
                                attacker_id=revoked_cert_attacker_id,
                                victim_receiver_id=revoked_cert_victim_id,
                                vehicles_map=vehicles,
                                main_perform_secure_communication_func=perform_secure_communication,
                                main_get_certificate_func=get_certificate, # 传递辅助函数
                                main_verify_certificate_func=verify_certificate # 传递辅助函数
                            )
                        else:
                            print(f"  无法执行吊销证书攻击：车辆 {revoked_cert_attacker_id} 或 {revoked_cert_victim_id} 未注册或不存在。")
                elif current_scenario == TestScenario.LYING_ATTACK:
                    # if step == attack_trigger_step: 
                    if step % 20 == 0:
                        print(f"\n--- 测试场景: {TestScenario.LYING_ATTACK} (Step: {step}) ---")
                        if lying_attacker_id in registered_vehicles and target_receiver_for_lying_attack in registered_vehicles:
                            print(f"  车辆 {lying_attacker_id} 将尝试对 {target_receiver_for_lying_attack} 发送谎报信息。")
                            perform_secure_communication(
                                lying_attacker_id,
                                target_receiver_for_lying_attack,
                                message_payload=None, # Payload will be overridden by lying logic
                                capture_this_comm=True, 
                                current_scenario_for_attack=current_scenario, 
                                lying_attacker_id_for_attack=lying_attacker_id 
                            )
                        else:
                            print(f"  无法执行谎报攻击：攻击者 {lying_attacker_id} 或目标接收者 {target_receiver_for_lying_attack} 未注册/不存在。")


        # 更新所有在网车辆的动态属性（在每个阶段的末尾，或只在非注册阶段的开始）
        # 为了简化，我们可以在每个step的末尾统一更新一次（在 register_done 变为 True 后）
        if register_done :
            active_vehicle_ids_for_update = traci.vehicle.getIDList() # 重新获取当前在网车辆
            for veh_id_update in active_vehicle_ids_for_update:
                if veh_id_update in vehicles:
                    vehicles[veh_id_update].update_dynamic_attributes(traci)
                    vehicles[veh_id_update].upload_trust_to_ta()


        step += 1
        try:
            traci.simulationStep()
        except traci.exceptions.TraCIException as e:
            print(f"TraCI 错误 (仿真可能已结束): {e}")
            break
    
    print(f"仿真循环结束 (Step: {step})。")
    if monitor_thread.is_alive():
        print("等待监控线程优雅退出...")
        # monitor_thread.join(timeout=2) # 给监控线程一点时间完成当前循环
    traci.close()
    print("SUMO仿真已关闭。")


# --- 新的主入口点 ---
def main_entry():
    parser = argparse.ArgumentParser(description="SUMO 车辆安全通信仿真与攻击测试")

    scenario_choices = [
        TestScenario.NONE,
        TestScenario.IDENTITY_FORGERY,
        TestScenario.REPLAY_ATTACK,
        TestScenario.ABNORMAL_BEHAVIOR,
        TestScenario.REVOKED_CERTIFICATE,
        TestScenario.LYING_ATTACK
    ]

    parser.add_argument(
        "--scenario",
        type=str,
        choices=scenario_choices, # 使用手动创建的列表
        default=TestScenario.NONE,
        help=f"选择要运行的测试场景 (默认: {TestScenario.NONE}). "
             f"可选: {', '.join([sc for sc in scenario_choices if sc != TestScenario.NONE])}."
    )
    args = parser.parse_args()

    print(f"\n🚀 正在启动仿真，选择的测试场景: {args.scenario}")
    
    # 重置全局状态，确保每次运行的独立性
    global vehicles, registered_vehicles, recent_messages, register_done
    # captured_for_replay 列表由 attack_one.py 管理，但我们也应该在这里清空它
    global captured_for_replay 
    
    vehicles.clear()
    registered_vehicles.clear()
    recent_messages.clear()
    
    # 确保 captured_for_replay 是从 attack_one.py 正确导入的列表
    # 并且 attack_one.py 中的 captured_for_replay = [] 是在模块级别定义的
    if 'attack_one' in globals() and hasattr(globals()['attack_one'], 'captured_for_replay') \
       and isinstance(globals()['attack_one'].captured_for_replay, list):
        globals()['attack_one'].captured_for_replay.clear() # 清空 attack_one.py 中的列表
        print("[INFO] 已清空先前捕获的重放数据 (通过 attack_one.captured_for_replay)。")
    elif 'captured_for_replay' in globals() and isinstance(captured_for_replay, list): # 如果是作为全局变量导入
        captured_for_replay.clear()
        print("[INFO] 已清空先前捕获的重放数据 (通过全局导入的 captured_for_replay)。")
    else:
        print("[警告] 无法直接清空 'captured_for_replay'。请确保它在 attack_one.py 中被正确定义和管理，或在此处正确导入。")


    register_done = False
    
    # 初始化POI列表（因为 run_simulation_with_scenario 依赖它）
    global poi_positions, all_sensor
    poi_positions.clear()
    all_sensor.clear()

    try:
        startSim() # 启动SUMO
        run_simulation_with_scenario(args.scenario) # 运行带场景的仿真逻辑
    except Exception as e:
        print(f"[FATAL_ERROR] 仿真过程中发生未捕获的异常: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 确保在任何情况下都尝试关闭 TraCI 连接
        # isEmbedded() 检查 TraCI 是否已加载。如果 SUMO 提前崩溃，直接调用 close() 可能出错。
        closed_traci = False
        try:
            if traci.isEmbedded(): # 检查TraCI是否仍在运行/连接
                traci.close()
                closed_traci = True
                print("SUMO连接已在finally块中关闭。")
        except traci.exceptions.TraCIException as te: # SUMO可能已经关闭
             print(f"尝试关闭SUMO连接时出错 (可能已关闭): {te}")
        except NameError: # traci 可能未成功导入或初始化
            pass 
        except Exception as e_final: # 其他可能的关闭错误
            print(f"关闭SUMO时发生未知错误: {e_final}")
        
        if not closed_traci:
            print("SUMO连接可能未正常关闭或从未建立。")
            
        print("脚本执行完毕。")


if __name__ == "__main__":
    main_entry()
