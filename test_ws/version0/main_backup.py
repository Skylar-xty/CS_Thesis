from sumolib import checkBinary
import traci
import time
import requests
from property import Vehicle
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from attack_one import perform_identity_forgery_attack, captured_for_replay, capture_for_replay,perform_replay_attack_detailed
import threading
from monitor_new import POIMonitor
import argparse
import json

sumoBinary = checkBinary('sumo-gui')

EXPERIMENT = 'test1'
RED = [255, 0, 0]
EDGE_ID = 'closed'
all_VEHICLES = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
 '11', '12', '13', '14', '15', '16', '17', '18', '19']

all_sensor = []
poi_positions = []

VEHICLES = ['1', '4', '8']
# TA_POI_ID = "poi_1"

register_done = False

vehicles = {} # Dictionary to store all vehicle objects
registered_vehicles = []
recent_messages = {} # 存储每辆车最近发送的通信内容
attacker_veh_id_for_capture_logic = "13"

# 💡 后台监测线程逻辑
def monitor_thread_fn(monitor):
    while shouldContinueSim():
        monitor.scan_all(vehicles, recent_messages)
        time.sleep(0.1)

def main():
    step = 0
    global register_done,all_VEHICLES,registered_vehicles,all_sensor,vehicles
    startSim()
    # 获取当前视图（即整个网络）的边界框：((x_min, y_min), (x_max, y_max))
    boundary = traci.gui.getBoundary("View #0")  # 默认视图 ID 为 "View #0"
    print(f"📏 地图边界范围: {boundary}")

    # RSU init
    for poi_id in traci.poi.getIDList():
        if traci.poi.getType(poi_id) == "sensor_unit":
            all_sensor.append(poi_id)
            x, y = traci.poi.getPosition(poi_id)
            poi_positions.append((x,y))
            print(f"📢 sensor{poi_id} inited at ({x:.2f},{y:.2f})")
        break
    monitor = POIMonitor(poi_positions)
    # 启动后台线程
    threading.Thread(target=monitor_thread_fn, args=(monitor,), daemon=True).start()

    while shouldContinueSim():
        if not register_done:
            # 每步检查是否有新出发车辆
            new_veh_ids = traci.simulation.getDepartedIDList()
            for veh_id in new_veh_ids:
                if veh_id == "13":
                    traci.vehicle.setColor("13", (255,0,0))
                if veh_id == "13":   # TODO
                    register_done = True
                
                # If the car is never initialized:
                if veh_id not in vehicles:
                    print(f"🚗 新车辆 {veh_id} 出发")
                    vehicles[veh_id] = Vehicle(veh_id, 'passenger', 33.33, 4.5, 2.0, 100, 50)
                # If the car is not registered yet:
                if veh_id not in registered_vehicles:
                    print(f"车辆 {veh_id}，开始注册")
                    register_vehicle(veh_id)
                    registered_vehicles.append(veh_id)
            # 更新并显示车辆动态属性
            for veh in vehicles.values():
                veh.update_dynamic_attributes(traci)
                # veh.display_info() 
                veh.upload_trust_to_ta()
        else:
            # if "0" in vehicles:
            #     perform_attack1("0")
            # if step % 10 == 0:
            #     recover_vehicle("0")
                # perform_attack2("13")
                # perform_identity_forgery_attack(attacker_name="13")
            # if vehicles["1"].isrecovered == 0:
                # recover_vehicle("1")
            
        # secure communication:
            # --- 模拟一些正常的安全通信以便捕获数据 ---
            if step > 0 and step < 50 : # 在 step 50 之前进行一些通信
                # 例如，让车辆 "0" 和 "1" 每隔几步通信一次
                if step % 5 == 0: # 每5步尝试一次
                    if "0" in vehicles and "1" in vehicles and \
                       "0" in registered_vehicles and "1" in registered_vehicles: # 确保它们已注册并存在
                        print(f"\n[模拟主循环] Step {step}: 触发车辆 0 和 1 之间的安全通信 (用于数据捕获)")
                        # 为了让 perform_secure_communication 中的 attacker_vehicle_id_for_capture_logic 生效
                        # 可以直接在 perform_secure_communication 中使用这个全局变量，或者修改其调用方式
                        # 这里假设 perform_secure_communication 可以访问到 main 中定义的 attacker_vehicle_id_for_capture_logic
                        perform_secure_communication("0", "1", f"来自车辆0到1的消息，step {step}")
                    else:
                        if step % 5 == 0: # 避免过多打印
                            print(f"[模拟主循环] Step {step}: 车辆 0 或 1 未准备好进行通信 (可能未注册或不存在)。")

            # --- 重放攻击测试逻辑 ---
            if step == 50:
                print("\n--- 触发重放攻击场景 (针对一个Nonce的第一次尝试) ---")
                if len(captured_for_replay) > 0:
                    perform_replay_attack_detailed(vehicles, specific_packet_index=0, clear_receiver_nonce_cache=True)
                else:
                    print("尚无捕获的数据包可供重放。")

            if step == 55:
                print("\n--- 触发重放攻击场景 (针对同一Nonce的第二次尝试) ---")
                if len(captured_for_replay) > 0:
                    attack_defended = perform_replay_attack_detailed(vehicles, specific_packet_index=0, clear_receiver_nonce_cache=False) # 不再清除缓存
                    if attack_defended:
                        print("对数据包0的重放攻击在第二次尝试时被成功防御。")
                    else:
                        print("对数据包0的重放攻击在第二次尝试时未被防御。检查逻辑。")
                else:
                    print("尚无捕获的数据包可供重放。")
                print("--- 重放攻击场景结束 ---\n")
            # perform_secure_communication("0", "1")    
            step += 1
        traci.simulationStep()
 
    traci.close()
 
 
def startSim():
    """Starts the simulation."""
    traci.start(
        [
            sumoBinary,
            '--net-file', f'./config/{EXPERIMENT}/net.net.xml',
            # '--net-file', './config/network_new.net.xml',
            # '--route-files', './config/trips.trips.xml',
            '--route-files', f'./config/{EXPERIMENT}/modified_routes2_newlong.rou.xml',
            '--delay', '200',
            '--gui-settings-file', './config/viewSettings.xml',
            '--additional-files', f'./config/{EXPERIMENT}/poi.add.xml',
            # '--additional-files', './config/additional.xml',
            '--log', "sumo_log.txt",
            # '--collision.action', 'warn',         # 显示碰撞但不中断仿真
            '--start'
 
        ])
 

def register_vehicle(veh_id):
    """向 TA 服务器注册车辆"""
    """ 🚗 车辆注册到 TA，并获取证书 """
    url = "http://localhost:5000/register_vehicle"

    if veh_id not in vehicles:
        print(f"❌ 车辆 {veh_id} 未初始化，无法注册！")
        return
    ecc_public_key_pem = vehicles[veh_id].public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()  # 转换为字符串
    data = {
        "veh_id": veh_id,
        "ecc_public_key": ecc_public_key_pem,
        "bls_public_key": bytes(vehicles[veh_id].bls_public_key).hex()
    }
    
    response = requests.post(url, json=data)
    if response.status_code == 200:
        print(f"✅ 车辆 {veh_id} 注册成功")
    else:
        print(f"❌ 车辆 {veh_id} 注册失败: {response.json()}")
    # response = requests.post("http://localhost:5000/register_vehicle", json={"veh_id": veh_id})
    # print(response.json())


def get_vehicle_info(veh_id):
    """ 🔍 查询目标车辆的信任值 """
    url = f"http://localhost:5000/get_vehicle_info?veh_id={veh_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        print(f"🚗 车辆 {veh_id} 信息: 信任值 {data['trust_score']}")
        return data
    else:
        print(f"❌ 车辆 {veh_id} 信息查询失败")
        return None

def get_certificate(veh_id):
    """ 查询目标车辆的证书 """
    url = f"http://localhost:5000/get_vehicle_certificate?veh_id={veh_id}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        print(f"🚗 车辆 {veh_id} 的证书信息：\n{data['certificate']}")
        return data["certificate"]
    else:
        print(f"❌ 车辆 {veh_id} 证书查询失败")
        return None

def verify_certificate(certificate, veh_id=None):
    """ 🚗 向 TA 服务器发送证书验证请求 """
    url = "http://localhost:5000/verify_certificate"
    data = {"certificate": certificate}

    if veh_id:
        data["veh_id"] = veh_id
    response = requests.post(url, json=data)
    
    if response.status_code == 200:
        print("✅ 证书验证成功")
        return True
    else:
        print("❌ 证书验证失败:", response.json())
        return False

# Communication: bls+ecc
def perform_secure_communication(sender_id, receiver_id, message=None):
    """发起一次从 sender 到 receiver 的安全通信，包括信任值判断、证书验证、加解密"""
    if sender_id not in vehicles or receiver_id not in vehicles:
        print(f"🚨 通信失败：车辆 {sender_id} 或 {receiver_id} 不存在")
        return

    sender = vehicles[sender_id]
    receiver = vehicles[receiver_id]

    base_message_content = message if message is not None else f"来自车辆 {sender_id} 的数据请求@{int(time.time())}"

    recent_messages[sender_id] = { # 用于监控器
        "location": sender.position, "speed": sender.speed, "timestamp": time.time(),
        "message": base_message_content, "receiver_id": receiver_id
    }
    # 1. 信任值判断
    trust_info_sender = get_vehicle_info(sender_id)
    if not trust_info_sender or trust_info_sender["trust_score"] < receiver.trust_threshold:
        print(f"🚫 {receiver_id} 拒绝来自 {sender_id} (TS: {trust_info_sender.get('trust_score', 'N/A'):.2f}) 的通信：发送方信任值低于阈值 {receiver.trust_threshold}")
        return
    print(f"✅ {sender_id} (TS: {trust_info_sender['trust_score']:.2f}) 与 {receiver_id} (信任阈值: {receiver.trust_threshold}) 开始安全通信...")

    # 2. 接收方验证发送方的证书
    certificate = get_certificate(sender_id)
    # 🆕 第一次通信时查询证书
    if not receiver.has_verified_certificate(sender_id):
        # certificate = get_certificate(sender_id)
        if certificate:
            if verify_certificate(certificate, sender_id):  # sender证书验证
                receiver.set_verified_certificate(sender_id, True)
                print(f"📜 证书验证成功，允许通信！")
            else:
                print(f"🚫 通信中止：车辆 {receiver_id} 的证书无效")
                return
        else:
            print("🚫 通信中止 ({receiver_id} to {sender_id}): 无法获取发送方 {sender_id} 证书。")
    print("📡 开始数据交换...")

    # 3. 从证书中提取 ECC 公钥
    certificate_receiver = get_certificate(receiver_id)
    cert = x509.load_pem_x509_certificate(certificate_receiver.encode(), default_backend())
    receiver_public_key = cert.public_key()
    # print("【receiver 公钥】")
    # print(receiver.public_key.public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # ).decode())

    # print("【证书中的公钥】")
    # print(cert.public_key().public_bytes(
    #     encoding=serialization.Encoding.PEM,
    #     format=serialization.PublicFormat.SubjectPublicKeyInfo
    # ).decode())

    assert receiver.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # receiver_public_key = receiver.public_key
    # 4. 准备消息 & BLS 签名
    message_nonce = str(uuid.uuid4())
    if message is None:
        message = f"来自车辆 {sender_id} 的加密数据请求"
    signature = sender.bls_sign(message, message_nonce)
    print(f"车辆 {sender_id} 发出消息：'{base_message_content}' (Nonce: {message_nonce.split('-')[0]}..., 已签名)")

    # === 传输 (message_content, nonce, signature, 然后是 ciphertext) ===
    # 接收方检查Nonce是否重放
    if receiver.is_nonce_replayed(sender_id, message_nonce):
        print(f"🚫 {receiver_id}检测到重放攻击！来自 {sender_id} 的 Nonce: {message_nonce.split('-')[0]}... 已处理。通信中止。")
        return False
    print(f"✅ {receiver_id} 收到来自 {sender_id} 的新 Nonce: {message_nonce.split('-')[0]}...。")
    
    # 5. 接收方验证BLS签名 (Nonce是已签名数据的一部分)
    if not receiver.bls_verify(message, message_nonce, signature, sender.bls_public_key):
        print(f"❌ {receiver_id} 验证来自 {sender_id} 的签名失败 (消息+Nonce)。通信中止。")
        return
    print(f"✅ {receiver_id} 成功验证来自 {sender_id} 的签名 (消息+Nonce)。")

    # 6. 加密消息并发送
    try:
        ciphertext = sender.encrypt_message(receiver_public_key, message)
        print(f"✅ 车辆 {sender_id} 已使用证书公钥加密消息")

        # 7. 解密 & 校验
        decrypted = receiver.decrypt_message(sender.public_key, ciphertext)
        print(f"🔓 车辆 {receiver_id} 解密内容为：{decrypted}")

        if decrypted == message:
            print(f"✅ 安全通信成功！'{base_message_content}' 完整、加密可靠、未重放。")
            # --- 为重放攻击演示捕获数据 (成功通信后，返回True之前) ---
            # 这有助于攻击者脚本捕获一次有效的交换。
            if '13' in vehicles: # 指定一个攻击者车辆
                capture_for_replay(
                    sender_id, receiver_id, base_message_content, message_nonce,
                    signature, ciphertext,
                    sender.bls_public_key, sender.public_key
                )
            return True
        else:
            print(f"❓ 解密消息不一致，完整性可能受损")
            return
    except Exception as e:
        print(f"❌ 通信过程中加密/解密失败: {str(e)}")
    return False
def perform_attack1(attacker_id):
    # 异常行为 1
    # 🚨 控制车辆13在接近 POI 时执行异常行为（超速 + 闯红灯）
    if attacker_id in traci.vehicle.getIDList():
        x, y = traci.vehicle.getPosition(attacker_id)
        if abs(x - 50.09) < 5 and abs(y - 49.60) < 5:
            try:
                # 禁用所有速度/红灯/安全限制（允许闯红灯）
                traci.vehicle.setSpeedMode(attacker_id, 0b00000)

                # 强制设置为超速（40m/s）
                traci.vehicle.setSpeed(attacker_id, 20)

                # 可视化上色（红色）
                traci.vehicle.setColor(attacker_id, (255, 0, 0))

                print(f"📢 异常车辆 {attacker_id} 接近 POI：执行闯红灯 + 超速！")
                vehicles[attacker_id].isrecoverd = 0
            except Exception as e:
                print("❌ 设置车辆13异常行为失败：", e)

def recover_vehicle(attacker_id):
    """
    恢复车辆行为为正常状态（恢复默认速度限制、颜色等）
    """
    if attacker_id in traci.vehicle.getIDList():
        x, y = traci.vehicle.getPosition(attacker_id)
        if abs(x - 50.09) > 40 and abs(y - 49.60) > 40:
            try:
                # 恢复默认的速度模式（如启用安全性检查）
                traci.vehicle.setSpeedMode(attacker_id, 0b11111)
                
                # 恢复为 SUMO 控制速度（-1 表示由SUMO控制）
                traci.vehicle.setSpeed(attacker_id, -1)

                print(f"✅ 车辆 {attacker_id} 已恢复正常状态")
                vehicles[attacker_id].isrecoverd = 1
            except Exception as e:
                print("❌ 恢复车辆行为失败：", e)

def perform_attack2(attacker_id):
    """🚨 数据篡改攻击：发送伪造数据，但使用原始签名，测试服务端能否检测完整性问题"""
    if attacker_id not in vehicles:
        print(f"❌ 攻击失败：车辆 {attacker_id} 不存在")
        return

    attacker = vehicles[attacker_id]
    # 1. 构造原始合法数据
    original_data = {
        "veh_id": attacker_id,
        "location": "104.95,37.99",
        "speed": 30,
        "event": "normal"
    }
    msg = f"{original_data['veh_id']}-{original_data['location']}-{original_data['speed']}-{original_data['event']}"
    signature = attacker.bls_sign(msg)

    # 2. 构造伪造数据（修改字段，但用原始签名）
    fake_data = {
        "veh_id": attacker_id,
        "location": "105.00,38.00",   # ❌ 伪造位置
        "speed": 180,                 # ❌ 伪造速度
        "event": "emergency_stop",   # ❌ 伪造事件
        # "signature": signature.hex()
    }

    print(f"🚨 车辆 {attacker_id} 正在发送伪造数据: {fake_data}")

    # 3. 发送到服务端攻击入口（你需要在服务端实现 /receive_data）
    try:
        res = requests.post("http://localhost:5000/test_attack", json=fake_data)
        print("📡 服务端响应：", res.json())
    except Exception as e:
        print("❌ 攻击请求失败:", str(e))

def shouldContinueSim():
    """Checks that the simulation should continue running.
    Returns:
        bool: `True` if vehicles exist on network. `False` otherwise.
    """
    numVehicles = traci.simulation.getMinExpectedNumber()
    return True if numVehicles > 0 else False
 
 
def setVehColor(vehId, color):
    """Changes a vehicle's color.
    Args:
        vehId (String): The vehicle to color.
        color ([Int, Int, Int]): The RGB color to apply.
    """
    traci.vehicle.setColor(vehId, color)
 
 
def avoidEdge(vehId, edgeId):
    """Sets an edge's travel time for a vehicle infinitely high, and reroutes the vehicle based on travel time.
    Args:
        vehId (Str): The ID of the vehicle to reroute.
        edgeId (Str): The ID of the edge to avoid.
    """
    traci.vehicle.setAdaptedTraveltime(
        vehId, edgeId, float('inf'))
    traci.vehicle.rerouteTraveltime(vehId)
 
 
def getOurDeparted(filterIds=[]):
    """Returns a set of filtered vehicle IDs that departed onto the network during this simulation step.
    Args:
        filterIds ([String]): The set of vehicle IDs to filter for.
    Returns:
        [String]: A set of vehicle IDs.
    """
    newlyDepartedIds = traci.simulation.getDepartedIDList()
    filteredDepartedIds = newlyDepartedIds if len(
        filterIds) == 0 else set(newlyDepartedIds).intersection(filterIds)
    return filteredDepartedIds
 
 
if __name__ == "__main__":
    main()