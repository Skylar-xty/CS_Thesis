from sumolib import checkBinary
import traci
import time
import requests
from property import Vehicle

from cryptography.hazmat.primitives import serialization
from attack_one import perform_identity_forgery_attack
import threading
from monitor_new import POIMonitor

sumoBinary = checkBinary('sumo-gui')

EXPERIMENT = 'test1'
RED = [255, 0, 0]
EDGE_ID = 'closed'
all_VEHICLES = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
 '11', '12', '13', '14', '15', '16', '17', '18', '19']
registered_vehicles = []

all_sensor = []
poi_positions = []

VEHICLES = ['1', '4', '8']
# TA_POI_ID = "poi_1"

register_done = False

vehicles = {} # Dictionary to store all vehicle objects
 
recent_messages = {} # 存储每辆车最近发送的通信内容
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
            if "0" in vehicles:
                perform_attack1("0")
            if step % 10 == 0:
                recover_vehicle("0")
                # recover_vehicle("9")
                # perform_attack2("13")
                # perform_identity_forgery_attack(attacker_name="13")
            # if vehicles["1"].isrecovered == 0:
                # recover_vehicle("1")
            
        # secure communication:
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
        print(f"🚗 车辆 {veh_id} 信息: 信任值 {data['trust_score']}, 碰撞次数 {data['collision']}")
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
    recent_messages[sender_id] = {
        "location": sender.position,
        "speed": sender.speed,
        "timestamp": time.time(),
        "message": message,
        "receiver_id": receiver_id
    }
    # 1. 信任值判断
    trust_info = get_vehicle_info(sender_id)
    if not trust_info or trust_info["trust_score"] < 1:
        print(f"🚫 通信中止：车辆 {receiver_id} 信任值不足")
        return
    else:
        print(f"✅ 车辆 {sender_id} 想要与 {receiver_id} 进行安全通信...")

    # 2. 证书获取与验证
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
    print("📡 开始数据交换...")

    # 3. 从证书中提取 ECC 公钥
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    certificate_sender = get_certificate(receiver_id)
    cert = x509.load_pem_x509_certificate(certificate_sender.encode(), default_backend())
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
    if message is None:
        message = f"来自车辆 {sender_id} 的加密数据请求"
    signature = sender.bls_sign(message)
    print(f"车辆 {sender_id} 发出消息：{message}（已签名）")

    # 5. 接收方验证签名
    if not receiver.bls_verify(message, signature, sender.bls_public_key):
        print(f"❌ 车辆 {receiver_id} 验证签名失败，通信中止")
        return
    print(f"✅ 车辆 {receiver_id} 成功验证来自 {sender_id} 的签名")

    # 6. 加密消息并发送
    try:
        ciphertext = sender.encrypt_message(receiver_public_key, message)
        print(f"✅ 车辆 {sender_id} 已使用证书公钥加密消息")

        # 7. 解密 & 校验
        decrypted = receiver.decrypt_message(sender.public_key, ciphertext)
        print(f"🔓 车辆 {receiver_id} 解密内容为：{decrypted}")

        if decrypted == message:
            print(f"✅ 通信成功！消息完整、加密可靠")
        else:
            print(f"❓ 解密消息不一致，完整性可能受损")
            return
    except Exception as e:
        print(f"❌ 通信过程中加密/解密失败: {str(e)}")

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