
from sumolib import checkBinary
import traci
import time
import requests
from property import Vehicle

from cryptography.hazmat.primitives import serialization
from task import TASKS
import threading
from monitor_multi import POIMonitorMulti
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

register_done = False

vehicles = {} # Dictionary to store all vehicle objects

# 💡 后台监测线程逻辑
def monitor_thread_fn(monitor):
    while shouldContinueSim():
        monitor.scan_all(vehicles)
        time.sleep(0.1)

def main():
    global register_done,all_VEHICLES,registered_vehicles,all_sensor,vehicles
    startSim()

    # RSU init
    for poi_id in traci.poi.getIDList():
        if traci.poi.getType(poi_id) == "sensor_unit":
            all_sensor.append(poi_id)
            x, y = traci.poi.getPosition(poi_id)
            poi_positions.append((x,y))
            print(f"sensor{poi_id} inited at ({x:.2f},{y:.2f})")

    # 初始化 POI 多点监测器
    monitor = POIMonitorMulti(poi_positions)

    # 启动后台线程
    threading.Thread(target=monitor_thread_fn, args=(monitor,), daemon=True).start()

    while shouldContinueSim():
        if not register_done:
            new_veh_ids = traci.simulation.getDepartedIDList()
            for veh_id in new_veh_ids:
                if veh_id == "19":
                    register_done = True
                if veh_id not in registered_vehicles:
                    print(f"🚗 新车辆 {veh_id} 出发，开始注册")
                    vehicles[veh_id] = Vehicle(veh_id, 'passenger', 33.33, 4.5, 2.0, 100, 50)
                    register_vehicle(veh_id)
                    registered_vehicles.append(veh_id)

            for veh in vehicles.values():
                veh.update_dynamic_attributes(traci)
                veh.display_info() 
                veh.upload_trust_to_ta()
        else:
            veh_id = "0"
            veh = vehicles[veh_id]
            target_veh_id = "1"
            trust_info = get_vehicle_info(target_veh_id)

            if trust_info and trust_info["trust_score"] >=0:
                print(f"✅ 车辆 {veh_id} 想要与 {target_veh_id} 进行安全通信...")

                if not veh.has_verified_certificate(target_veh_id):
                    certificate = get_certificate(target_veh_id)
                    if certificate:
                        if verify_certificate(certificate):
                            veh.set_verified_certificate(target_veh_id, True)
                            print(f"📜 证书验证成功，允许通信！")
                        else:
                            print(f"❌ 证书验证失败，终止通信！")
                            continue
                print("📡 开始数据交换...")
            else:
                print(f"❌ 车辆 {target_veh_id} 信任值过低，拒绝通信")    
        traci.simulationStep()

    traci.close()

def startSim():
    traci.start(
        [
            sumoBinary,
            '--net-file', f'./config/{EXPERIMENT}/net.net.xml',
            '--route-files', f'./config/{EXPERIMENT}/modified_routes2.rou.xml',
            '--delay', '200',
            '--gui-settings-file', './config/viewSettings.xml',
            '--additional-files', f'./config/{EXPERIMENT}/poi.add.xml',
            '--log', "sumo_log.txt",
            '--start'
        ])

def register_vehicle(veh_id):
    url = "http://localhost:5000/register_vehicle"

    if veh_id not in vehicles:
        print(f"❌ 车辆 {veh_id} 未初始化，无法注册！")
        return
    ecc_public_key_pem = vehicles[veh_id].public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
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

def get_vehicle_info(veh_id):
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
    url = f"http://localhost:5000/get_vehicle_certificate?veh_id={veh_id}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        print(f"🚗 车辆 {veh_id} 的证书信息：
{data['certificate']}")
        return data["certificate"]
    else:
        print(f"❌ 车辆 {veh_id} 证书查询失败")
        return None

def verify_certificate(certificate):
    url = "http://localhost:5000/verify_certificate"
    data = {"certificate": certificate}

    response = requests.post(url, json=data)

    if response.status_code == 200:
        print("✅ 证书验证成功")
        return True
    else:
        print("❌ 证书验证失败:", response.json())
        return False

def shouldContinueSim():
    return traci.simulation.getMinExpectedNumber() > 0

if __name__ == "__main__":
    main()
