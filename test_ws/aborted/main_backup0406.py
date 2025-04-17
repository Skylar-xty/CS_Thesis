from sumolib import checkBinary
import traci
import time
import requests
from property import Vehicle
from environments import RSU

from cryptography.hazmat.primitives import serialization
sumoBinary = checkBinary('sumo-gui')

EXPERIMENT = 'test1'
RED = [255, 0, 0]
EDGE_ID = 'closed'
all_VEHICLES = ['0','1','2','3','4','5','6','7','8','9']
VEHICLES = ['1', '4', '8']
# Define RSUs
rsus = [
    RSU("rsu_1", (1000, 2000), 500, 100),
    RSU("rsu_2", (1500, 2500), 500, 50)
]
vehicles = {} # Dictionary to store all vehicle objects
 
def main():
    startSim()
 
    # vehilce init
    for vehId in all_VEHICLES:
        vehicles[vehId] = Vehicle(vehId, 'passenger', 33.33, 4.5, 2.0, 100, 50)
        register_vehicle(vehId)
    # # 🚗 车辆A 想与 车辆B 通信
    # if vehicles[0].decide_communication("1"):
    #     print("📡 开始数据交换...")
    # else:
    #     print("❌ 终止通信")
    while shouldContinueSim():

        # 更新并显示车辆动态属性
        for veh in vehicles.values():
            veh.update_dynamic_attributes(traci)
            veh.display_info() 
            veh.upload_trust_to_ta()
            
            # 查询目标车辆信任评分
            target_veh_id = "1"
            trust_info = get_vehicle_info(target_veh_id)

            if trust_info and trust_info["trust_score"] >=0:
                print(f"✅ 车辆 {veh.id} 想要与 {target_veh_id} 进行安全通信...")

                # 🆕 第一次通信时查询证书
                if not veh.has_verified_certificate(target_veh_id):
                    certificate = get_certificate(target_veh_id)
                    if certificate:
                        if verify_certificate(certificate):  # 证书验证
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
    """Starts the simulation."""
    traci.start(
        [
            sumoBinary,
            '--net-file', f'./config/{EXPERIMENT}/net.net.xml',
            # '--net-file', './config/network_new.net.xml',
            # '--route-files', './config/trips.trips.xml',
            '--route-files', f'./config/{EXPERIMENT}/routes.rou.xml',
            '--delay', '200',
            '--gui-settings-file', './config/viewSettings.xml',
            '--additional-files', './config/additional.xml',
            '--log', "sumo_log.txt",
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

def verify_certificate(certificate):
    """ 🚗 向 TA 服务器发送证书验证请求 """
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