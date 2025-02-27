from sumolib import checkBinary
import traci
import time
import requests
from property import Vehicle
from environments import RSU
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
        register_vehicle(vehId)
        vehicles[vehId] = Vehicle(vehId, 'passenger', 33.33, 4.5, 2.0, 100, 50)
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
    response = requests.post("http://localhost:5000/register_vehicle", json={"veh_id": veh_id})
    print(response.json())

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