from sumolib import checkBinary
import traci
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
        vehicles[vehId] = Vehicle(vehId, 'passenger', 33.33, 4.5, 2.0, 100, 50)
    # # 🚗 车辆A 想与 车辆B 通信
    # if vehicles[0].decide_communication("1"):
    #     print("📡 开始数据交换...")
    # else:
    #     print("❌ 终止通信")
    while shouldContinueSim():

        # for vehId in getOurDeparted(VEHICLES):
        #     setVehColor(vehId, RED)
        #     avoidEdge(vehId, EDGE_ID)

        # 更新并显示车辆动态属性
        for veh in vehicles.values():
            veh.update_dynamic_attributes(traci)
            veh.display_info() 
            veh.upload_trust_to_ta()

        # Communication example between two vehicles
        if '1' in vehicles and '4' in vehicles:
            sender = vehicles['1']
            receiver = vehicles['4']
            # **1️⃣ 发送方 1 生成 BLS 签名**
            message = "Hello from Vehicle 1!"
            signature = sender.bls_sign(message)
            print(f"🚗 Vehicle {sender.id} sent a signed message: {message}")

            # **2️⃣ 接收方 4 验证 BLS 签名**
            # message = "error!"
            if receiver.bls_verify(message, signature, sender.bls_public_key):
                print(f"✅ Vehicle {receiver.id} verified the signature from {sender.id}!")
            else:
                print(f"❌ Signature verification failed.")

            # **3️⃣ 发送方 1 使用 ECC 加密**
            encrypted_message = sender.encrypt_message(receiver.public_key, message)
            print(f"🔐 Vehicle {sender.id} encrypted a message for Vehicle {receiver.id}.")

            # **4️⃣ 接收方 4 使用 ECC 解密**
            decrypted_message = receiver.decrypt_message(sender.public_key, encrypted_message)
            print(f"🔓 Vehicle {receiver.id} decrypted the message: {decrypted_message}")

            # **5️⃣ 检查解密数据是否正确**
            if decrypted_message == message:
                print(f"✅ Secure communication between {sender.id} and {receiver.id} is successful!")
            else:
                print(f"❌ Communication integrity compromised!")
            # # Sender creates and signs a message
            # message = "Hello from Vehicle 1!"
            # signature = sender.sign_message(message)
            # print(f"Vehicle {sender.id} sent a signed message: {message}")

            # # Receiver verifies the message and signature
            # if receiver.verify_signature(message, signature, sender.public_key):
            #     print(f"Vehicle {receiver.id} verified the message successfully!")
            # else:
            #     print(f"Vehicle {receiver.id} failed to verify the message.")

        # Example communication between two vehicles
        # if '1' in vehicles and '4' in vehicles:
        #     sender = vehicles['1']
        #     receiver = vehicles['4']

        #     # Step 1: Sender signs a message
        #     message = "Hello, this is Vehicle 1."
        #     signature = sender.sign_message(message)
        #     print(f"[INFO] Vehicle {sender.id} sent a signed message: {message}")

        #     # Step 2: Receiver verifies the signature
        #     if receiver.verify_signature(message, signature, sender.public_key):
        #         print(f"[SUCCESS] Vehicle {receiver.id} verified the signature from Vehicle {sender.id}.")
        #     else:
        #         print(f"[FAILURE] Vehicle {receiver.id} failed to verify the signature from Vehicle {sender.id}.")

        #     # Step 3: Sender encrypts the message for the receiver
        #     encrypted_message = sender.encrypt_message(receiver.public_key, message)
        #     print(f"[INFO] Vehicle {sender.id} encrypted a message for Vehicle {receiver.id}.")

        #     # Step 4: Receiver decrypts the message
        #     decrypted_message = receiver.decrypt_message(sender.public_key, encrypted_message)
        #     print(f"[INFO] Vehicle {receiver.id} decrypted the message: {decrypted_message}")

        #     # Step 5: Validate decrypted message matches original
        #     if decrypted_message == message:
        #         print(f"[SUCCESS] Communication between Vehicle {sender.id} and {receiver.id} is secure.")
        #     else:
        #         print(f"[FAILURE] Communication integrity between Vehicle {sender.id} and {receiver.id} is compromised.")


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