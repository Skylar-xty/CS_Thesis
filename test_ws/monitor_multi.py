import math
import traci
import requests
import logging
logging.basicConfig(
    filename='monitor_log.txt', 
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] %(message)s')

class SinglePOIMonitor:
    def __init__(self, x, y, radius=10.0):
        self.x = x
        self.y = y
        self.radius = radius

    def monitor_nearby_vehicles(self, vehicles_dict):
        for veh_id in traci.vehicle.getIDList():
            pos = traci.vehicle.getPosition(veh_id)
            dx, dy = pos[0] - self.x, pos[1] - self.y
            if dx * dx + dy * dy <= self.radius * self.radius:
                if veh_id in vehicles_dict:
                    print(f"👀 Scanning vehicle {veh_id} near POI...")
                    self._analyze(veh_id, vehicles_dict[veh_id])

    def _analyze(self, veh_id, veh_obj):
        speed = traci.vehicle.getSpeed(veh_id)
        accel = traci.vehicle.getAcceleration(veh_id)

        anomaly_detected = False

        # === 异常行为设计入口 === #
        # 🚩 规则 1：超速或急加速
        if speed > 33.33 or abs(accel) > 5.0:
            veh_obj.anomaly_driving = 1
            anomaly_detected = True
        else:
            veh_obj.anomaly_driving = 0

        # 🚩 规则 2：疑似碰撞行为
        if accel < -8.0 and speed < 2.0:
            veh_obj.collision += 1
            anomaly_detected = True

        # 🚩 规则 3：信任值下降模拟（可添加突变行为等）
        veh_obj.data_reliability *= 0.98 if veh_obj.anomaly_driving else 1.0
        veh_obj.data_consistency *= 0.97 if veh_obj.collision else 1.0
        veh_obj.neighbor_trust *= 0.99 if veh_obj.anomaly_driving else 1.0

        score = 0.2 * veh_obj.data_reliability + 0.2 * veh_obj.data_consistency + \
                0.2 * veh_obj.valid_certification + 0.4 * veh_obj.neighbor_trust
        veh_obj.trustScore = max(0.0, min(1.0, score))

        veh_obj.malicious = veh_obj.trustScore < veh_obj.trust_threshold

        if anomaly_detected:  # if 1:
            print(f"🚨 异常行为 | {veh_id} | Trust={veh_obj.trustScore:.2f}")
            logging.info(
                f"[POI监测] 车辆 {veh_id} 异常: Trust={veh_obj.trustScore:.2f}, "
                f"Anomaly={veh_obj.anomaly_driving}, Collision={veh_obj.collision}"
            )
            try:
                r = requests.post("http://localhost:5000/update_trust_factors", json={
                    "veh_id": veh_id,
                    "trust_score": veh_obj.trustScore,
                    "anomaly_driving": veh_obj.anomaly_driving,
                    "collision": veh_obj.collision,
                    "data_reliability": veh_obj.data_reliability,
                    "data_consistency": veh_obj.data_consistency,
                    "valid_certification": veh_obj.valid_certification,
                    "neighbor_trust": veh_obj.neighbor_trust
                })
                print("📡 已上传信任更新：", r.json())
            except Exception as e:
                print("❌ 信任上传失败：", e)

class POIMonitorMulti:
    def __init__(self, poi_positions, radius=10.0):
        self.monitors = [SinglePOIMonitor(x, y, radius) for x, y in poi_positions]

    def scan_all(self, vehicles_dict):
        for monitor in self.monitors:
            monitor.monitor_nearby_vehicles(vehicles_dict)
