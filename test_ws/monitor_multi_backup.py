import math
import traci
import requests

class POIMonitorMulti:
    def __init__(self, poi_list, radius=10.0):
        self.poi_list = poi_list  # list of (x, y) tuples
        self.radius = radius

    def is_near_any_poi(self, position):
        for poi in self.poi_list:
            if math.hypot(position[0] - poi[0], position[1] - poi[1]) <= self.radius:
                return True
        return False

    def detect_anomalies(self, veh_id, veh_obj):
        speed = traci.vehicle.getSpeed(veh_id)
        accel = traci.vehicle.getAcceleration(veh_id)

        anomaly_detected = False
        if speed > 33.33 or abs(accel) > 5.0:
            veh_obj.anomaly_driving = 1
            anomaly_detected = True
        else:
            veh_obj.anomaly_driving = 0

        if accel < -8.0 and speed < 2.0:
            veh_obj.collision += 1
            anomaly_detected = True

        veh_obj.data_reliability *= 0.98 if veh_obj.anomaly_driving else 1.0
        veh_obj.data_consistency *= 0.97 if veh_obj.collision else 1.0
        veh_obj.neighbor_trust *= 0.99 if veh_obj.anomaly_driving else 1.0

        score = 0.2 * veh_obj.data_reliability + 0.2 * veh_obj.data_consistency + \
                0.2 * veh_obj.valid_certification + 0.4 * veh_obj.neighbor_trust
        veh_obj.trustScore = max(0.0, min(1.0, score))

        if veh_obj.trustScore < veh_obj.trust_threshold:
            veh_obj.malicious = True
        else:
            veh_obj.malicious = False

        return anomaly_detected

    def monitor_vehicle(self, veh_id, veh_obj):
        position = traci.vehicle.getPosition(veh_id)
        if self.is_near_any_poi(position):
            print(f"🔍 车辆 {veh_id} 接近任意 POI，执行监测...")
            if self.detect_anomalies(veh_id, veh_obj):
                print(f"🚨 异常行为检测：{veh_id} | Trust={veh_obj.trustScore:.2f}")
                try:
                    response = requests.post("http://localhost:5000/update_trust_factors", json={
                        "veh_id": veh_id,
                        "trust_score": veh_obj.trustScore,
                        "anomaly_driving": veh_obj.anomaly_driving,
                        "collision": veh_obj.collision,
                        "data_reliability": veh_obj.data_reliability,
                        "data_consistency": veh_obj.data_consistency,
                        "valid_certification": veh_obj.valid_certification,
                        "neighbor_trust": veh_obj.neighbor_trust
                    })
                    print("📡 信任值已更新：", response.json())
                except Exception as e:
                    print("❌ 上传异常行为失败：", e)
