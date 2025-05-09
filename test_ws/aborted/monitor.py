import math
import traci
import requests

class POIMonitor:
    def __init__(self, poi_x, poi_y, radius=10.0):
        self.poi_position = (poi_x, poi_y)
        self.radius = radius

    def is_near_poi(self, position):
        dx = position[0] - self.poi_position[0]
        dy = position[1] - self.poi_position[1]
        return math.hypot(dx, dy) <= self.radius

    def detect_anomalies(self, veh_id, veh_obj):
        speed = traci.vehicle.getSpeed(veh_id)
        accel = traci.vehicle.getAcceleration(veh_id)
        lane_id = traci.vehicle.getLaneID(veh_id)

        # 简单规则检测
        anomaly_detected = False
        if speed > 33.33 or abs(accel) > 5.0:
            veh_obj.anomaly_driving = 1
            anomaly_detected = True
        else:
            veh_obj.anomaly_driving = 0

        # 模拟碰撞检测（可以通过坐标变动或SUMO的collider API扩展）
        # 如果车辆突然减速且accel为负，可能是发生碰撞
        if accel < -8.0 and speed < 2.0:
            veh_obj.collision += 1
            anomaly_detected = True

        # 更新信任相关参数（可扩展为机器学习预测）
        veh_obj.data_reliability *= 0.98 if veh_obj.anomaly_driving else 1.0
        veh_obj.data_consistency *= 0.97 if veh_obj.collision else 1.0
        veh_obj.neighbor_trust *= 0.99 if veh_obj.anomaly_driving else 1.0

        # 简单计算新 trust score（可替换为更复杂模型）
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
        if self.is_near_poi(position):
            print(f"🔍 监测到车辆 {veh_id} 靠近 POI，正在检测...")
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
                    print("❌ 无法上传异常数据：", e)
