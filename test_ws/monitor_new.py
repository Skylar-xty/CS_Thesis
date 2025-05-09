import traci
import requests
speed_max = 33
class POIMonitor:
    def __init__(self, poi_positions, radius=180.0):
        self.poi_positions = poi_positions
        self.radius = radius
        self.violations = {} # 记录每辆车的违规次数

    def scan_all(self, vehicles):
        print(f"📡 扫描开始：共{len(vehicles)}辆车")
        for veh_id in traci.vehicle.getIDList():
            x, y = traci.vehicle.getPosition(veh_id)
            for px, py in self.poi_positions:
                if (x - px)**2 + (y - py)**2 <= self.radius ** 2:
                    self._analyze(veh_id, vehicles.get(veh_id))

    def _analyze(self, veh_id, veh):
        if not veh: return
        speed = traci.vehicle.getSpeed(veh_id)
        accel = traci.vehicle.getAcceleration(veh_id)

        anomaly = 0
        if veh_id not in self.violations:
            self.violations[veh_id] = {"overspeed": 0, "redlight": 0}

        # 规则1：超速
        overspeed = speed>speed_max
        
        # 规则2：闯红灯
        redlight_violation = traci.vehicle.getSpeedMode(veh_id) == 0b00000

        if overspeed:
            self.violations[veh_id]["overspeed"] += 1
            anomaly += 1
        
        if redlight_violation:
            self.violations[veh_id]["redlight"] += 1
            anomaly += 1
        # veh.collision += int(collision)
        # veh.data_reliability *= 0.98 if anomaly else 1.0
        # veh.data_consistency *= 0.97 if collision else 1.0
        # veh.neighbor_trust *= 0.99 if anomaly else 1.0

        # trust_score = 0.2 * veh.data_reliability + \
        #               0.2 * veh.data_consistency + \
        #               0.2 * veh.valid_certification + \
        #               0.4 * veh.neighbor_trust
        # veh.trustScore = max(0.0, min(1.0, trust_score))

        if anomaly:
            veh_id.anomaly_driving += anomaly
            print(f"🚨 车辆 {veh_id} 异常！超速:{self.violations[veh_id]['overspeed']}，闯红灯:{self.violations[veh_id]['redlight']}")
            try:
                requests.post("http://localhost:5000/update_trust_factors", json={
                    "veh_id": veh_id,
                    "anomaly_driving": veh.anomaly_driving
                    # "collision": veh.collision,
                    # "data_reliability": veh.data_reliability,
                    # "data_consistency": veh.data_consistency,
                    # "valid_certification": veh.valid_certification,
                    # "neighbor_trust": veh.neighbor_trust
                })
            except Exception as e:
                print("❌ Failed to upload trust update:", e)
