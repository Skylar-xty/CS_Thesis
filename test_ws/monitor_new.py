import traci
import requests
speed_max = 33
class POIMonitor:
    def __init__(self, poi_positions, radius=180.0):
        self.poi_positions = poi_positions
        self.radius = radius
        self.violations = {} # 记录每辆车的违规次数

    def scan_all(self, vehicles, message_buffer):
        print(f"📡 扫描开始：共{len(vehicles)}辆车")
        for veh_id in traci.vehicle.getIDList():
            x, y = traci.vehicle.getPosition(veh_id)
            for px, py in self.poi_positions:
                if (x - px)**2 + (y - py)**2 <= self.radius ** 2:
                    self._analyze(veh_id, vehicles.get(veh_id), message_buffer)

    def _analyze(self, veh_id, veh, message_buffer):
        if not veh: return
        speed = traci.vehicle.getSpeed(veh_id)
        position = traci.vehicle.getPosition(veh_id)
        accel = traci.vehicle.getAcceleration(veh_id)

        anomaly = 0
        if veh_id not in self.violations:
            self.violations[veh_id] = {"overspeed": 0, "redlight": 0, "lying": 0}

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
        # 规则3：检查基本信息
        # ⚠️ 如果该车有最近发出的通信内容
        if veh_id in message_buffer:
            msg = message_buffer[veh_id]
            claimed_speed = msg["speed"]
            claimed_position = msg["location"]
            receiver_id = msg["receiver_id"]

            # 计算差异
            speed_diff = abs(claimed_speed - speed)
            loc_diff = ((claimed_position[0] - position[0])**2 + (claimed_position[1] - position[1])**2) ** 0.5

            if speed_diff > 5 or loc_diff > 10:
                print(f"🚨 RSU 检测到车辆 {veh_id} 谎报数据！")
                print(f"📍 声称位置: {claimed_position}，实际位置: {position}")
                print(f"🚗 声称速度: {claimed_speed}，实际速度: {speed}")
                print(f"📢 通知车辆 {receiver_id}：请警惕 {veh_id} 的不实广播")
                self.violations[veh_id]["lying"] += 1
                anomaly += 1
                # 降低数据可靠性
                old_reliability = veh.data_reliability
                veh.data_reliability = max(0.0, veh.data_reliability * 0.8)
                print(f"📉 数据可靠性下降: {old_reliability:.2f} → {veh.data_reliability:.2f}")
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
            print(f"🚨 车辆 {veh_id} 异常累积:{anomaly}！超速:{self.violations[veh_id]['overspeed']}，闯红灯:{self.violations[veh_id]['redlight']}, 谎报:{self.violations[veh_id].get('lying', 0)}")
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
