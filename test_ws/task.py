from traci import vehicle

class BaseTask:
    def __init__(self, name, from_id, to_id):
        self.name = name
        self.from_id = from_id
        self.to_id = to_id
        self.done = False

    def run(self, vehicles, all_sensor):
        raise NotImplementedError("Each task must implement the run method.")


class VehicleToVehicleTask(BaseTask):
    def run(self, vehicles, all_sensor):
        if self.done:
            return
        if self.from_id in vehicles and self.to_id in vehicles:
            sender = vehicles[self.from_id]
            if sender.decide_communication(self.to_id):
                print(f"📡 {self.name}: {self.from_id} → {self.to_id} 通信成功")
                self.done = True
            else:
                print(f"❌ {self.name}: 信任值不足，通信失败")


class VehicleToRSUTask(BaseTask):
    def run(self, vehicles, all_sensor):
        if self.done:
            return
        if self.from_id in vehicles and self.to_id in all_sensor:
            print(f"📡 {self.name}: 车辆 {self.from_id} 与 RSU {self.to_id} 通信中")
            self.done = True
            # 可以添加 RSU 存储、记录车辆状态等逻辑
        else:
            print(f"❌ {self.name}: RSU {self.to_id} 不存在或车辆未初始化")

TASKS = {
    "Task1": VehicleToVehicleTask("Task1", from_id="1", to_id="10"),
    "Task2": VehicleToRSUTask("Task2", from_id="2", to_id="rsu_1"),
    # 可添加更多任务
}