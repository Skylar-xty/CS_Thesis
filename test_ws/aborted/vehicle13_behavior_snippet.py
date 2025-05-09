
# 🚨 控制车辆13在接近 POI 时执行异常行为（超速 + 闯红灯）
if "13" in traci.vehicle.getIDList():
    x, y = traci.vehicle.getPosition("13")
    if abs(x - 50.09) < 5 and abs(y - 49.60) < 5:
        try:
            # 禁用所有速度/红灯/安全限制（允许闯红灯）
            traci.vehicle.setSpeedMode("13", 0b00000)

            # 强制设置为超速（40m/s）
            traci.vehicle.setSpeed("13", 40)

            # 可视化上色（红色）
            traci.vehicle.setColor("13", (255, 0, 0))

            print("📢 异常车辆 13 接近 POI：执行闯红灯 + 超速！")
        except Exception as e:
            print("❌ 设置车辆13异常行为失败：", e)
