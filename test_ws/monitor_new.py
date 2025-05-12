import traci
import requests
import json # 新增导入 for json parsing

# 全局或可配置的最大速度阈值
SPEED_MAX_THRESHOLD = 20 # m/s, 您可以根据需要调整
# 谎报检测的阈值
LYING_SPEED_DIFF_THRESHOLD = 5.0 # m/s
LYING_LOC_DIFF_THRESHOLD = 10.0  # meters

class POIMonitor:
    def __init__(self, poi_positions, radius=180.0):
        self.poi_positions = poi_positions
        self.radius = radius
        self.violations = {} # 记录每辆车的具体违规次数
        self.processed_lying_messages = set()
        print(f"[监控器初始化] POI位置: {self.poi_positions}, 监控半径: {self.radius}m")

    def scan_all(self, vehicles_map, message_buffer): # 重命名 vehicles 为 vehicles_map 以更清晰
        # print(f"📡 [监控器扫描] 开始扫描。当前车辆字典大小: {len(vehicles_map)}") # 减少过于频繁的打印
        try:
            active_vehicle_ids = list(traci.vehicle.getIDList()) # 获取当前仿真中的所有车辆ID
        except traci.exceptions.TraCIException as e:
            print(f"📡 [监控器扫描] 获取活动车辆列表时出错 (SUMO可能已关闭): {e}")
            return

        if not active_vehicle_ids:
            # print("📡 [监控器扫描] 当前仿真中无活动车辆。")
            return
        
        current_time = traci.simulation.getTime()

        for veh_id in active_vehicle_ids:
            try:
                # 确保车辆在我们的内部字典中，并且仍在仿真中
                if veh_id not in vehicles_map:
                    # print(f"  [监控器扫描] 车辆 {veh_id} 在仿真中，但不在我们的车辆字典中，跳过分析。")
                    continue

                vehicle_obj = vehicles_map.get(veh_id)
                if not vehicle_obj: # 以防万一 get 返回 None (理论上不会，因为上面检查了)
                    continue

                veh_sim_pos_x, veh_sim_pos_y = traci.vehicle.getPosition(veh_id)
                
                is_near_any_poi = False
                for poi_x, poi_y in self.poi_positions:
                    if (veh_sim_pos_x - poi_x)**2 + (veh_sim_pos_y - poi_y)**2 <= self.radius ** 2:
                        is_near_any_poi = True
                        break
                
                if is_near_any_poi:
                    # print(f"  [监控器扫描] 车辆 {veh_id} 靠近POI，准备分析...")
                    self._analyze(veh_id, vehicle_obj, message_buffer)
                # else:
                    # print(f"  [监控器扫描] 车辆 {veh_id} 不在任何POI附近。")

            except traci.exceptions.TraCIException as e:
                # print(f"  [监控器扫描] 处理车辆 {veh_id} 时发生 TraCI 错误 (车辆可能已离开): {e}")
                continue # 继续处理下一个车辆
            except Exception as e_global:
                print(f"  [监控器扫描] 处理车辆 {veh_id} 时发生未知错误: {e_global}")
                continue


    def _analyze(self, veh_id, veh_obj, message_buffer): # veh_obj 是 property.Vehicle 的实例
        if not veh_obj: # veh_obj 是从 vehicles_map.get(veh_id) 传入的
            # print(f"    [分析] 车辆对象 {veh_id} 为空，无法分析。")
            return

        try:
            actual_speed = traci.vehicle.getSpeed(veh_id)
            actual_position = traci.vehicle.getPosition(veh_id)
            # actual_accel = traci.vehicle.getAcceleration(veh_id) # 如果需要加速度
            speed_mode = traci.vehicle.getSpeedMode(veh_id)
        except traci.exceptions.TraCIException as e:
            # print(f"    [分析] 获取车辆 {veh_id} 的 TraCI 数据失败 (车辆可能已离开): {e}")
            return # 无法获取真实数据，无法分析

        current_anomalies_found_count = 0 # 本次分析发现的异常数量
        if veh_id not in self.violations:
            self.violations[veh_id] = {"overspeed": 0, "redlight": 0, "lying": 0, "total_detected_anomalies": 0}

        # 规则1：超速检测 (基于实际观测)
        is_overspeeding = actual_speed > SPEED_MAX_THRESHOLD
        if is_overspeeding:
            self.violations[veh_id]["overspeed"] += 1
            current_anomalies_found_count += 1
            print(f"    [分析] 车辆 {veh_id}: 检测到超速！速度: {actual_speed:.2f} m/s (阈值: {SPEED_MAX_THRESHOLD} m/s)")

        # 规则2：闯红灯检测 (基于实际观测)
        # SUMO速度模式0表示完全忽略速度限制、红绿灯和安全距离。
        # 通常这用于攻击者车辆，或者在某些特殊情况下。
        # 正常车辆的speedMode通常是31 (二进制11111)，表示遵守所有规则。
        is_running_red_light = (speed_mode == 0) # 或者更复杂的基于交通灯状态的判断
                                               # getRedYellowGreenState() 和 getControlledLinks()
        if is_running_red_light:
            # 注意：仅凭 speed_mode == 0 可能不足以精确判断闯红灯，
            # 它更多地表明车辆忽略了规则。真实的闯红灯检测需要结合交通灯状态。
            # 但对于模拟攻击车辆的行为，这通常是一个好指标。
            self.violations[veh_id]["redlight"] += 1
            current_anomalies_found_count += 1
            print(f"    [分析] 车辆 {veh_id}: 检测到闯红灯/忽略规则行为 (SpeedMode: {speed_mode})！")

        # 规则3：谎报数据检测 (基于通信内容)
        if veh_id in message_buffer:
            msg_entry = message_buffer[veh_id]
            # `msg_entry["message"]` 是 `perform_secure_communication` 中传递的 `actual_message_content`
            # 这可能是普通字符串，也可能是包含伪造数据的JSON字符串
            raw_message_payload = msg_entry.get("message")
            msg_timestamp = msg_entry.get("timestamp")

            message_identifier = (veh_id, msg_timestamp) # 使用 (veh_id, timestamp) 作为消息的唯一标识
            claimed_speed_from_msg = None
            claimed_position_from_msg = None

            if message_identifier not in self.processed_lying_messages:
                if isinstance(raw_message_payload, str):
                    try:
                        # 尝试将消息内容解析为JSON
                        parsed_payload = json.loads(raw_message_payload)
                        # 从解析后的JSON中提取声称的速度和位置
                        # 确保这些键名与您在数据伪造攻击中使用的键名一致
                        claimed_speed_from_msg = parsed_payload.get("claimed_speed")
                        claimed_position_from_msg = parsed_payload.get("claimed_location") # 期望是 (x, y) 元组或列表
                        # print(f"    [分析] 车辆 {veh_id}: 成功解析消息负载。声称速度: {claimed_speed_from_msg}, 声称位置: {claimed_position_from_msg}")
                    except json.JSONDecodeError:
                        # print(f"    [分析] 车辆 {veh_id}: 消息内容不是有效的JSON格式，无法检测谎报。内容: '{raw_message_payload[:50]}...'")
                        pass # 不是JSON，无法按此方式检测谎报
                    except TypeError: # 如果 raw_message_payload 不是字符串或字节
                        # print(f"    [分析] 车辆 {veh_id}: 消息内容类型不正确 ({type(raw_message_payload)})，无法检测谎报。")
                        pass


                # 如果成功从消息中提取了声称的速度和位置
                if claimed_speed_from_msg is not None and claimed_position_from_msg is not None:
                    try:
                        # 类型转换和校验
                        claimed_speed_val = float(claimed_speed_from_msg)
                        if not (isinstance(claimed_position_from_msg, (list, tuple)) and len(claimed_position_from_msg) == 2):
                            # print(f"    [分析] 车辆 {veh_id}: 消息中声称的位置格式不正确: {claimed_position_from_msg}")
                            raise ValueError("声称的位置格式错误")
                        
                        claimed_pos_x = float(claimed_position_from_msg[0])
                        claimed_pos_y = float(claimed_position_from_msg[1])

                        speed_difference = abs(claimed_speed_val - actual_speed)
                        location_difference = ((claimed_pos_x - actual_position[0])**2 + \
                                            (claimed_pos_y - actual_position[1])**2)**0.5

                        if speed_difference > LYING_SPEED_DIFF_THRESHOLD or location_difference > LYING_LOC_DIFF_THRESHOLD:
                            print(f"🚨 [分析] RSU 检测到车辆 {veh_id} 谎报数据！")
                            print(f"  📍 声称位置: ({claimed_pos_x:.2f}, {claimed_pos_y:.2f}) vs 实际位置: ({actual_position[0]:.2f}, {actual_position[1]:.2f}) (差异: {location_difference:.2f}m)")
                            print(f"  🚗 声称速度: {claimed_speed_val:.2f} m/s vs 实际速度: {actual_speed:.2f} m/s (差异: {speed_difference:.2f}m/s)")
                            # print(f"  📢 (可选) 通知车辆 {msg_entry.get('receiver_id', '未知接收者')}：请警惕 {veh_id} 的不实广播")
                            
                            self.violations[veh_id]["lying"] += 1
                            current_anomalies_found_count += 1
                            
                            # 对数据可靠性进行惩罚
                            old_reliability = veh_obj.data_reliability
                            veh_obj.data_reliability = max(0.0, veh_obj.data_reliability * 0.7) # 更严厉的惩罚
                            print(f"    📉 车辆 {veh_id} 数据可靠性因此次谎报下降: {old_reliability:.2f} → {veh_obj.data_reliability:.2f}")
                            self.processed_lying_messages.add(message_identifier) # 标记此消息已因谎报被处理
                    except (ValueError, TypeError) as parse_err:
                        # print(f"    [分析] 车辆 {veh_id}: 解析声称的速度/位置数据时出错: {parse_err}")
                        pass # 解析声称数据失败，无法检测

        # 如果在本次分析中检测到任何类型的异常
        if current_anomalies_found_count > 0:
            self.violations[veh_id]["total_detected_anomalies"] += current_anomalies_found_count
            veh_obj.anomaly_driving += current_anomalies_found_count # 更新车辆对象的异常驾驶总数
            
            print(f"🚨 [分析总结] 车辆 {veh_id} 异常行为增加。当前异常驾驶总计: {veh_obj.anomaly_driving}。"
                  f" 本次新增: {current_anomalies_found_count}。"
                  f" (具体: 超速 {self.violations[veh_id]['overspeed']} 次,"
                  f" 闯红灯 {self.violations[veh_id]['redlight']} 次,"
                  f" 谎报 {self.violations[veh_id]['lying']} 次)")
            
            # 更新TA的信任因素
            # 注意：这里只发送了 anomaly_driving 和 data_reliability。
            # 如果其他因素（如碰撞、邻居信任等）也由监控器更新，也应包含。
            # TA侧的 /update_trust_factors 接口需要能处理这些部分更新。
            payload_to_ta = {
                "veh_id": veh_id,
                "anomaly_driving": veh_obj.anomaly_driving # 发送更新后的总数
            }
            # 只有当数据可靠性实际发生变化时才发送 (例如因为谎报)
            if "old_reliability" in locals() and old_reliability != veh_obj.data_reliability:
                payload_to_ta["data_reliability"] = veh_obj.data_reliability
            
            try:
                response = requests.post("http://localhost:5000/update_trust_factors", json=payload_to_ta, timeout=2)
                if response.status_code == 200:
                    # print(f"    📡 成功上传车辆 {veh_id} 的信任更新到TA。")
                    pass
                else:
                    print(f"    ❌ 上传车辆 {veh_id} 信任更新到TA失败: {response.status_code} - {response.text}")
            except requests.exceptions.RequestException as e:
                print(f"    ❌ 上传车辆 {veh_id} 信任更新到TA时网络请求失败: {e}")

        # 注意: 这里的信任评分计算和 malicious 标志的设置被注释掉了。
        # 这些通常应该由TA根据所有因素来计算和判断，或者车辆自身根据TA的反馈来更新。
        # 如果POIMonitor也负责计算本地的临时信任分，则需要取消注释并确保逻辑正确。
        # trust_score = 0.2 * veh_obj.data_reliability + \
        #               0.2 * veh_obj.data_consistency + \ # data_consistency 未在此处更新
        #               0.2 * veh_obj.valid_certification + \ # valid_certification 未在此处更新
        #               0.4 * veh_obj.neighbor_trust # neighbor_trust 未在此处更新
        # veh_obj.trustScore = max(0.0, min(1.0, trust_score))
        # veh_obj.malicious = veh_obj.trustScore < veh_obj.trust_threshold # 假设有 trust_threshold