from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# 🚀 1. 初始化数据库（存储信任值）
def connect_db():
    conn = sqlite3.connect("trust_db.sqlite")
    return conn

def init_db():
    conn = connect_db()
    cursor = conn.cursor()
    # **🗑️ 清空 `vehicles` 表，防止主键冲突**
    cursor.execute("DROP TABLE IF EXISTS vehicles")
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS vehicles (
                        veh_id TEXT PRIMARY KEY,
                        trust_score REAL DEFAULT 1.0,
                        anomaly_driving INTEGER DEFAULT 0,
                        collision INTEGER DEFAULT 0,
                        data_reliability REAL DEFAULT 1.0,
                        data_consistency REAL DEFAULT 1.0,
                        valid_certification INTEGER DEFAULT 1,
                        neighbor_trust REAL DEFAULT 1.0
                      )''')
    conn.commit()
    conn.close()

init_db()  # 初始化数据库

# 🚗 2. 车辆注册
@app.route("/register_vehicle", methods=["POST"])
def register_vehicle():
    data = request.json
    veh_id = data["veh_id"]
    trust_score = 1.0  # 默认信任值
    location = "(0,0)"  # 默认位置
    
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO vehicles (veh_id, trust_score, anomaly_driving, collision, 
                      data_reliability, data_consistency, valid_certification, neighbor_trust)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                   (veh_id, 1.0, 0, 0, 1.0, 1.0, 1, 1.0))
    conn.commit()
    conn.close()
    
    return jsonify({"message": f"✅ 车辆 {veh_id} 注册成功"}), 200

# 🚗 3. 查询某辆车的信任值和位置信息
@app.route("/get_vehicle_info", methods=["GET"])
def get_vehicle_info():
    veh_id = request.args.get("veh_id")  # 查询目标车辆
    
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vehicles WHERE veh_id=?", (veh_id,))
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return jsonify({
            "veh_id": result[0], 
            "trust_score": result[1],
            "anomaly_driving": result[2],
            "collision": result[3],
            "data_reliability": result[4],
            "data_consistency": result[5],
            "valid_certification": result[6],
            "neighbor_trust": result[7]
        })
    else:
        return jsonify({"error": "车辆未注册"}), 404

# 🚗 4. 更新车辆信任值（发生违规时）
@app.route("/update_trust_factors", methods=["POST"])
def update_trust():
    data = request.json
    veh_id = data["veh_id"]

    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''UPDATE vehicles SET 
                      trust_score=?, anomaly_driving=?, collision=?, 
                      data_reliability=?, data_consistency=?, valid_certification=?, neighbor_trust=? 
                      WHERE veh_id=?''',
                   (data["trustScore"], data["anomaly_driving"], data["collision"], 
                    data["data_reliability"], data["data_consistency"], 
                    data["valid_certification"], data["neighbor_trust"], veh_id))
    conn.commit()
    conn.close()

    return jsonify({"message": f"✅ 车辆 {veh_id} 信任值更新成功"}), 200

if __name__ == "__main__":
# import os

# # 🚀 1. 运行服务器之前，删除旧数据库
# if os.path.exists("trust_db.sqlite"):
#     print("🗑️ 删除旧的 trust_db.sqlite...")
#     os.remove("trust_db.sqlite")

    # 运行服务器
    app.run(debug=True, port=5000)
