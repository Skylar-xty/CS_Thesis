from xml.etree import ElementTree as ET

tree = ET.parse("./test1/modified_routes2_bidirectional.rou.xml")
root = tree.getroot()

for vehicle in root.findall('vehicle'):
    # 1. 设置全部同时出发
    vehicle.set('depart', '0.00')

    # # 2. 路径重复一遍以延长路程
    # route = vehicle.find('route')
    # edges = route.get('edges').strip()
    # extended_edges = f"{edges} {edges}"  # 简单重复一遍
    # route.set('edges', extended_edges)

tree.write("modified_routes2_new.rou.xml", encoding='utf-8', xml_declaration=True)
print("✅ 车辆全部设置为同时出发，路线已加长。")
