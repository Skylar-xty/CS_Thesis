import xml.etree.ElementTree as ET

def reverse_and_flip(edge_list):
    reversed_edges = edge_list[::-1]
    flipped = []
    for edge in reversed_edges:
        if edge.startswith("-"):
            flipped.append(edge[1:])  # remove '-'
        else:
            flipped.append(f"-{edge}")  # add '-'
    return flipped

def process_routes(input_file, output_file):
    tree = ET.parse(input_file)
    root = tree.getroot()

    for vehicle in root.findall("vehicle"):
        route = vehicle.find("route")
        original_edges = route.get("edges").strip().split()
        reversed_flipped = reverse_and_flip(original_edges)
        new_edges = original_edges + reversed_flipped
        route.set("edges", " ".join(new_edges))

    tree.write(output_file, encoding="utf-8", xml_declaration=True)

if __name__ == "__main__":
    input_file = "modified_routes2_new.rou.xml"   # 输入文件路径
    output_file = "modified_routes2_newlong.rou.xml"  # 输出文件路径
    process_routes(input_file, output_file)
    print(f"✅ Processed route file saved to: {output_file}")
