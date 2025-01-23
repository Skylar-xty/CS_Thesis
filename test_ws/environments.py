class RSU:
    def __init__(self, rsu_id, position, coverage_range, storage_capacity):
        # Static attributes
        self.id = rsu_id
        self.position = position  # GPS coordinates (x, y)
        self.coverage_range = coverage_range  # Communication radius in meters
        self.storage_capacity = storage_capacity  # Max number of records/certificates

        # Dynamic attributes
        self.connected_vehicles = {}  # Dictionary of connected vehicles: {veh_id: trust_score}
        self.message_cache = []  # Cached messages for relaying

    # Functional: Certificate issuance
    def issue_certificate(self, vehicle):
        """Simulate issuing a digital certificate to a vehicle."""
        certificate = f"Certificate for {vehicle.id} issued by {self.id}"
        print(f"[INFO] RSU {self.id} issued certificate to Vehicle {vehicle.id}")
        return certificate

    # Functional: Trust score calculation
    def calculate_trust_score(self, vehicle_id, behavior_score):
        """Evaluate and update trust score for a connected vehicle."""
        if vehicle_id in self.connected_vehicles:
            self.connected_vehicles[vehicle_id] += behavior_score
            print(f"[INFO] RSU {self.id} updated trust score for Vehicle {vehicle_id}: {self.connected_vehicles[vehicle_id]}")

    # Functional: Message relaying
    def relay_message(self, sender_id, message):
        """Relay a message to all connected vehicles."""
        self.message_cache.append((sender_id, message))
        for vehicle_id in self.connected_vehicles:
            print(f"[INFO] RSU {self.id} relayed message from {sender_id} to Vehicle {vehicle_id}: {message}")

    # Connect a vehicle
    def connect_vehicle(self, vehicle):
        """Connect a vehicle to the RSU."""
        if len(self.connected_vehicles) < self.storage_capacity:
            self.connected_vehicles[vehicle.id] = vehicle.trustScore
            print(f"[INFO] Vehicle {vehicle.id} connected to RSU {self.id}")
        else:
            print(f"[WARN] RSU {self.id} storage capacity reached. Cannot connect Vehicle {vehicle.id}")

    # Disconnect a vehicle
    def disconnect_vehicle(self, vehicle_id):
        """Disconnect a vehicle from the RSU."""
        if vehicle_id in self.connected_vehicles:
            del self.connected_vehicles[vehicle_id]
            print(f"[INFO] Vehicle {vehicle_id} disconnected from RSU {self.id}")
