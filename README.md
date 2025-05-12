# CS_Thesis
Design of a Vehicular Network Data Authentication System (Undergraduate dissertation)

This project simulates a vehicular network environment to design and test a data authentication system incorporating PKI and a dynamic trust management mechanism. It uses SUMO for traffic simulation and Python for implementing security protocols, trust management, and various attack scenarios.

## Features
* PKI-based authentication for vehicles using ECC and BLS cryptography.
* Secure V2X communication using ECDH for key exchange and AES-GCM for encryption.
* Dynamic trust management system evaluating vehicles based on multiple factors.
* Simulation of various attack scenarios to test system robustness.
* Centralized Trusted Authority (TA) for certificate management and trust score aggregation.
* RSU-like monitoring UAVs (simulated via POIs) to detect and report anomalous vehicle behavior.


## Running the Simulation

To start the simulation, you need to run two main components in separate terminal windows:

1.  **Start the Trusted Authority (TA) service:**
    ```bash
    python trusted_authority.py
    ```
    This service handles vehicle registration, certificate issuance and verification, and trust score management. It listens on `localhost:5000` by default.

2.  **Start the SUMO simulation controlado por `main.py`:**
    ```bash
    python main.py --scenario [SCENARIO_NAME]
    ```

### SCENARIO_NAME Options:

Replace `[SCENARIO_NAME]` with one of the following options to run different simulation scenarios:

* `none`:
    * **Description**: Runs a normal simulation cycle without any specific pre-defined attacks. Vehicles will register, communicate securely, and the monitor will observe behaviors. This is the default scenario and useful for observing baseline system performance.
* `identity_forgery`:
    * **Description**: Simulates an identity forgery attack. An attacker vehicle (pre-configured as vehicle "3" in the code) attempts to interact with the system or other vehicles using a counterfeit digital certificate. This tests the TA's ability to detect fake certificates and the PKI's overall identity verification strength.
* `replay_attack`:
    * **Description**: Simulates a replay attack. The system first attempts to capture a legitimate secure communication packet (e.g., between vehicles "0" and "1"). Subsequently, an attacker tries to re-transmit this captured packet to test the system's nonce mechanism and replay detection capabilities. Two replay attempts are made, with the second one specifically testing the effectiveness of the nonce cache.
* `abnormal_behavior`:
    * **Description**: Simulates a vehicle (pre-configured as vehicle "0") exhibiting anomalous driving patterns (e.g., speeding, running red lights) when approaching a Point of Interest (POI), which simulates an RSU-monitored zone. This scenario tests the `POIMonitor` module's detection capabilities and the TA's response in adjusting the vehicle's trust score.
* `revoked_certificate`:
    * **Description**: Simulates an attack where a vehicle (pre-configured as "2") attempts to communicate with another vehicle (pre-configured as "4") using a certificate that has been previously revoked by the TA. This tests the certificate revocation mechanisms and the TA's response during the verification of a revoked certificate.
* `lying_attack`:
    * **Description**: Simulates a "lying" vehicle (pre-configured as "5") that intentionally broadcasts false status information (e.g., incorrect position or speed) when communicating with another vehicle (pre-configured as "1"). This scenario tests the `POIMonitor`'s ability to detect such misbehavior by comparing broadcasted data against RSU-observed "ground truth," and assesses the impact on the attacker's `data_reliability` factor and overall trust score. The attacker will attempt to lie multiple times (defaulted to 3 in the code).

**Example:**

To run the simulation with the `identity_forgery` attack scenario:

1.  In terminal 1: `python trusted_authority.py`
2.  In terminal 2: `python main.py --scenario identity_forgery`

Make sure the `trusted_authority.py` service is running before starting `main.py`.
