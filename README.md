# WebSocket Smuggler (Modular)
![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white) ![Burp Suite](https://img.shields.io/badge/Burp_Suite-FF6633?style=for-the-badge&logo=burpsuite&logoColor=white) ![Security](https://img.shields.io/badge/Cybersecurity-Bug_Bounty-red?style=for-the-badge)

## Overview
The **WebSocket Smuggler (Modular)** is a specialized Burp Suite extension designed to automate the detection and exploitation of **HTTP Request Smuggling** vulnerabilities that arise from faulty WebSocket connection handling by reverse proxies.

This tool is essential for testing modern applications where simple header manipulation is insufficient, focusing on attacks that require precise timing, raw socket control, or chaining with other vulnerabilities like Server-Side Request Forgery (SSRF).

---

## Key Features
* **Intelligent Response Parsing:** Automatically distinguishes between harmless HTTP Pipelining (Safe) and valid Request Smuggling chains, eliminating common false positives.
* **Dual Attack Mode:** Supports two distinct types of blind smuggling attacks (Simple Desync vs. SSRF Trigger).
* **Wordlist Fuzzing Engine:** Load custom wordlists to brute-force internal endpoints or parameters within the smuggled request.
* **Attack Controls:** Pause, resume, and stop attacks on demand, giving you full control over traffic generation.
* **Native Burp UI:** Integrates seamlessly with Burp Suite, using the native **Request/Response editors** for professional traffic analysis.
* **Raw Socket Engine:** Bypasses Burp's high-level HTTP stack to ensure the smuggled payload is sent immediately and atomically, improving exploitation reliability.

---

## Installation

### Prerequisites
* **Java JDK 17+**
* **IntelliJ IDEA** (Recommended for development)
* **Gradle** (Used for building the JAR)

### Build Instructions
1.  **Execute Command:** Navigate to your project's terminal and run the build command:
    ```bash
    ./gradlew clean jar
    ```
2.  **Locate JAR:** The extension file will be generated in the `build/libs/` directory.

### Loading into Burp Suite
1.  Open Burp Suite.
2.  Navigate to **Extensions** → **Installed**.
3.  Click **Add**, set **Extension Type** to `Java`, and select the generated JAR file.
4.  A new top-level tab named **"WebSocket Smuggler"** will appear in the main Burp menu.

---

## Usage Guide (Attack Modes)

The tool operates in two modes, controlled by the **"Enable SSRF-Triggered Smuggling"** checkbox on the extension tab.

### Mode 1: Simple Smuggling (Default)

This mode tests for **naive proxies** (like Varnish) that fail to check the backend's response code for the WebSocket upgrade.

| Field | Value | Purpose |
| :--- | :--- | :--- |
| **[ ] Enable SSRF** | *(Unchecked)* | Uses Simple Mode. |
| **Simple Bait Path** | `/socket` | The backend WebSocket endpoint (the target of the initial connection). |
| **WS Version** | `777` or `13` | The version used to initiate the handshake. |
| **Smuggled Path** | `/flag` | The internal resource you are trying to access. |

> some proxies will not even require the existence of a WebSocket endpoint for this technique to work

https://github.com/user-attachments/assets/8b7b1f10-ec1a-49ca-9bc1-fb3f994d570e

### Mode 2: SSRF-Triggered Smuggling

This mode is used to bypass **smart proxies** (like Nginx) by chaining the attack with an external SSRF vulnerability to force a valid status code.

| Field | Value | Purpose |
| :--- | :--- | :--- |
| **[x] Enable SSRF** | *(Checked)* | Activates SSRF Injection logic. |
| **SSRF Injection Path** | `/check-url?server=` | The full path up to the injected URL (e.g., must include the parameter name and the equals sign). |
| **Python Server URL** | `http://<YOUR_VPS_IP>:80` | The **external endpoint** running your custom Python script. |
| **Smuggled Path** | `/flag` | The resource to smuggle the request to. |

https://github.com/user-attachments/assets/e386c160-5f32-4d10-9e36-b0750f0896d5

#### Attacker Server Setup (Real-World)
The external server used in this mode **cannot** be Burp Collaborator or Interactsh. These tools return a static `200 OK` response, but this attack requires the proxy to see a raw `101 Switching Protocols` status code to open the tunnel.

You must use a server capable of sending this raw response, typically by running your custom Python script exposed via:
1.  **A Public VPS (e.g., AWS, DigitalOcean).**
2.  **A Tunneling Service (e.g., Ngrok or Cloudflare Tunnel).**

---

## Advanced Usage: Wordlist Fuzzing

You can now perform dictionary-based attacks to discover internal endpoints or fuzz parameters through the smuggled tunnel.

1.  **Load a Wordlist:** Click the `Load Wordlist` button and select a text file containing your payloads.
2.  **Set the Placeholder:** In the **Smuggled Path** field, use the `{PAYLOAD}` placeholder. The extension will replace this tag with each line from your wordlist.
    * *Example 1 (Endpoint Fuzzing):* `/{PAYLOAD}`
    * *Example 2 (Parameter Fuzzing):* `/admin/delete?user={PAYLOAD}`
3.  **Run Attack:** Click `Run Attack`. The extension will iterate through the list, sending a full smuggling sequence for every item.

> **Note:** Fuzzing works with both Simple Mode and SSRF Mode.

---

## Attack Controls

Long-running fuzzing attacks can be managed using the control panel:

* **Run Attack:** Starts the iteration through the loaded wordlist.
* **Pause/Resume:** Temporarily halts the attack thread without losing progress. Useful if you need to inspect results or modify network settings.
* **Stop:** Completely terminates the current attack cycle.

---

## Interpreting Results (Status Logic)

The extension analyzes the raw byte stream to determine if the connection was pipelined or smuggled.

| Status | Meaning | Verdict |
| :--- | :--- | :--- |
| **Pipelining (Safe)** | The tool detected **2 distinct HTTP responses** (e.g., `403` then `403`). This means the Frontend Proxy successfully parsed both the Upgrade request and the Smuggled request individually. | **Not Vulnerable** |
| **Potential Smuggling** | The tool detected **1 HTTP response** (typically `101 Switching Protocols`) and the socket remained open. This indicates the Frontend Proxy opened a tunnel, likely passing the second request to the backend blindly. | **Vulnerable** |
| **Single Response** | The tool received one response (e.g., `403`) and the socket closed immediately. | **Blocked/Failed** |

---

<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>
