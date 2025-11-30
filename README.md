# WebSocket Smuggler (Modular)

## Overview
The **WebSocket Smuggler (Modular)** is a specialized Burp Suite extension designed to automate the detection and exploitation of **HTTP Request Smuggling** vulnerabilities that arise from faulty WebSocket connection handling by reverse proxies.

This tool is essential for testing modern applications where simple header manipulation is insufficient, focusing on attacks that require precise timing, raw socket control, or chaining with other vulnerabilities like Server-Side Request Forgery (SSRF).

---

## Key Features
* **Dual Attack Mode:** Supports two distinct types of blind smuggling attacks (Simple Desync vs. SSRF Trigger).
* **Native Burp UI:** Integrates seamlessly with Burp Suite, using the native **Request/Response editors** for professional traffic analysis.
* **Raw Socket Engine:** Bypasses Burp's high-level HTTP stack to ensure the smuggled payload is sent immediately and atomically, improving exploitation reliability.
* **Auto-Sync Feedback:** Automatically updates the viewer instantly when a test finishes, improving workflow.

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
| **WS Version** | `777` | An invalid version number designed to provoke a `426 Upgrade Required` response from the backend. |
| **Smuggled Path** | `/flag` | The internal resource you are trying to access. |

### Mode 2: SSRF-Triggered Smuggling

This mode is used to bypass **smart proxies** (like Nginx) by chaining the attack with an external SSRF vulnerability to force a valid status code.

| Field | Value | Purpose |
| :--- | :--- | :--- |
| **[x] Enable SSRF** | *(Checked)* | Activates SSRF Injection logic. |
| **SSRF Injection Path** | `/check-url?server=` | The full path up to the injected URL (e.g., must include the parameter name and the equals sign). |
| **Python Server URL** | `http://<YOUR_VPS_IP>:80` | The **external endpoint** running your custom Python script. |
| **Smuggled Path** | `/flag` | The resource to smuggle the request to. |

#### Attacker Server Setup (Real-World)
The external server used in this mode **cannot** be Burp Collaborator or Interactsh. These tools return a static `200 OK` response, but this attack requires the proxy to see a raw `101 Switching Protocols` status code to open the tunnel.

You must use a server capable of sending this raw response, typically by running your custom Python script exposed via:
1.  **A Public VPS (e.g., AWS, DigitalOcean).**
2.  **A Tunneling Service (e.g., Ngrok or Cloudflare Tunnel).**

---

## Vulnerability Analysis
The extension determines a successful smuggle by observing **two distinct HTTP responses** (the first is the Bait/101, and the second is the Smuggled Payload/200) returned over the single raw TCP connection. This confirms the Reverse Proxy has switched to blind tunneling mode.

---

## Code Structure & Contributors
The core logic is executed in the `performAttack` method, which utilizes the `java.net.Socket` class to bypass standard HTTP libraries and perform the atomic write operation necessary for the attack.
