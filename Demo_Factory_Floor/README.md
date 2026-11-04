# Demo Factory Floor

An interactive **3D Digital Twin & Cyber-Physical Attack Simulator** for industrial telemetry, built with **React 18**, **Three.js**, **@react-three/fiber**, and **Zustand**.

The simulator models a smart factory production environment and provides a real-time testing harness for the **Trust Analyser** ecosystem. Operators can trigger physical and cyber anomalies on individual industrial assets, dispatching live telemetry payloads directly to the Trust Analyser API (`TA_API`) to evaluate system trust scores, anomaly detection, and ledger recordings in real time.

---

## Architecture & System Context

The Factory Floor Simulator acts as an active telemetry source within the Trust Analyser architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    Demo Factory Floor                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                   3D Digital Twin                     │  │
│  │  [Robotic Arm]  [Conveyor Belt]  [CCTV]  [Mainframe]  │  │
│  └──────────────────────────┬────────────────────────────┘  │
│                             │ State change / Attack toggle  │
│  ┌──────────────────────────▼────────────────────────────┐  │
│  │             Zustand State & Telemetry Store           │  │
│  │  - Maps asset to tool JSON (ssm, atc_network, etc.)   │  │
│  │  - Injects severity (ON/OFF) & network overrides      │  │
│  │  - Packages standardized API envelope                 │  │
│  └──────────────────────────┬────────────────────────────┘  │
└─────────────────────────────┼───────────────────────────────┘
                              │ HTTP POST /submit
                              ▼
               ┌──────────────────────────────┐
               │         TA_API (FastAPI)     │
               │   - Dynamic Rule Engine      │
               │   - Trust Score Calculator   │
               │   - Telemetry Ledger Bridge  │
               └──────────────┬───────────────┘
                              │
                              ▼
               ┌──────────────────────────────┐
               │         ADI_Connector        │
               │   (Distributed Ledger / WS)  │
               └──────────────────────────────┘
```

---

## Key Features

- **Interactive 3D Digital Twin**:
  - Fully navigable 3D industrial scene with orbital camera controls (pan, zoom, rotate).
  - Procedural 3D assets: multi-axis Robotic Arm, dynamic Conveyor Belt with moving packages, motorized CCTV surveillance camera, Mainframe terminal workstation, field operator Mobile Phone, and inventory box stacks.
  - Realistic materials, ambient lighting, directional shadows, and contact shadow catchers.

- **Dual Operational Modes (Normal vs. Compromised)**:
  - **Normal Operation**: Smooth, coordinated pick-and-place kinematics for the robotic arm, steady conveyor belt transit, synchronized camera sweeping, and baseline telemetry outputs.
  - **Compromised / Malicious Mode**: Erratic, high-speed arm movements, glowing red emissive warning indicators, abnormal camera tracking, and injection of high-severity anomaly payloads.

- **Master & Asset-Level Attack Controls**:
  - Individual machine toggle switches for quick anomaly isolation.
  - **Breach Button**: Instantly triggers widespread compromised state across all machinery, injecting malicious IP destination overrides (`90.90.90.90`) and high-severity alarms.
  - **Override Button**: Instantly restores factory operations to normal baseline, resetting IP routing to trusted internal subnets (`192.168.10.10`).

- **Dynamic Telemetry Injection**:
  - Wraps industry tool telemetry schemas into standard `TA_API` submission envelopes:
    ```json
    {
      "tool_name": "atc_network",
      "time_stamp": "2026-09-15T16:00:00.000Z",
      "payload": { ... }
    }
    ```
  - Injects dynamic severity levels (`ON` / `OFF`) and supplementary details (e.g., suspicious destination IPs).

- **In-App Configuration & Payload Tester**:
  - Configurable backend target URL (default: `http://localhost:8001/submit`).
  - Asset-to-Tool mapping interface: assign any supported tool schema to any 3D asset.
  - **Manual Trigger**: Send arbitrary tool JSON payloads on demand with selectable severity levels (`OFF` normal, `ON` anomaly) and real-time HTTP response status monitoring.

- **Embedded Presentation Mode**:
  - Dedicated slide viewer tab for stakeholder demos and architecture walkthroughs.
  - Keyboard shortcut navigation (Left / Right arrow keys) with slide progress indicators.

---

## Project Structure

```
Demo_Factory_Floor/
├── public/                         # Static assets (favicons, icons)
├── src/
│   ├── assets/
│   │   ├── presentation/           # Slide deck images (Slide4.jpg – Slide8.jpg)
│   │   ├── tool_jsons/             # Pre-configured tool telemetry schemas
│   │   │   ├── acram.json          # Autonomous Cyber Risk Assessment Module
│   │   │   ├── atc_network.json    # Network Traffic & Connection telemetry
│   │   │   ├── bacon.json          # Baseline & Anomaly Configuration Observation Node
│   │   │   ├── i4ri.json           # Industry 4.0 Reliability Index
│   │   │   ├── nad.json            # Network Anomaly Detection
│   │   │   ├── rad.json            # Remote Asset Diagnostics
│   │   │   ├── sbom.json           # Software Bill of Materials & Vulnerability log
│   │   │   └── ssm.json            # System Security Monitor
│   │   ├── Logo-Telemetry.png      # Telemetry project brand asset
│   │   └── Nimbus-Logo.png         # Nimbus brand asset
│   ├── components/
│   │   ├── BoxStack.jsx            # 3D warehouse inventory geometry
│   │   ├── CCTVCamera.jsx          # 3D surveillance camera with pan animation
│   │   ├── Computer.jsx            # 3D terminal workstation & monitor
│   │   ├── ConfigPage.jsx          # Modal for endpoint configuration & manual payload tester
│   │   ├── ConveyorBelt.jsx        # 3D animated belt with looping cargo boxes
│   │   ├── MobilePhone.jsx         # 3D operator mobile smartphone
│   │   ├── Presentation.jsx        # Slide presentation view with keyboard controls
│   │   ├── RoboticArm.jsx          # Multi-joint articulated robot arm with normal/malicious kinematics
│   │   ├── Scene.jsx               # Three.js Canvas setup, lighting, grid, and OrbitControls
│   │   └── UI.jsx                  # Floating HUD overlay, status indicators, and control panel
│   ├── store/
│   │   └── useStore.js             # Zustand state management, asset status, and HTTP dispatch logic
│   ├── App.css                     # Component layout styles
│   ├── App.jsx                     # Root application view switcher (Simulator vs. Presentation)
│   ├── index.css                   # Global styles, glassmorphism panel styling, HUD UI tokens
│   └── main.jsx                    # React 18 DOM entry point
├── Dockerfile                      # Multi-stage production container build (Node -> Nginx)
├── eslint.config.js                # ESLint configuration
├── index.html                      # HTML document entry
├── package.json                    # Project dependencies and npm scripts
└── vite.config.js                  # Vite bundler configuration
```

---

## Supported Telemetry Schemas

The simulator comes pre-loaded with representative schemas located in `src/assets/tool_jsons/`:

| Tool Schema | Identifier | Description | Key Telemetry Attributes |
|---|---|---|---|
| **ACRAM** | `acram.json` | Autonomous Cyber Risk Assessment Module | Cyber risk scores, CVE counts, threat classifications |
| **ATC Network** | `atc_network.json` | Access & Traffic Controller | Source IP, destination IP, packet volume, protocol flags |
| **BACON** | `bacon.json` | Baseline & Anomaly Configuration Observation Node | Node configuration drift, unexpected ports, baseline deviation |
| **I4RI** | `i4ri.json` | Industry 4.0 Reliability Index | Operational uptime, motor temperature, vibration variance |
| **NAD** | `nad.json` | Network Anomaly Detector | Flow rate anomalies, unexpected ingress spikes, intrusion indicators |
| **RAD** | `rad.json` | Remote Asset Diagnostics | Firmware hash validation, peripheral health, telemetry cadence |
| **SBOM** | `sbom.json` | Software Bill of Materials Monitor | Component dependency versions, vulnerability status (CVSS) |
| **SSM** | `ssm.json` | System Security Monitor | Process integrity, privileged execution alerts, authentication logs |

When an asset is toggled in the UI, the corresponding JSON payload is fetched, adjusted for severity or IP override, stamped with the current ISO timestamp, and POSTed to the configured server URL.

---

## Getting Started

### Prerequisites

- **Node.js**: `v18.0.0` or higher
- **npm**: `v9.0.0` or higher

### Local Development

1. **Navigate to the directory**:
   ```bash
   cd Demo_Factory_Floor
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the local development server**:
   ```bash
   npm run dev
   ```

4. **Access the application**:
   Open your browser to:
   ```
   http://localhost:5173
   ```

### Available NPM Scripts

| Command | Description |
|---|---|
| `npm run dev` | Starts Vite local development server with Hot Module Replacement (HMR) |
| `npm run build` | Compiles and minifies assets into `/dist` for production deployment |
| `npm run preview` | Locally serves the production build in `/dist` for testing |
| `npm run lint` | Runs ESLint across all JSX and JS files |

---

## 3D Controls & Navigation

| Action | Control |
|---|---|
| **Rotate Scene** | Left-click + Drag |
| **Pan Camera** | Right-click + Drag (or Two-Finger Drag on trackpad) |
| **Zoom In / Out** | Mouse Wheel (or Pinch-to-zoom on trackpad) |
| **Presentation Slide Next** | Right Arrow (`→`) or click on right arrow button |
| **Presentation Slide Previous** | Left Arrow (`←`) or click on left arrow button |

---

## Connecting to Trust Analyser API

By default, the simulator attempts to send payloads to:
```
http://localhost:8001/submit
```

### Configuration Steps

1. Click the **Gear icon (⚙)** in the top-right header to open the **Configuration Modal**.
2. Update the **Server POST URL** if running `TA_API` on a different host, container network, or port (e.g., `http://192.168.1.50:8001/submit` or `http://ta-api-service:8001/submit`).
3. Under **Anomaly Mapping**, configure which JSON payload corresponds to each asset:
   - **Robotic Arm**: e.g., `ssm.json` or `i4ri.json`
   - **Conveyor Belt**: e.g., `rad.json`
   - **CCTV Camera**: e.g., `bacon.json`
   - **Mainframe**: e.g., `acram.json`
   - **Mobile Phone**: e.g., `atc_network.json`
4. Use the **Manual Trigger** utility to verify network connectivity and ensure `TA_API` responds with `200 OK`.

> **Note on CORS:** Ensure `TA_API` has CORS enabled for `http://localhost:5173` (or `*`), which is configured by default in `TA_API/api/main.py`.

---

## Docker Deployment

A production-ready, multi-stage `Dockerfile` is included to build and serve the application with high-performance Nginx.

### 1. Build the Docker Image

```bash
docker build -t demo-factory-floor:latest .
```

### 2. Run the Container

```bash
docker run -d \
  --name demo-factory-floor \
  -p 3000:80 \
  demo-factory-floor:latest
```

The application will be accessible at `http://localhost:3000`.

### 3. Multi-Stage Build Details

- **Stage 1 (`build`)**: Uses `node:18-alpine` to install dependencies and execute `npm run build` using Vite.
- **Stage 2 (`production`)**: Uses lightweight `nginx:alpine`, copies the compiled `/dist` directory into `/usr/share/nginx/html`, and serves static assets on port `80`.

---

## Technology Stack

- **Framework**: [React 18](https://react.dev/)
- **Bundler & Tooling**: [Vite](https://vitejs.dev/)
- **3D Graphics Engine**: [Three.js](https://threejs.org/)
- **React 3D Bridge**: [@react-three/fiber](https://docs.pmnd.rs/react-three-fiber)
- **3D Helpers & Controls**: [@react-three/drei](https://github.com/pmndrs/drei)
- **State Management**: [Zustand](https://github.com/pmndrs/zustand)
- **Icons**: [Lucide React](https://lucide.dev/)
- **Web Server**: [Nginx Alpine](https://hub.docker.com/_/nginx)
