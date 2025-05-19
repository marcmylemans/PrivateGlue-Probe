# PrivateGlue-Probe

This is a standalone network discovery tool for PrivateGlue. It can scan your local network for devices and send the results to your PrivateGlue backend for easy import.

## Features

- Scans all subnets on all network interfaces by default (wired, wireless, etc.)
- Optional ping-based discovery
- Allows specifying a custom subnet and backend URL
- Can be run as a Python script or built as a Windows executable (probe.exe)

## Usage

### 1. As a Python Script

#### Prerequisites

- Python 3.7+
- Install dependencies:

  ```powershell
  pip install -r requirements.txt
  ```

#### Run the probe

- Default (ping scan, all subnets, send to localhost backend):

  ```powershell
  python probe.py
  ```

- Scan a specific subnet:

  ```powershell
  python probe.py --subnet 192.168.1
  ```

- Specify a custom backend URL:

  ```powershell
  python probe.py --backend http://yourserver:5000/api/discovered-devices
  ```

- Combine options:

  ```powershell
  python probe.py --subnet 10.0.0 --backend http://yourserver:5000/api/discovered-devices --apikey YOUR_API_KEY
  ```

### 2. As a Standalone Executable

If you have `probe.exe` (built with PyInstaller):

- Double-click to run, or use in PowerShell/cmd with the same arguments as above:

  ```powershell
  .\probe.exe --subnet 192.168.1 --backend http://yourserver:5000/api/discovered-devices --apikey YOUR_API_KEY
  ```

## How it works

- The probe scans the network and collects device information (IP, MAC, hostname, etc.).
- It sends the results to your PrivateGlue backend at `/api/discovered-devices`.
- In the PrivateGlue web UI, you will see a notification and can import discovered devices.

## Notes

- The probe only finds devices that respond to ping. For best results, ensure devices allow ICMP (ping) requests.
- You may need to run as Administrator for best results on some networks.
- The backend URL must be reachable from the machine running the probe.

## Building the Executable (Optional)

If you want to build your own `probe.exe`:

1. Install Python and dependencies as above.
2. Install PyInstaller:

   ```powershell
   pip install pyinstaller
   ```

3. Build:

   ```powershell
   pyinstaller --onefile --name probe probe.py
   ```

4. The executable will be in the `dist` folder.

---

For more help, see the PrivateGlue documentation or contact your administrator.
