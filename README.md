# PrivateGlue Probe

A small network discovery tool for [PrivateGlue](https://github.com/marcmylemans/PrivateGlue). It finds the devices on your local network and sends the list to your PrivateGlue server, where you review it and pick what to import.

## What it does

1. Pings every address of the networks this machine is connected to.
2. For each device that answers, looks up its name (reverse DNS) and its MAC address (from the operating system's neighbour table).
3. Sends the list to PrivateGlue. Nothing is added to your inventory yet: an editor reviews the list under **Devices > Discovered** and imports what they want.

It only finds devices that answer ping. MAC addresses are only known for devices on the same network segment as the machine running the probe.

## What you need

- The address of your PrivateGlue server, as reachable from the machine that runs the probe.
- The probe API key. An administrator finds it in PrivateGlue under **Devices > Discovered > Probe set-up**. The key only allows sending a list of discovered devices. It cannot read anything.

## Run it

### Windows, without Python

Download `probe.exe` from the [latest release](https://github.com/marcmylemans/PrivateGlue-Probe/releases/latest). The release also has `probe.exe.sha256` to check the download:

```powershell
(Get-FileHash .\probe.exe -Algorithm SHA256).Hash
```

The value must match the one in `probe.exe.sha256`. Then:

```powershell
$env:PRIVATEGLUE_URL = "https://glue.example.com"
$env:PRIVATEGLUE_API_KEY = "paste-the-key-here"
.\probe.exe
```

### With Python (Windows, Linux, macOS)

Python 3.9 or newer.

```bash
pip install -r requirements.txt
export PRIVATEGLUE_URL="https://glue.example.com"
export PRIVATEGLUE_API_KEY="paste-the-key-here"
python probe.py
```

### Try it first without sending anything

```bash
python probe.py --dry-run
```

## Options

| Option | What it does |
|---|---|
| `--server URL` | PrivateGlue address. Same as the `PRIVATEGLUE_URL` variable. `--backend` is the old name and still works, with or without `/api/discovered-devices` at the end. |
| `--apikey KEY` | API key. Prefer the `PRIVATEGLUE_API_KEY` variable: a command line is visible to other users of the machine and is saved in the shell history. |
| `--subnet NET` | Network to scan, for example `192.168.1.0/24`. Can be given more than once. The old short form `192.168.1` still works. |
| `--max-hosts N` | Largest network that will be scanned. Default 1024 addresses (a /22). |
| `--workers N` | How many addresses are pinged at the same time. Default 64. |
| `--dry-run` | Scan and print the result, send nothing. Needs no server and no key. |
| `--insecure` | Do not verify the server's HTTPS certificate. Only for a self-signed certificate on your own network. |

Without `--subnet` the probe scans every home or office network (10.x.x.x, 172.16 to 172.31.x.x, 192.168.x.x) the machine is connected to, using the real network size. It never scans public addresses by itself, and it skips networks larger than `--max-hosts` with a message.

## Security

- Use `https://` for the server address whenever the probe is not on the same private network as PrivateGlue. Over plain `http` the key and the device list can be read on the way. The probe warns when you send over `http` to a public address.
- If a key may have leaked, an administrator creates a new one under **Probe set-up**. The old key stops working at once.
- Only scan networks you are allowed to scan.

## Run it on a schedule

The probe runs once and exits, so use the scheduler of the operating system.

Windows Task Scheduler: create a task that runs `probe.exe`, and set `PRIVATEGLUE_URL` and `PRIVATEGLUE_API_KEY` as environment variables of the account the task runs as.

Linux cron, every night at 02:00:

```cron
0 2 * * * PRIVATEGLUE_URL=https://glue.example.com PRIVATEGLUE_API_KEY=paste-the-key-here /usr/bin/python3 /opt/privateglue-probe/probe.py
```

Each run replaces the previous list in PrivateGlue.

## Troubleshooting

| Message | What to do |
|---|---|
| The server refused the API key | Copy the key again from Probe set-up. A new key may have been created. |
| Could not connect | Check the address and that this machine can reach the server (firewall, VPN, port). |
| The server did not answer like PrivateGlue | The address points at something else, often a reverse proxy login page. |
| 0 devices answered | Devices may block ping. On Windows, run the probe as Administrator if nothing is found at all. |
| No MAC addresses | The devices are behind a router as seen from the probe machine. Run the probe inside that network. |

## Build probe.exe yourself

```powershell
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --name probe probe.py
```

The file ends up in `dist`. The releases are built the same way by GitHub Actions (`.github/workflows/build.yml`), not on anyone's own computer.

## Development

```bash
python -m unittest discover -s tests
```
