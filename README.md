# winainetmon
Windows AI network Monitor
Below is a **safe, “no-packet-capture”** Windows **.NET console app** that:

1. Detects whether the PC has internet connectivity (not just “connected to a network”)
2. Monitors **new outbound TCP connections** and prints **which process/app** opened them

It **does NOT sniff payloads** (no packet contents, no passwords, no deep inspection). It only watches connection metadata (process → remote IP:port).


## Run it

```powershell
dotnet run
```

You’ll see output like:

* `Internet: ON/OFF`
* `NEW OUTBOUND: PID 1234 (chrome)  192.168.1.50:54012 -> 142.250.72.206:443`

That “NEW OUTBOUND” line is your “new app sending data out” signal (new outbound connection metadata).

---

## Useful upgrades (if you want)

* **Show executable path** for each PID (sometimes requires admin): uncomment `p.MainModule.FileName` section.
* **Filter only new processes** (first time a PID is seen).
* **Log to file / JSON** for auditing.
* **Alerting**: if an unknown app creates a new connection, beep, toast, or write a Windows Event Log entry.
* **More accurate “internet on”**: add a lightweight HTTP HEAD probe (metadata-only) to a known endpoint if ping/DNS is unreliable in your environment.


On Windows, you can only reliably say **“which app initiated the network connection”** if you map a **socket/connection** to a **process (PID)** at (or very near) the moment the connection is created. The OS doesn’t keep a perfect “who started this HTTP request” log by default—so the usual approach is:

## The reliable method (recommended)

### 1) Watch new connections, then map connection → PID → process

Use the Windows TCP tables that include the owning PID:

* **GetExtendedTcpTable** (TCP + owning PID)
* **GetExtendedUdpTable** (UDP + owning PID)

That’s what the sample app I gave does for TCP. When you see a new connection, you grab its PID and then resolve the PID to:

* process name (`Process.GetProcessById(pid).ProcessName`)
* executable path (optional, may require admin)

This tells you which **process** owns the socket that initiated the connection.

**Limitation:** For localhost/proxy scenarios, the “initiator” may be the proxy process (browser → local proxy → internet). You’ll see the proxy PID, not the original app’s higher-level request.

---

## Built-in Windows tools (quick checks)

### Option A: Resource Monitor (GUI)

1. Start → type **Resource Monitor** → Network tab
2. Look under **TCP Connections** and **Listening Ports**
3. It shows **Image (process)**, **PID**, **Remote Address**, **Remote Port**

This is the easiest visual way.

### Option B: `netstat` (CLI)

```powershell
netstat -abno
```

* `-b` shows executable name (needs admin)
* `-o` shows PID

Then map PID → process:

```powershell
tasklist /FI "PID eq 1234"
```

### Option C: PowerShell (`Get-NetTCPConnection`)

```powershell
Get-NetTCPConnection -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess |
  Sort-Object OwningProcess
```

Then map OwningProcess → process name/path:

```powershell
Get-Process -Id 1234 | Select-Object Id,ProcessName,Path
```

---

## If you need “who initiated it” beyond the PID (hard cases)

Sometimes the PID you see is not the real “app” you care about:

### 1) Browsers & many apps use shared processes

Chrome/Edge have many processes. You’ll still get the correct PID, but you may want to map it to a tab/site—Windows won’t tell you that automatically.

### 2) Proxies/VPNs/EDR tools

If traffic goes through:

* local proxy (e.g., `zscaler`, `charles`, `fiddler`)
* VPN tunnel process
* security agent
  …then **that process owns the outbound socket**, so it looks like it “initiated” everything.

To go deeper you need higher-level telemetry.

---

## Best “deep attribution” option (still metadata-only)

### Windows Filtering Platform (WFP) / ETW

If you want higher-confidence attribution at connection creation time, use:

* **WFP callouts** (driver-level) or
* **ETW providers** (Event Tracing for Windows)

ETW can give events like connect/accept with PID and sometimes more context. This is what many security tools use.

Practical path (no driver required):

* Use **Sysmon** (from Microsoft Sysinternals) and enable network connection logging:

  * Event ID 3: Network connection (includes Image, PID, destination IP/port)

That gives you “which executable created the connection” with good fidelity.

---

## What I’d do for your console app

To make your console app better at “initiated by”:

1. **Poll more frequently** (e.g., every 250–500ms) so you don’t miss short-lived connections.
2. **Track first-seen PID** and print the executable path.
3. Add **UDP support** (many apps “phone home” via UDP: DNS, QUIC/HTTP3).
4. Detect **proxy ownership** by checking:

   * if most connections are from a known proxy process
   * if remote ports are mostly 443 but all from same PID

## TODO: Extend code to

* monitor **UDP + TCP**
* show **process path + publisher signature**
* maintain an **allowlist** and alert when a new executable talks to the internet



