using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal class Program
{
    // -------- Settings --------
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    // A couple reliable “is internet reachable” checks (ICMP may be blocked in some networks)
    private static readonly string[] InternetProbeHosts = new[]
    {
        "1.1.1.1",        // Cloudflare DNS
        "8.8.8.8"         // Google DNS
    };

    private static async Task Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("NetMonitor (metadata-only outbound connection monitor)");
        Console.WriteLine("Press Ctrl+C to stop.\n");

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        // Connectivity events (network up/down)
        NetworkChange.NetworkAvailabilityChanged += (_, e) =>
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Network availability changed: {(e.IsAvailable ? "AVAILABLE" : "NOT AVAILABLE")}");
        };

        NetworkChange.NetworkAddressChanged += (_, __) =>
        {
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Network address changed.");
        };

        // Track outbound connections we’ve already reported
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Cache PID->process name lookups to reduce overhead
        var procNameCache = new Dictionary<int, string>();

        while (!cts.Token.IsCancellationRequested)
        {
            bool hasInternet = await HasInternetAccessAsync(cts.Token);
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] Internet: {(hasInternet ? "ON" : "OFF")}");

            // Snapshot current TCP connections
            var conns = GetAllTcpConnections();

            foreach (var c in conns)
            {
                // Focus on outbound-ish established connections (local ephemeral port -> remote)
                if (c.State != TcpState.Established)
                    continue;

                // You can filter further if desired:
                // if (c.RemoteEndPoint.Address.Equals(IPAddress.Loopback)) continue;
                // if (c.RemoteEndPoint.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;

                string key = $"{c.ProcessId}|{c.LocalEndPoint}->{c.RemoteEndPoint}|{c.State}";
                if (!seen.Add(key))
                    continue;

                string proc = GetProcessNameSafe(c.ProcessId, procNameCache);
                Console.WriteLine($"  NEW OUTBOUND: PID {c.ProcessId} ({proc})  {c.LocalEndPoint}  ->  {c.RemoteEndPoint}");
            }

            await Task.Delay(PollInterval, cts.Token);
        }

        Console.WriteLine("\nStopped.");
    }

    // -------- Internet detection --------
    private static async Task<bool> HasInternetAccessAsync(CancellationToken ct)
    {
        // Quick check: any “up” interface with a gateway?
        if (!HasUsableNetworkInterface())
            return false;

        // Probe by pinging known hosts (fast + simple). If ICMP is blocked, this may return false even if internet is OK.
        foreach (var host in InternetProbeHosts)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(host, 1200);
                if (reply.Status == IPStatus.Success)
                    return true;
            }
            catch
            {
                // ignore and try next
            }
        }

        // Fallback: DNS resolve a common hostname (often works when ICMP blocked)
        try
        {
            var _ = await Dns.GetHostEntryAsync("example.com");
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool HasUsableNetworkInterface()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up)
                continue;

            if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                continue;

            var ipProps = ni.GetIPProperties();
            if (ipProps?.GatewayAddresses == null)
                continue;

            foreach (var gw in ipProps.GatewayAddresses)
            {
                if (gw?.Address == null) continue;
                if (gw.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                    gw.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    // A gateway suggests this interface can reach beyond local link
                    return true;
                }
            }
        }
        return false;
    }

    // -------- TCP connection monitoring (GetExtendedTcpTable) --------
    private static List<TcpConnection> GetAllTcpConnections()
    {
        int bufferSize = 0;
        // First call to get required size
        uint result = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        if (result != ERROR_INSUFFICIENT_BUFFER)
            return new List<TcpConnection>();

        IntPtr buffer = IntPtr.Zero;
        try
        {
            buffer = Marshal.AllocHGlobal(bufferSize);
            result = GetExtendedTcpTable(buffer, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != NO_ERROR)
                return new List<TcpConnection>();

            // First 4 bytes: number of entries
            int numEntries = Marshal.ReadInt32(buffer);
            IntPtr rowPtr = IntPtr.Add(buffer, 4);

            var connections = new List<TcpConnection>(numEntries);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                var localIp = new IPAddress(row.localAddr);
                var remoteIp = new IPAddress(row.remoteAddr);

                int localPort = ntohs((ushort)row.localPort);
                int remotePort = ntohs((ushort)row.remotePort);

                connections.Add(new TcpConnection
                {
                    State = (TcpState)row.state,
                    ProcessId = (int)row.owningPid,
                    LocalEndPoint = new IPEndPoint(localIp, localPort),
                    RemoteEndPoint = new IPEndPoint(remoteIp, remotePort)
                });

                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }

            return connections;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
        }
    }

    private static string GetProcessNameSafe(int pid, Dictionary<int, string> cache)
    {
        if (pid <= 0) return "Unknown";

        if (cache.TryGetValue(pid, out var cached))
            return cached;

        try
        {
            using var p = Process.GetProcessById(pid);
            string name = p.ProcessName;

            // Optional: add executable path (can require extra privileges)
            // string path = p.MainModule?.FileName ?? "";
            // name = string.IsNullOrWhiteSpace(path) ? name : $"{name} ({path})";

            cache[pid] = name;
            return name;
        }
        catch
        {
            return "Unknown";
        }
    }

    // -------- Native / Interop --------
    private const int AF_INET = 2;
    private const uint NO_ERROR = 0;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TCP_TABLE_CLASS tblClass,
        uint reserved);

    // Ports are stored in network byte order
    private static int ntohs(ushort netshort)
    {
        // swap bytes
        return (netshort >> 8) | ((netshort & 0xFF) << 8);
    }

    private sealed class TcpConnection
    {
        public TcpState State { get; set; }
        public int ProcessId { get; set; }
        public IPEndPoint LocalEndPoint { get; set; } = default!;
        public IPEndPoint RemoteEndPoint { get; set; } = default!;
    }
}
