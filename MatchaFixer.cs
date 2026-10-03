// matcha fixer 1.0.0. Starts, updates and fixes the Matcha loader by watching it from the outside:
// window size, files and processes only. Optional disclosed diagnostics never include keys or logs.
// Optional WireGuard + third-party wgcf setup is enabled with consent and disconnected when the loader is done.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
[assembly: AssemblyTitle("matcha fixer")]
[assembly: AssemblyDescription("Starts, updates and fixes the Matcha loader")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

static class Program {
    internal const string Version = "1.0.0";
    internal static readonly string Data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "matcha-fixer");
    internal static string LogPath { get { return Path.Combine(Data, "log.txt"); } }
    static readonly object logLock = new object();
    internal static bool Logging = true;
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();

    [STAThread] static void Main(string[] args) {
        SetProcessDPIAware(); Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        try {
            Directory.CreateDirectory(Data);
            if (args.Length == 2 && args[0] == "--guard") {
                int parentId;
                if (Int32.TryParse(args[1], out parentId)) {
                    try { using (var parent = Process.GetProcessById(parentId)) parent.WaitForExit(); } catch (ArgumentException) {}
                    try { Tunnel.Off(); } catch (Exception e) { Program.Log("guardian: " + e.Message); }
                }
                return;
            }
            if (Array.IndexOf(args, "--tunnel-off") >= 0) { Tunnel.Off(); return; }
            if (args.Length == 2 && args[0] == "--unlink-loader") { LoaderLink.Remove(LoaderLink.Canonical(args[1])); MessageBox.Show("loader unlinked.","matcha fixer"); return; }
            string linked = null; string[] loaderArgs = new string[0];
            if (args.Length >= 2 && args[0] == "--from-loader") {
                linked = LoaderLink.Canonical(args[1]);
                if (!LoaderLink.IsLinked(linked)) throw new InvalidOperationException("this loader's launch rule has changed. open the portable fixer and unlink the loader.");
                loaderArgs = args.Skip(2).ToArray();
            }
            bool created;
            using (var single = new Mutex(true, "Local\\matcha-fixer-" + System.Security.Principal.WindowsIdentity.GetCurrent().User.Value, out created)) {
                if (!created) {
                    if (linked != null && loaderArgs.Length == 0) {
                        try { using (var launch = EventWaitHandle.OpenExisting(LoaderLink.EventName(linked))) { launch.Set(); return; } } catch (WaitHandleCannotBeOpenedException) {}
                    }
                    MessageBox.Show("matcha fixer is already open. use its window, or close it before opening a different linked loader.", "matcha fixer"); return;
                }
                Application.Run(new FixerWindow(false,linked,loaderArgs));
            }
        } catch (Exception e) { MessageBox.Show(e.Message, "matcha fixer", MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }
    internal static void Log(string message) {
        if (!Logging) return;
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!String.IsNullOrEmpty(profile)) message = message.Replace(profile, "%USERPROFILE%");
        lock (logLock) { try { File.AppendAllText(LogPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + message + "\r\n"); } catch (IOException) {} catch (UnauthorizedAccessException) {} }
    }
    internal static string Resource(string name) { using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) using (var r = new StreamReader(s)) return r.ReadToEnd(); }
    internal static string Run(string file, string args, string input, int timeoutMs) {
        var info = new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = input != null };
        using (var p = Process.Start(info)) {
            if (input != null) { p.StandardInput.Write(input); p.StandardInput.Close(); }
            var output = p.StandardOutput.ReadToEndAsync(); var error = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs)) { try { p.Kill(); } catch (InvalidOperationException) {} throw new TimeoutException(Path.GetFileName(file) + " timed out"); }
            string result = (output.Result + error.Result).Trim();
            if (p.ExitCode != 0) throw new InvalidOperationException(Path.GetFileName(file) + " failed (" + p.ExitCode + "): " + result);
            return result;
        }
    }
    internal static string PowerShell(string script) {
        string ps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell\\v1.0\\powershell.exe");
        return Run(ps, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)), null, 120000);
    }
    internal static string Where(string exe) {
        foreach (string dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';').Concat(new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft\\WindowsApps") }))
            try { string full = Path.Combine(dir.Trim(), exe); if (File.Exists(full)) return full; } catch (ArgumentException) {}
        return null;
    }
}

// ============================== loader observation ==============================

enum Stage { Idle, Checking, Starting, SignIn, Authenticating, Updating, UpdateDone, Failed, Ready, Launched, Closed }

static class Win {
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr parent, EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern IntPtr SendMessageTimeout(IntPtr h, int msg, IntPtr w, StringBuilder l, int flags, int timeout, out IntPtr result);
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int L, T, R, B; }
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);

    static string ClassOf(IntPtr h) { var s = new StringBuilder(256); GetClassName(h, s, 256); return s.ToString(); }
    static string TextOf(IntPtr h) { var s = new StringBuilder(1024); IntPtr result; SendMessageTimeout(h, 0x000D, (IntPtr)1024, s, 2, 150, out result); return s.ToString(); }

    // Size of the visible window with this class owned by pid, or Size.Empty.
    internal static Size WindowSize(int pid, string cls) {
        Size found = Size.Empty;
        EnumWindows(delegate(IntPtr h, IntPtr l) {
            uint p; GetWindowThreadProcessId(h, out p);
            if (p == pid && IsWindowVisible(h) && ClassOf(h) == cls) { RECT r; GetWindowRect(h, out r); found = new Size(r.R - r.L, r.B - r.T); return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
    // Text of a standard message box (#32770) shown by pid, or null.
    internal static string DialogText(int pid) {
        string text = null;
        EnumWindows(delegate(IntPtr h, IntPtr l) {
            uint p; GetWindowThreadProcessId(h, out p);
            if (p != pid || !IsWindowVisible(h) || ClassOf(h) != "#32770") return true;
            var parts = new List<string>();
            EnumChildWindows(h, delegate(IntPtr c, IntPtr x) { if (ClassOf(c) == "Static") { string t = TextOf(c).Trim(); if (t.Length > 0) parts.Add(t); } return true; }, IntPtr.Zero);
            text = String.Join(" ", parts); return false;
        }, IntPtr.Zero);
        return text;
    }
    internal static string ProcessPath(Process p) {
        IntPtr h = OpenProcess(0x1000, false, p.Id); if (h == IntPtr.Zero) return null;
        try { var s = new StringBuilder(1024); int n = s.Capacity; return QueryFullProcessImageName(h, 0, s, ref n) ? s.ToString() : null; } finally { CloseHandle(h); }
    }
}

// ============================== network checks ==============================

sealed class NetReport {
    public bool Ok, DnsProblem, NameBlocked;
    public string BlockedBy, Detail;
}

static class Net {
    internal static readonly string[] Hosts = { "files.matcha.pink", "keyauth.win" };

    // Completes a TLS handshake with host (optionally at a pinned ip). Returns null when it works.
    internal static string Probe(string host, IPAddress ip) {
        try {
            if (ip == null) {
                var resolve = Task.Run(delegate { return Dns.GetHostAddresses(host); });
                if (!resolve.Wait(6000)) return "dns lookup timed out";
                var all = resolve.Result; string last = "no addresses returned";
                foreach (var address in all.OrderBy(a => a.AddressFamily != AddressFamily.InterNetwork)) {
                    last = Probe(host, address); if (last == null) return null;
                }
                return last;
            }
            using (var tcp = new TcpClient(ip.AddressFamily)) {
                var wait = tcp.BeginConnect(ip, 443, null, null);
                if (!wait.AsyncWaitHandle.WaitOne(6000)) return "connection timed out";
                tcp.EndConnect(wait); tcp.ReceiveTimeout = tcp.SendTimeout = 8000;
                using (var ssl = new SslStream(tcp.GetStream(), false)) { ssl.ReadTimeout = ssl.WriteTimeout = 8000; ssl.AuthenticateAsClient(host, null, SslProtocols.Tls12, true); return null; }
            }
        } catch (Exception e) { while (e.InnerException != null) e = e.InnerException; return e.Message.Trim(); }
    }
    // DNS over HTTPS, so the ISP or router cannot fake the answer.
    internal static List<IPAddress> Doh(string host, string type) {
        var result = new List<IPAddress>();
        foreach (string url in new[] { "https://1.1.1.1/dns-query?name=" + host + "&type=" + type, "https://dns.google/resolve?name=" + host + "&type=" + type }) {
            try {
                var req = (HttpWebRequest)WebRequest.Create(url); req.Accept = "application/dns-json"; req.Timeout = 8000; req.Proxy = null;
                using (var res = req.GetResponse()) using (var r = new StreamReader(res.GetResponseStream())) {
                    var json = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(r.ReadToEnd());
                    object answers; if (!json.TryGetValue("Answer", out answers)) continue;
                    foreach (Dictionary<string, object> a in (System.Collections.IEnumerable)answers) { IPAddress ip; if (IPAddress.TryParse(Convert.ToString(a["data"]), out ip)) result.Add(ip); }
                    if (result.Count > 0) return result;
                }
            } catch (WebException) {} catch (InvalidOperationException) {} catch (ArgumentException) {}
        }
        return result;
    }
    // Plain-HTTP request; a redirect to somewhere that is not Matcha is an ISP/router block page.
    internal static string BlockPage(string host) {
        try {
            using (var tcp = new TcpClient()) {
                var wait = tcp.BeginConnect(host, 80, null, null);
                if (!wait.AsyncWaitHandle.WaitOne(6000)) return null;
                tcp.EndConnect(wait); tcp.ReceiveTimeout = 8000;
                var s = tcp.GetStream(); byte[] req = Encoding.ASCII.GetBytes("HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"); s.Write(req, 0, req.Length);
                string head = new StreamReader(s, Encoding.ASCII).ReadToEnd();
                var m = System.Text.RegularExpressions.Regex.Match(head, @"(?im)^location:\s*(\S+)");
                Uri u; if (!m.Success || !Uri.TryCreate(m.Groups[1].Value, UriKind.Absolute, out u) || String.Equals(u.Host, host, StringComparison.OrdinalIgnoreCase)) return null;
                return u.Host;
            }
        } catch (Exception) { return null; }
    }
    internal static NetReport Check(Action<string> progress = null) {
        var report = new NetReport { Ok = true };
        var details = new List<string>();
        foreach (string host in Hosts) {
            if (progress != null) progress("checking " + host + "…");
            string error = Probe(host, null);
            if (error == null) { details.Add(host + " ok"); continue; }
            report.Ok = false; details.Add(host + ": " + error);
            if (progress != null) progress("checking encrypted dns for " + host + "…");
            var addresses = Doh(host, "A").Concat(Doh(host, "AAAA")).ToList();
            if (addresses.Any(ip => Probe(host, ip) == null)) report.DnsProblem = true;
        }
        if (!report.Ok) report.BlockedBy = BlockPage(Hosts[0]);
        report.NameBlocked = report.BlockedBy != null;
        report.Detail = String.Join(" | ", details);
        Program.Log("network check: " + report.Detail + (report.BlockedBy != null ? " | block page: " + report.BlockedBy : ""));
        return report;
    }
    internal static string Provider(string blockHost) {
        if (blockHost == null) return null;
        if (blockHost.Contains("charter") || blockHost.Contains("cujo")) return "spectrum security shield";
        if (blockHost.Contains("xfinity") || blockHost.Contains("comcast")) return "xfinity xfi advanced security";
        if (blockHost.Contains("sky.com")) return "sky broadband shield";
        if (blockHost.Contains("opendns") || blockHost.Contains("umbrella")) return "opendns / cisco umbrella";
        return blockHost;
    }
}

// ============================== optional lightweight tunnel ==============================
// Third-party wgcf creates the account/profile. Official WireGuard runs the tunnel.
// Routes are IP based, not application based. Consent is obtained before any setup.
static class Tunnel {
    internal const string Name = "matchafixer";
    static string Dir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard"); } }
    static string WireGuard { get { return Path.Combine(Dir, "wireguard.exe"); } }
    static string Wg { get { return Path.Combine(Dir, "wg.exe"); } }
    static string Data { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "matcha-fixer-tunnel"); } }
    static string Account { get { return Path.Combine(Data, "wgcf-account.toml"); } }
    static string Profile { get { return Path.Combine(Data, "wgcf-profile.conf"); } }
    static string Config { get { return Path.Combine(Data, Name + ".conf"); } }
    static string Wgcf { get { return Path.Combine(Data, "wgcf.exe"); } }
    const string WgcfHash = "5c633e265fb969c9507b68b39c5b0762e39181ce9f578ab66cb3b4edb0696ef5";
    internal static bool IsOn {
        get { using (var service = new System.ServiceProcess.ServiceController("WireGuardTunnel$" + Name)) {
            try { return service.Status == System.ServiceProcess.ServiceControllerStatus.Running; }
            catch (InvalidOperationException) { return false; }
        } }
    }
    internal static bool IsInstalled {
        get { using (var service = new System.ServiceProcess.ServiceController("WireGuardTunnel$" + Name)) {
            try { var ignored = service.Status; return true; }
            catch (InvalidOperationException) { return false; }
        } }
    }
    static string Hash(string path) {
        using (var sha = System.Security.Cryptography.SHA256.Create())
        using (var stream = File.OpenRead(path)) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
    static void Prepare(Action<string> progress) {
        progress("preparing the private tunnel folder…");
        var info = Directory.CreateDirectory(Data);
        var acl = new System.Security.AccessControl.DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, System.Security.Principal.WellKnownSidType.LocalSystemSid })
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid, null),
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
        info.SetAccessControl(acl);
        if (!File.Exists(WireGuard) || !File.Exists(Wg)) {
            progress("installing official wireguard…");
            string winget = Program.Where("winget.exe");
            if (winget == null) throw new InvalidOperationException("winget is missing. install WireGuard from wireguard.com/install and retry.");
            Program.Run(winget, "install --id WireGuard.WireGuard --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity", null, 300000);
        }
        if (!File.Exists(WireGuard) || !File.Exists(Wg)) throw new InvalidOperationException("WireGuard installation did not complete.");
        if (!File.Exists(Wgcf) || Hash(Wgcf) != WgcfHash) {
            progress("downloading wgcf and checking its pinned sha256…");
            var req = (HttpWebRequest)WebRequest.Create("https://github.com/ViRb3/wgcf/releases/download/v2.3.0/wgcf_2.3.0_windows_amd64.exe");
            req.Timeout = 30000; req.ReadWriteTimeout = 30000; req.UserAgent = "matcha-fixer/1.0";
            string pending = Wgcf + ".download";
            using (var response = req.GetResponse())
            using (var input = response.GetResponseStream())
            using (var output = File.Create(pending)) input.CopyTo(output);
            if (Hash(pending) != WgcfHash) { File.Delete(pending); throw new InvalidOperationException("wgcf checksum did not match the pinned release."); }
            if (File.Exists(Wgcf)) File.Delete(Wgcf);
            File.Move(pending, Wgcf);
        }
        // Never log account output: wgcf can include account identifiers and license details.
        if (!File.Exists(Account)) { progress("registering the cloudflare warp account…"); RunWgcf("register --accept-tos"); }
        if (!File.Exists(Profile)) { progress("creating the wireguard profile…"); RunWgcf("generate --keepalive=25"); }
    }
    static void RunWgcf(string command) {
        try { Program.Run(Wgcf, "--config \"" + Account + "\" " + command + (command.StartsWith("generate") ? " --profile \"" + Profile + "\"" : ""), null, 60000); }
        catch (Exception) { throw new InvalidOperationException("wgcf setup failed. no tunnel was connected. see github.com/ViRb3/wgcf for registration support."); }
    }
    internal static string ScopeProfile(string source, IEnumerable<IPAddress> addresses) {
        var routes = addresses.Where(IsPublic).Distinct().Select(ip => ip + (ip.AddressFamily == AddressFamily.InterNetwork ? "/32" : "/128")).ToArray();
        if (routes.Length == 0) throw new InvalidOperationException("no public server addresses could be resolved.");
        var lines = new List<string>(); bool allowed = false; int peers = 0;
        foreach (string raw in source.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
            string line = raw.Trim(); string key = line.Split('=')[0].Trim();
            if (line.Equals("[Peer]", StringComparison.OrdinalIgnoreCase)) peers++;
            if (key.Equals("DNS", StringComparison.OrdinalIgnoreCase)) continue;
            if (key.Equals("PreUp", StringComparison.OrdinalIgnoreCase) || key.Equals("PostUp", StringComparison.OrdinalIgnoreCase)
                || key.Equals("PreDown", StringComparison.OrdinalIgnoreCase) || key.Equals("PostDown", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("profile hooks are not supported.");
            if (key.Equals("AllowedIPs", StringComparison.OrdinalIgnoreCase)) { lines.Add("AllowedIPs = " + String.Join(", ", routes)); allowed = true; }
            else lines.Add(raw);
        }
        if (peers != 1 || !allowed) throw new InvalidOperationException("expected a single-peer wgcf profile.");
        return String.Join("\r\n", lines) + "\r\n";
    }
    internal static bool IsPublic(IPAddress ip) {
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast) return false;
        var b = ip.GetAddressBytes();
        if (b.Length == 16) return !ip.IsIPv4MappedToIPv6 && (b[0] & 0xfe) != 0xfc;
        return b[0] != 0 && b[0] != 10 && b[0] != 127 && b[0] < 224
            && !(b[0] == 169 && b[1] == 254) && !(b[0] == 172 && b[1] >= 16 && b[1] <= 31) && !(b[0] == 192 && b[1] == 168);
    }
    internal static bool On(Action<string> progress = null) {
        if (progress == null) progress = delegate {};
        Prepare(progress);
        progress("resolving the addresses for matcha's hosts…");
        var addresses = new List<IPAddress>();
        foreach (string host in Net.Hosts) {
            addresses.AddRange(Net.Doh(host, "A")); addresses.AddRange(Net.Doh(host, "AAAA"));
            try { addresses.AddRange(Dns.GetHostAddresses(host)); } catch (SocketException) {}
        }
        File.WriteAllText(Config, ScopeProfile(File.ReadAllText(Profile), addresses));
        if (IsInstalled) Off();
        progress("connecting the temporary tunnel…");
        Program.Run(WireGuard, "/installtunnelservice \"" + Config + "\"", null, 30000);
        // Guardian removes only our named tunnel if the UI exits or crashes.
        using (var guardian = Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--guard " + Process.GetCurrentProcess().Id) { UseShellExecute = false, CreateNoWindow = true })) {}
        for (int i = 0; i < 20; i++) {
            progress("waiting for a working handshake · " + (i+1) + "/20…");
            if (IsOn) {
                // Generate traffic to one of the included routes before checking the handshake.
                if (Net.Probe(Net.Hosts[0], null) == null &&
                    System.Text.RegularExpressions.Regex.IsMatch(Program.Run(Wg, "show " + Name + " latest-handshakes", null, 5000), @"\s[1-9]\d*\s*$"))
                    return true;
            }
            Thread.Sleep(500);
        }
        Off(); return false;
    }
    internal static void Off() {
        if (!File.Exists(WireGuard) || !IsInstalled) return;
        Program.Run(WireGuard, "/uninstalltunnelservice " + Name, null, 30000);
        if (IsInstalled) throw new InvalidOperationException("tunnel service could not be removed. open WireGuard and disconnect matchafixer.");
        Program.Log("tunnel: disconnected");
    }
}

// ============================== read-only security review ==============================
static class Defender {
    internal static string Check(string folder) {
        string escaped = folder.Replace("'", "''");
        return Program.PowerShell("$ErrorActionPreference='Stop'; $f='" + escaped + "'; " +
            "$hits=@(Get-MpThreatDetection | Where-Object { $resources=$_.Resources; @($resources | Where-Object { $_ -like ('file:_'+$f+'\\*') -or $_ -like ('file:'+ $f+'\\*') }).Count -gt 0 }); " +
            "'detections for selected folder: '+$hits.Count");
    }
}
// ============================== window ==============================

sealed class FixerWindow : Form {
    readonly Color Ink = Color.FromArgb(235, 239, 236), Muted = Color.FromArgb(137, 148, 143), Mint = Color.FromArgb(160, 225, 193), Card = Color.FromArgb(22, 29, 25);
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
    Label heading, detail, sub, pathLabel, tunnelLabel, tunnelTitle, versionLabel, reportingLabel;
    Button primary, secondary, usermodeButton, kernelButton, closeLoaderButton;
    string folder;
    Stage stage = Stage.Closed;
    Process loader, matcha;
    string matchaMode, lastDialog;
    int progress = -1;
    bool busy, tunnelOn, closing, retryChecked, disconnecting, reportingOpen, tunnelShown;
    FileCheckResult fileCheck;
    ConnectionWindow connectionWindow;
    string lastVerification;
    Task cleanup;
    readonly LoaderTracker tracker = new LoaderTracker();
    readonly HashSet<int> existingApps = new HashSet<int>();
    DateTime nextProcessScan, loaderExitedAt;
    readonly bool preview;
    Button changeButton, reviewButton, reportingButton, logButton, sourceButton, helpButton;
    EventWaitHandle launchRequest;
    readonly bool autoStart;
    readonly string[] loaderArguments;

    string Auth { get { return @"C:\matcha\auth.exe"; } }
    string VersionFile { get { return @"C:\matcha\version.txt"; } }
    string KernelExe { get { return Path.Combine(folder ?? "", "app.exe"); } }
    string UsermodeExe { get { return Path.Combine(folder ?? "", "usermode", "app.exe"); } }
    string[] Downloads { get { return new[] { KernelExe, UsermodeExe, Path.Combine(folder ?? "", "map.exe") }; } }

    public FixerWindow(bool previewOnly = false, string selectedLoader = null, string[] arguments = null) {
        preview = previewOnly;
        autoStart = selectedLoader != null; loaderArguments = arguments ?? new string[0];
        Text = "matcha fixer"; BackColor = Color.FromArgb(14, 18, 16); ForeColor = Ink; Font = new Font("Segoe UI", 10);
        ClientSize = new Size(520, 626); MinimumSize = MaximumSize = Size; FormBorderStyle = FormBorderStyle.FixedSingle; MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen; Icon = MakeIcon(); DoubleBuffered = true;
        folder = selectedLoader == null ? FindFolder() : Path.GetDirectoryName(selectedLoader);
        BindLaunchEvent();
        BuildUI();
        timer.Interval = 500; timer.Tick += delegate { Watch(); }; if (!preview) timer.Start();
        FormClosing += OnClosing;
        FormClosed += delegate { if (launchRequest != null) launchRequest.Dispose(); };
        Shown += async delegate {
            if (preview) return;
            Program.Log("matcha fixer " + Program.Version + " started, folder: " + (folder ?? "not found"));
            await RecoverTunnel();
            var running = Process.GetProcessesByName("loader").FirstOrDefault(p => SameFile(Win.ProcessPath(p), Path.Combine(folder ?? "", "loader.exe")));
            if (running != null) Attach(running); else SetStage(Stage.Idle);
            if (Reporting.NeedsChoice) OpenReporting();
            else { Reporting.Start(); Reporting.Track(stage, matchaMode); UpdateReportingLabel(); }
            if (folder != null) {
                busy = true; Buttons(primary.Visible, usermodeButton.Visible);
                try { fileCheck = await CheckFiles(); if (stage == Stage.Idle) { SetStage(Stage.Starting); SetStage(Stage.Idle); } }
                finally { busy = false; Buttons(primary.Visible, usermodeButton.Visible); }
            }
            if (autoStart && !Alive(loader)) StartFlow(false);
        };
        SetStage(Stage.Idle);
    }

    Label LabelAt(string text, int x, int y, int w, int h, float size, Color color) {
        var l = new Label { Text = text, Location = new Point(x, y), Size = new Size(w, h), Font = new Font("Segoe UI", size), ForeColor = color, BackColor = Color.Transparent }; Controls.Add(l); return l;
    }
    Button ButtonAt(string text, int x, int y, int w, EventHandler action, bool isPrimary) {
        var b = new Button { Text = text, Location = new Point(x, y), Size = new Size(w, 38), FlatStyle = FlatStyle.Flat, BackColor = isPrimary ? Mint : Color.FromArgb(23, 29, 26), ForeColor = isPrimary ? Color.FromArgb(14, 24, 18) : Ink, Cursor = Cursors.Hand };
        b.FlatAppearance.BorderColor = Color.FromArgb(53, 65, 58); b.FlatAppearance.BorderSize = isPrimary ? 0 : 1;
        b.Click += action; Controls.Add(b); return b;
    }
    void BuildUI() {
        LabelAt("adorablewhale / windows", 28, 25, 440, 22, 9, Muted);
        LabelAt("matcha fixer", 28, 56, 440, 46, 25, Ink);
        LabelAt("updates, fixes and starts matcha for you.", 30, 109, 440, 24, 10, Muted);
        heading = LabelAt("", 52, 173, 410, 40, 23, Mint);
        detail = LabelAt("", 52, 225, 410, 44, 10, Ink);
        sub = LabelAt("", 52, 272, 410, 22, 9, Muted);
        primary = ButtonAt("start matcha", 30, 344, 196, delegate { StartFlow(false); }, true);
        secondary = ButtonAt("fix connection", 236, 344, 150, delegate { StartFlow(true); }, false);
        usermodeButton = ButtonAt("usermode", 30, 344, 150, delegate { LaunchMode(false); }, true);
        kernelButton = ButtonAt("kernel", 190, 344, 130, delegate { LaunchMode(true); }, false);
        closeLoaderButton = ButtonAt("close loader", 330, 344, 160, delegate { CloseLoader(); }, false);
        LabelAt("matcha folder", 30, 406, 440, 20, 8, Muted);
        pathLabel = LabelAt(folder ?? "not found - choose the folder with loader.exe", 30, 432, 354, 36, 9, Ink);
        changeButton = ButtonAt("change", 392, 424, 98, ChooseFolder, false);
        tunnelTitle = LabelAt("temporary connection", 30, 484, 440, 20, 8, Muted);
        tunnelLabel = LabelAt("off · optional wireguard + wgcf setup, with your confirmation.", 30, 508, 460, 36, 9, Ink);
        reportingLabel = LabelAt("sharing off · basic diagnostics stay on this pc.", 30, 561, 330, 40, 9, Ink);
        reportingButton = ButtonAt("reporting", 370, 556, 120, delegate { OpenReporting(); }, false);
        reviewButton = ButtonAt("review pc", 30, 612, 120, delegate { FullFix(); }, false);
        logButton = ButtonAt("view log", 160, 612, 120, delegate { if (File.Exists(Program.LogPath)) Process.Start("notepad.exe", "\"" + Program.LogPath + "\""); }, false);
        sourceButton = ButtonAt("view source", 290, 612, 130, delegate { OpenSource(); }, false);
        helpButton = ButtonAt("help",430,612,60,delegate { OpenHelp(); },false);
        versionLabel = LabelAt("v" + Program.Version + " · open source · mit license", 30, 660, 460, 22, 9, Muted);
        SetTunnelVisible(false);
    }
    protected override void OnPaint(PaintEventArgs e) {
        base.OnPaint(e); e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using (var b = new SolidBrush(Card)) e.Graphics.FillRectangle(b, 30, 154, 460, 170);
        using (var pen = new Pen(Color.FromArgb(48, 65, 55))) e.Graphics.DrawRectangle(pen, 30, 154, 459, 169);
        if (progress >= 0) {
            using (var b = new SolidBrush(Color.FromArgb(40, 52, 45))) e.Graphics.FillRectangle(b, 52, 302, 416, 5);
            using (var b = new SolidBrush(Mint)) e.Graphics.FillRectangle(b, 52, 302, 416 * Math.Min(progress, 100) / 100, 5);
        }
        using (var pen = new Pen(Color.FromArgb(44, 54, 48))) { e.Graphics.DrawLine(pen, 30, 396, 490, 396); e.Graphics.DrawLine(pen, 30, 476, 490, 476); if (tunnelShown) e.Graphics.DrawLine(pen, 30, 546, 490, 546); }
    }

    void SetTunnelVisible(bool visible) {
        tunnelShown = visible; tunnelTitle.Visible = tunnelLabel.Visible = visible;
        int shift = visible ? 0 : -70;
        reportingLabel.Top = 561 + shift; reportingButton.Top = 556 + shift;
        reviewButton.Top = logButton.Top = sourceButton.Top = helpButton.Top = 612 + shift; versionLabel.Top = 660 + shift;
        MinimumSize = Size.Empty; MaximumSize = Size.Empty; ClientSize = new Size(520, visible ? 696 : 626); MinimumSize = MaximumSize = Size;
        Invalidate();
    }
    void FileProgress(string text) { if (!IsDisposed) BeginInvoke((Action)delegate { detail.Text = text; }); }
    Task<FileCheckResult> CheckFiles() {
        Show("checking files…", "reading launch files and the server's current release reference.", "sha256 checks stay on this pc.");
        return Task.Run(delegate { return FileChecks.Check(folder, FileProgress); });
    }
    async Task<NetReport> CheckConnection() {
        if (connectionWindow != null && !connectionWindow.IsDisposed) connectionWindow.Close();
        connectionWindow = new ConnectionWindow(); connectionWindow.Show(this);
        Show("checking connection…", "following the loader repair checks.", "the temporary connection is offered only if hosts remain unreachable.");
        var window = connectionWindow;
        var report = await Task.Run(delegate { return RepairChecks.Run(folder, delegate(int step,string text) {
            if (!IsDisposed) BeginInvoke((Action)delegate { if (!window.IsDisposed) window.Step(step,text); detail.Text = RepairChecks.Steps[step] + " · " + text; progress = (step+1)*100/6; Invalidate(); });
        }); });
        window.Finish(report.Ok); return report;
    }
    async Task VerifyReady(Stage ready) {
        busy = true; Buttons(false,false);
        try {
            fileCheck = await CheckFiles();
            if (!fileCheck.ModeReady(false) && !fileCheck.ModeReady(true)) {
                Reporting.Problem("unavailable"); SetStage(Stage.Failed);
                detail.Text = "the launch files do not yet match the current release."; sub.Text = "retry the loader update or review windows security."; return;
            }
            SetStage(ready);
            if (fileCheck.Matches) { detail.Text = "kernel, usermode and map sha256 hashes match the current release."; sub.Text = "choose a mode here, or continue inside the loader."; }
            else if (fileCheck.Expected != null) { heading.Text = "mode ready"; detail.Text = fileCheck.ModeReady(false) ? "usermode matches the current release. kernel needs attention." : "kernel and map match the current release. usermode needs attention."; sub.Text = "only the checked mode is available. help covers mapping and other issues."; }
            else { heading.Text = "loader ready"; detail.Text = fileCheck.Standard ? "the loader reports ready. the current release hash reference is unavailable." : "pro / beta: the loader reports ready. standard hashes do not apply."; sub.Text = "readable modes are available; freshness could not be independently checked."; }
        } finally { busy = false; Buttons(primary.Visible,usermodeButton.Visible); }
    }

    // ---------- stages ----------
    void Show(string h, string d, string s) { heading.Text = h; detail.Text = d; sub.Text = s ?? ""; }
    void Buttons(bool start, bool launch) {
        primary.Visible = secondary.Visible = start; usermodeButton.Visible = kernelButton.Visible = closeLoaderButton.Visible = launch;
        primary.Enabled = secondary.Enabled = !busy && !disconnecting;
        closeLoaderButton.Enabled = !busy && !disconnecting;
        usermodeButton.Enabled = !busy && !disconnecting && (fileCheck == null || fileCheck.ModeReady(false));
        kernelButton.Enabled = !busy && !disconnecting && (fileCheck == null || fileCheck.ModeReady(true));
        changeButton.Enabled = !busy && !disconnecting && loader == null && matcha == null;
        reviewButton.Enabled = !busy && !disconnecting;
        helpButton.Enabled = !busy && !disconnecting;
    }
    void SetStage(Stage next) {
        if (stage == next && next != Stage.Updating) return;
        if (stage != next) Program.Log("stage: " + stage + " -> " + next);
        stage = next;
        if (!preview) Reporting.Track(next, matchaMode);
        if (next != Stage.Updating) progress = -1;
        switch (next) {
            case Stage.Idle: Show(folder == null ? "find matcha" : fileCheck != null && fileCheck.Matches ? "up to date" : "ready", folder == null ? "choose the folder that has loader.exe." : fileCheck != null ? fileCheck.Summary : "start matcha and i'll handle updates and connection problems.", "start the loader for sign-in and mode selection."); primary.Text = "start matcha"; Buttons(true, false); break;
            case Stage.Checking: Show("checking…", "testing the connection to matcha's servers.", null); Buttons(true, false); break;
            case Stage.Starting: Show("starting…", "opening the matcha loader.", null); Buttons(false, false); break;
            case Stage.SignIn: Show("sign in", "sign in inside the loader window.", "your login file is never read or copied."); Buttons(false, false); break;
            case Stage.Authenticating: Show("authenticating…", "the loader is checking your saved sign-in.", "waiting for the next screen."); Buttons(false, false); break;
            case Stage.Updating: Show("updating…", "the loader is downloading or preparing files.", "if the loader says ready, click continue there."); Buttons(false, false); break;
            case Stage.UpdateDone: Show("update complete", "the version marker was rewritten and all files are present.", "choose a mode here, or continue inside the loader."); Buttons(false, true); StopTunnel(); break;
            case Stage.Ready: Show("up to date", "the loader is ready to launch matcha.", "choose a mode or close the loader."); Buttons(false, true); StopTunnel(); break;
            case Stage.Failed: Show("needs attention", "the loader stopped progressing. check its window.", "check the connection or retry when you're ready."); primary.Text = "retry loader"; Buttons(true, false); break;
            case Stage.Launched: Show(matchaMode + " launched", "matcha is running. you can close this fixer.", "waiting for any startup message…"); Buttons(false, false); StopTunnel(); break;
            case Stage.Closed: Show("loader closed", "the loader closed without a new matcha process.", "start it again when you're ready."); primary.Text = "start matcha"; Buttons(true, false); StopTunnel(); break;
        }
        Invalidate();
    }

    static bool SameFile(string a, string b) {
        if (String.IsNullOrEmpty(a) || String.IsNullOrEmpty(b)) return false;
        try { return String.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
        catch (ArgumentException) { return false; }
    }
    static bool Alive(Process p) {
        try { return p != null && !p.HasExited; } catch (InvalidOperationException) { return false; }
    }
    static string FindFolder() {
        var candidates = new List<string> { Application.StartupPath, Path.GetDirectoryName(Application.StartupPath), @"C:\matcha" };
        string saved = Path.Combine(Program.Data, "folder.txt");
        try { if (File.Exists(saved)) candidates.Insert(0, File.ReadAllText(saved).Trim()); } catch (IOException) {}
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Gaming", "Mods & Tools", "Matcha", "matcha"));
        return candidates.FirstOrDefault(p => !String.IsNullOrEmpty(p) && File.Exists(Path.Combine(p, "loader.exe")));
    }
    void ChooseFolder(object sender, EventArgs e) {
        if (busy || disconnecting || loader != null || matcha != null) return;
        using (var dialog = new OpenFileDialog { Title = "choose matcha's loader.exe", Filter = "matcha loader|loader.exe", CheckFileExists = true }) {
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            folder = Path.GetDirectoryName(dialog.FileName); pathLabel.Text = folder;
            fileCheck = null; BindLaunchEvent();
            try { File.WriteAllText(Path.Combine(Program.Data, "folder.txt"), folder); } catch (IOException ex) { Error(ex); }
            SetStage(Stage.Idle);
        }
    }
    void BaselineApps() {
        existingApps.Clear();
        foreach (var p in Process.GetProcessesByName("app")) using (p) existingApps.Add(p.Id);
    }
    void Attach(Process process) {
        if (loader != null) loader.Dispose();
        loader = process; loaderExitedAt = DateTime.MinValue; retryChecked = false; lastVerification = null;
        BaselineApps(); tracker.Begin(Snapshot(Size.Empty)); SetStage(Stage.Starting);
        Program.Log("watching loader pid=" + loader.Id);
    }
    LoaderSnapshot Snapshot(Size size) {
        return new LoaderSnapshot { Window = size, AuthExists = File.Exists(Auth),
            Files = Downloads.Select(FileStamp.Read).ToArray(), Version = FileStamp.Read(VersionFile), Now = DateTime.UtcNow };
    }
    async void StartFlow(bool fix) {
        if (busy || disconnecting) return;
        if (folder == null) { ChooseFolder(this, EventArgs.Empty); if (folder == null) return; }
        busy = true;
        try {
            if (fix) {
                SetStage(Stage.Checking);
                var report = await CheckConnection();
                if (!report.Ok) Reporting.Problem("connection");
                if (!report.Ok && !await OfferTunnel(report)) { SetStage(Stage.Failed); detail.Text = "matcha's hosts remain unreachable. the update is still blocked on this connection."; return; }
                if (report.Ok && Alive(loader)) {
                    Show("connection works", "the download and sign-in servers are reachable.", "if the loader reports failed, use retry loader."); Buttons(true, false); primary.Text = "retry loader"; return;
                }
            }
            if (Alive(loader)) {
                if (!loader.CloseMainWindow()) throw new InvalidOperationException("close the existing loader, then retry.");
                var current = loader;
                if (!await Task.Run(delegate { return current.WaitForExit(5000); })) throw new InvalidOperationException("the loader is still open. close it and retry.");
            }
            var process = LoaderLink.Start(Path.Combine(folder, "loader.exe"), loaderArguments);
            Attach(process);
        } catch (Exception ex) { Reporting.Problem("loader"); Error(ex); SetStage(Stage.Failed); }
        finally { busy = false; Buttons(primary.Visible, usermodeButton.Visible); }
    }
    async Task<bool> OfferTunnel(NetReport report) {
        if (report.Ok) return true;
        SetTunnelVisible(true); tunnelLabel.Text = "needed · matcha's hosts are still unreachable.";
        Reporting.TunnelResult("needed");
        string cause = report.NameBlocked ? "a redirect suggests a network filter (" + Net.Provider(report.BlockedBy) + ")." :
            report.DnsProblem ? "normal dns failed but encrypted dns addresses worked." : "a connection check failed; the cause is not confirmed.";
        using (var consent = new TunnelConsentWindow(cause)) { consent.ShowDialog(this); if (!consent.Accepted) return false; }
        Show("setting up tunnel…", "installing dependencies and checking the connection.", "this can take a few minutes on the first run."); Buttons(false, false);
        Exception failure;
        try {
            tunnelOn = true; // Includes partially completed setup so errors and exit still clean up.
            bool connected = await Task.Run(delegate { return Tunnel.On(FileProgress); });
            if (!connected) throw new InvalidOperationException("the tunnel did not establish a working connection.");
            var retest = await Task.Run(delegate { return Net.Check(); });
            if (!retest.Ok) throw new InvalidOperationException("the tunnel connected, but server checks still failed.");
            tunnelLabel.Text = "on · temporary routes for matcha's download and sign-in servers.";
            Reporting.TunnelResult("connected");
            Program.Log("tunnel: working handshake and server checks verified"); return true;
        } catch (Exception ex) { Reporting.TunnelResult("failed"); Reporting.Problem("tunnel"); failure = ex; }
        await DisconnectTunnel(); Error(failure); return false;
    }
    async Task RecoverTunnel() {
        busy = true; Buttons(true, false);
        try { bool recovered = await Task.Run(delegate { if (!Tunnel.IsInstalled) return false; Tunnel.Off(); return true; }); if (recovered) { SetTunnelVisible(true); tunnelLabel.Text = "off · a leftover temporary connection was disconnected."; } }
        catch (Exception ex) { Error(ex); }
        finally { busy = false; Buttons(primary.Visible, usermodeButton.Visible); }
    }
    Task DisconnectTunnel() {
        if (cleanup != null && !cleanup.IsCompleted) return cleanup;
        cleanup = DisconnectCore(); return cleanup;
    }
    async Task DisconnectCore() {
        if (!tunnelOn) return;
        disconnecting = true; Buttons(primary.Visible, usermodeButton.Visible);
        try {
            await Task.Run(delegate { Tunnel.Off(); }); tunnelOn = false;
            tunnelLabel.Text = "off · the temporary tunnel has been disconnected.";
            Reporting.TunnelResult("disconnected");
        } catch (Exception ex) {
            tunnelLabel.Text = "disconnect failed · open WireGuard and disconnect matchafixer."; Error(ex);
        }
        finally { disconnecting = false; Buttons(primary.Visible, usermodeButton.Visible); }
    }
    async void StopTunnel() { await DisconnectTunnel(); }
    async void OnClosing(object sender, FormClosingEventArgs e) {
        if (closing || preview) return;
        if (busy || disconnecting || reportingOpen) { e.Cancel = true; MessageBox.Show(this, "wait for the current operation to finish before closing.", "matcha fixer"); return; }
        timer.Stop();
        e.Cancel = true; busy = true;
        if (tunnelOn) await DisconnectTunnel();
        await Task.WhenAny(Reporting.Finish(), Task.Delay(2000));
        Reporting.Stop(); busy = false; closing = true; Close();
    }
    void Error(Exception error) {
        Program.Log("error: " + error.Message);
        if (!IsDisposed) MessageBox.Show(this, error.Message, "matcha fixer", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
    async void Watch() {
        if (!preview) UpdateReportingLabel();
        if (busy || disconnecting || preview) return;
        if (launchRequest != null && launchRequest.WaitOne(0)) {
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate(); if (!Alive(loader) && !Alive(matcha)) StartFlow(false); return;
        }
        try {
            if (DateTime.UtcNow >= nextProcessScan && loader != null && matcha == null) {
                nextProcessScan = DateTime.UtcNow.AddSeconds(1);
                foreach (var p in Process.GetProcessesByName("app")) {
                    string path = Win.ProcessPath(p);
                    if (!existingApps.Contains(p.Id) && (SameFile(path, KernelExe) || SameFile(path, UsermodeExe))) {
                        matcha = p; matchaMode = SameFile(path, UsermodeExe) ? "usermode" : "kernel";
                        SetStage(Stage.Launched); break;
                    }
                    p.Dispose();
                }
            }
            if (matcha != null) {
                if (Alive(matcha)) {
                    string dialog = Win.DialogText(matcha.Id);
                    if (!String.IsNullOrEmpty(dialog) && dialog != lastDialog) {
                        lastDialog = dialog; detail.Text = dialog;
                        sub.Text = dialog.IndexOf("Roblox", StringComparison.OrdinalIgnoreCase) >= 0 ? "open roblox, then try launching again." : "check matcha's message before continuing.";
                        Program.Log("matcha startup dialog detected");
                    }
                    if (!Alive(loader) && loader != null) { loader.Dispose(); loader = null; }
                    return;
                }
                matcha.Dispose(); matcha = null; lastDialog = null; SetStage(Stage.Closed);
            }
            if (loader == null) return;
            if (!Alive(loader)) {
                if (loaderExitedAt == DateTime.MinValue) loaderExitedAt = DateTime.UtcNow;
                // app.exe can appear just after the loader exits.
                if ((DateTime.UtcNow - loaderExitedAt).TotalSeconds > 4) { loader.Dispose(); loader = null; SetStage(Stage.Closed); }
                return;
            }
            var snapshot = Snapshot(Win.WindowSize(loader.Id, "MatchaLauncher"));
            Stage observed = tracker.Observe(snapshot);
            string fingerprint = snapshot.Version.WriteTicks + ":" + String.Join("|", snapshot.Files.Select(f => f.Length + ":" + f.WriteTicks));
            if ((observed == Stage.Ready || observed == Stage.UpdateDone) && stage != observed) {
                if (fingerprint != lastVerification) { lastVerification = fingerprint; await VerifyReady(observed); }
            }
            else if (stage != Stage.Failed || !tracker.Stalled(snapshot.Now)) SetStage(observed);
            if (stage == Stage.Updating) sub.Text = snapshot.Files.Sum(f => Math.Max(0, f.Length)).ToString("N0") + " bytes present · waiting for completion marker";
            if (tracker.Stalled(snapshot.Now) && !retryChecked && (stage == Stage.Updating || stage == Stage.Authenticating)) {
                retryChecked = true; busy = true;
                try {
                    var report = await CheckConnection();
                    if (!report.Ok) {
                        Reporting.Problem("connection"); SetStage(Stage.Failed);
                        if (await OfferTunnel(report)) { tracker.Begin(Snapshot(Size.Empty)); SetStage(Stage.Starting); detail.Text = "temporary connection is working. use retry in the loader to continue."; }
                        else { detail.Text = "matcha's hosts remain unreachable. the update stays blocked on this connection."; sub.Text = "change the network or choose fix connection to try again."; }
                    }
                    else { detail.Text = "servers are reachable. check the loader for a message or click continue if ready."; Buttons(true, false); primary.Text = "retry loader"; }
                } finally { busy = false; Buttons(primary.Visible, usermodeButton.Visible); }
            }
        } catch (Exception ex) { retryChecked = true; Error(ex); }
    }
    async void LaunchMode(bool kernel) {
        if (busy || disconnecting || (stage != Stage.Ready && stage != Stage.UpdateDone)) return;
        string exe = kernel ? KernelExe : UsermodeExe;
        if (!File.Exists(exe)) { Error(new FileNotFoundException("mode executable is missing. run the loader update first.")); return; }
        if (Process.GetProcessesByName("RobloxPlayerBeta").Length == 0 &&
            MessageBox.Show(this, "roblox is not open. launch matcha anyway?", "matcha fixer", MessageBoxButtons.YesNo) != DialogResult.Yes) return;
        busy = true;
        try {
            fileCheck = await CheckFiles();
            if (!fileCheck.ModeReady(kernel)) { SetStage(Stage.Failed); detail.Text = "the selected mode's files need attention. retry the loader update."; Error(new InvalidOperationException("this mode's files are missing, changing or differ from the checked release. retry the loader update, or use a ready mode.")); return; }
            BaselineApps();
            // Launch the same executable observed in the loader's mode captures.
            matcha = Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = Path.GetDirectoryName(exe), UseShellExecute = true });
            matchaMode = kernel ? "kernel" : "usermode"; SetStage(Stage.Launched);
            if (Alive(loader)) loader.CloseMainWindow();
            await DisconnectTunnel();
        } catch (Exception ex) { Reporting.Problem("launch"); Error(ex); }
        finally { busy = false; Buttons(primary.Visible, usermodeButton.Visible); }
    }
    void UpdateReportingLabel() {
        reportingLabel.Text = Reporting.Enabled ? "sharing on · " + Reporting.Delivery : "sharing off · basic diagnostics stay on this pc.";
    }
    async void OpenReporting() {
        if (preview || disconnecting || reportingOpen) return;
        reportingOpen = true;
        try {
        using (var dialog = new ReportingWindow(Reporting.Enabled)) {
            dialog.ShowDialog(this);
            try {
                if (dialog.Choice == ReportingChoice.Share) { Reporting.SetChoice(true); Reporting.Track(stage, matchaMode); }
                if (dialog.Choice == ReportingChoice.Local) Reporting.SetChoice(false);
                if (dialog.Choice == ReportingChoice.Delete) {
                    bool deleted = await Reporting.DeleteHistory();
                    MessageBox.Show(this, deleted ? "sharing is off and your shared history has been deleted." :
                        "sharing is off. deletion could not be confirmed; try again when the website is reachable. existing reports expire after 30 days.", "basic diagnostics");
                }
            } catch (Exception) { MessageBox.Show(this, "your choice could not be saved. sharing is off for this run. check your choice again next time.", "basic diagnostics"); }
        }
        UpdateReportingLabel();
        } finally { reportingOpen = false; }
    }
    void CloseLoader() {
        if (busy || disconnecting) return;
        if (Alive(loader) && !loader.CloseMainWindow()) { Error(new InvalidOperationException("close the loader using its window.")); return; }
    }
    async void FullFix() {
        if (busy || disconnecting) return;
        busy = true; Buttons(primary.Visible, usermodeButton.Visible);
        try {
            string result = folder == null ? "choose the matcha folder first." : await Task.Run(delegate { return Defender.Check(folder); });
            MessageBox.Show(this, result + "\n\nreview detections in windows security. connection checks are available with fix connection.", "pc review");
            Process.Start(new ProcessStartInfo("windowsdefender://threat/") { UseShellExecute = true });
        } catch (Exception ex) { Error(ex); }
        finally { busy = false; Buttons(primary.Visible, usermodeButton.Visible); }
    }
    void OpenSource() {
        try {
            string path = Path.Combine(Program.Data, "source-code.txt"); File.WriteAllText(path, Program.Resource("Source"));
            Process.Start("notepad.exe", "\"" + path + "\"");
        } catch (Exception ex) { Error(ex); }
    }
    void BindLaunchEvent() {
        if (launchRequest != null) { launchRequest.Dispose(); launchRequest = null; }
        if (!preview && folder != null) launchRequest = new EventWaitHandle(false, EventResetMode.AutoReset, LoaderLink.EventName(Path.Combine(folder,"loader.exe")));
    }
    void OpenHelp() {
        if (preview || busy || disconnecting || reportingOpen) return;
        reportingOpen = true;
        try { using (var help = new TroubleshootingWindow(folder,delegate { return Alive(loader) || Alive(matcha); },delegate { fileCheck = null; lastVerification = null; })) help.ShowDialog(this); }
        finally { reportingOpen = false; }
    }
    static Icon MakeIcon() { return Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? (Icon)SystemIcons.Application.Clone(); }
    internal void RenderPreview(string directory) {
        Directory.CreateDirectory(directory);
        Opacity = 0; Show(); Application.DoEvents();
        foreach (Stage s in new[] { Stage.Idle, Stage.SignIn, Stage.Updating, Stage.UpdateDone, Stage.Ready, Stage.Launched, Stage.Failed }) {
            matchaMode = "usermode"; SetStage(s);
            using (var bitmap = new Bitmap(Width, Height)) { DrawToBitmap(bitmap, new Rectangle(0, 0, Width, Height)); bitmap.Save(Path.Combine(directory, s + ".png")); }
        }
        Hide();
    }
}

sealed class FileStamp {
    internal long Length = -1, WriteTicks, CreateTicks;
    internal static FileStamp Read(string path) {
        try { var f = new FileInfo(path); return f.Exists ? new FileStamp { Length = f.Length, WriteTicks = f.LastWriteTimeUtc.Ticks, CreateTicks = f.CreationTimeUtc.Ticks } : new FileStamp(); }
        catch (IOException) { return new FileStamp(); } catch (UnauthorizedAccessException) { return new FileStamp(); }
    }
    internal bool Same(FileStamp other) { return other != null && Length == other.Length && WriteTicks == other.WriteTicks && CreateTicks == other.CreateTicks; }
}
sealed class LoaderSnapshot {
    internal Size Window;
    internal bool AuthExists;
    internal FileStamp[] Files;
    internal FileStamp Version;
    internal DateTime Now;
}
sealed class LoaderTracker {
    LoaderSnapshot previous;
    FileStamp versionAtStart;
    DateTime changedAt;
    internal void Begin(LoaderSnapshot snapshot) { previous = snapshot; versionAtStart = snapshot.Version; changedAt = snapshot.Now; }
    internal Stage Observe(LoaderSnapshot snapshot) {
        if (previous == null) Begin(snapshot);
        bool filesChanged = !snapshot.Files.Zip(previous.Files, (a, b) => a.Same(b)).All(same => same);
        bool screenChanged = previous.Window != snapshot.Window;
        if (filesChanged || screenChanged || previous.AuthExists != snapshot.AuthExists) changedAt = snapshot.Now;
        previous = snapshot;
        if (Near(snapshot.Window, 380, 380)) return Stage.Ready;
        if (Near(snapshot.Window, 380, 460)) return snapshot.AuthExists ? Stage.Authenticating : Stage.SignIn;
        if (Near(snapshot.Window, 380, 320)) {
            if (!snapshot.Version.Same(versionAtStart) && snapshot.Version.Length > 0 && snapshot.Files.All(f => f.Length > 0)
                && (snapshot.Now - changedAt).TotalMilliseconds >= 750) return Stage.UpdateDone;
            return Stage.Updating;
        }
        return Stage.Starting; // An unknown size is not evidence of a failed download.
    }
    internal bool Stalled(DateTime now) { return (now - changedAt).TotalSeconds > 30; }
    static bool Near(Size size, int width, int height) {
        // Also accept proportional DPI-scaled windows, within a small border tolerance.
        double scale = size.Width / (double)width;
        return scale >= 0.75 && scale <= 4 && Math.Abs(size.Height / scale - height) <= 4;
    }
}
