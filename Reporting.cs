// Optional diagnostics. No administrator/website secret is present in this client.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

static class Reporting {
    internal const string Policy = "2026-10-03.1";
    const string Origin = "https://adorablewhale.world";
    internal const string Disclosure = "this helps adorablewhale check that matcha fixer is working and fix problems on other people's pcs.\n\n" +
        "if you share, adorablewhale.world receives run times, fixer version, windows version, launch mode, update and tunnel results, runtime, and brief error codes. " +
        "a random installation identifier groups your reports. each run expires 30 days after its last status.\n\n" +
        "no login keys, passwords, roblox identity, file paths, screenshots or logs are sent. the connection is encrypted. " +
        "you can turn sharing off or delete shared history here. keeping it local still gives you every fixer feature.";
    static readonly object sync = new object();
    static readonly SemaphoreSlim sendGate = new SemaphoreSlim(1, 1);
    static JavaScriptSerializer Json { get { return new JavaScriptSerializer(); } }
    internal static string DataDirectory = Program.Data;
    static string Preference { get { return Path.Combine(DataDirectory, "reporting.json"); } }
    static string KeyFile { get { return Path.Combine(DataDirectory, "reporting-key.dpapi"); } }
    static bool enabled, loaded, accepted, running, registered, final;
    static string delivery = "waiting for website";
    static string runId, installation, status = "started", mode = "none", update = "none", tunnel = "off", error = "none";
    static int sequence;
    static DateTime lastSent;
    static Stopwatch elapsed;
    static System.Threading.Timer timer;
    static HttpWebRequest inFlight;
    internal static bool Enabled { get { Load(); lock (sync) return enabled; } }
    internal static bool NeedsChoice { get { Load(); lock (sync) return !accepted; } }
    internal static string Delivery { get { lock (sync) return delivery; } }
    static void Load() {
        lock (sync) {
            if (loaded) return; loaded = true;
            try { var b = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(Preference));
                accepted = b.ContainsKey("policy") && Convert.ToString(b["policy"]) == Policy;
                enabled = accepted && b.ContainsKey("enabled") && b["enabled"] is bool && (bool)b["enabled"];
            } catch (Exception) { accepted = enabled = false; }
        }
    }
    internal static void SetChoice(bool share) {
        Load();
        // Opt-out takes effect immediately even if writing the preference fails.
        Stop();
        lock (sync) enabled = false;
        // Persist successfully before starting any request.
        Directory.CreateDirectory(DataDirectory);
        File.WriteAllText(Preference, Json.Serialize(new Dictionary<string, object> { { "policy", Policy }, { "enabled", share } }));
        lock (sync) { accepted = true; enabled = share; }
        if (share) Start();
    }
    internal static void Start() {
        if (!Enabled) return;
        lock (sync) {
            if (running) return;
            running = true; registered = false; final = false; sequence = 0; delivery = "waiting for website";
            runId = Guid.NewGuid().ToString("N"); elapsed = Stopwatch.StartNew(); lastSent = DateTime.MinValue;
            status = "started"; mode = update = error = "none"; tunnel = "off";
            timer = new System.Threading.Timer(delegate { Pump(); }, null, 1000, 60000);
        }
    }
    internal static void Track(Stage stage, string selectedMode) {
        if (!Enabled) return;
        lock (sync) {
            if (!running || final) return;
            switch (stage) {
                case Stage.SignIn: status = "login"; break;
                case Stage.Checking: case Stage.Authenticating: status = "checking"; break;
                case Stage.Updating: status = "updating"; update = "updating"; break;
                case Stage.UpdateDone: status = "ready"; update = "completed"; break;
                case Stage.Ready: status = "ready"; if (update != "completed") update = "already-current"; break;
                case Stage.Launched: status = "launched"; mode = selectedMode == "kernel" ? "kernel" : "usermode"; break;
                case Stage.Failed: status = "failed"; break;
                case Stage.Closed: status = "closed"; break;
                default: status = "started"; break;
            }
        }
        Pump();
    }
    internal static void TunnelResult(string result) {
        if (!Enabled || Array.IndexOf(new[] { "off", "needed", "connected", "failed", "disconnected" }, result) < 0) return;
        lock (sync) { if (!running || final) return; if (tunnel != "failed" || result != "disconnected") tunnel = result; } Pump();
    }
    internal static void Problem(string code) {
        if (!Enabled || Array.IndexOf(new[] { "connection", "loader", "launch", "tunnel", "unavailable" }, code) < 0) return;
        lock (sync) { if (!running || final) return; error = code; } Pump();
    }
    static void Pump() {
        lock (sync) {
            if (!enabled || !running || final || (DateTime.UtcNow - lastSent).TotalSeconds < 5) return;
        }
        Task.Run(delegate { return Send(false); });
    }
    internal static Task Finish() {
        lock (sync) { if (!enabled || !running) return Task.FromResult(false); final = true; }
        return Send(true);
    }
    internal static void Stop() {
        lock (sync) {
            running = false;
            if (timer != null) { timer.Dispose(); timer = null; }
            if (inFlight != null) { inFlight.Abort(); inFlight = null; }
        }
    }
    static RSACryptoServiceProvider LoadKey() {
        var rsa = NewKey();
        if (File.Exists(KeyFile)) rsa.ImportCspBlob(ProtectedData.Unprotect(File.ReadAllBytes(KeyFile), null, DataProtectionScope.CurrentUser));
        else File.WriteAllBytes(KeyFile, ProtectedData.Protect(rsa.ExportCspBlob(true), null, DataProtectionScope.CurrentUser));
        return rsa;
    }
    internal static RSACryptoServiceProvider NewKey() {
        var rsa = new RSACryptoServiceProvider(2048, new CspParameters(24)); rsa.PersistKeyInCsp = false; return rsa;
    }
    static string Base64Url(byte[] bytes) { return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
    internal static Dictionary<string, object> PublicKey(RSACryptoServiceProvider rsa) {
        var p = rsa.ExportParameters(false);
        return new Dictionary<string, object> { { "kty", "RSA" }, { "n", Base64Url(p.Modulus) }, { "e", Base64Url(p.Exponent) } };
    }
    internal static string Id(RSACryptoServiceProvider rsa) {
        var key = PublicKey(rsa);
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes("RSA\n" + key["n"] + "\n" + key["e"]))).Replace("-", "").ToLowerInvariant();
    }
    internal static Dictionary<string, string> Sign(RSACryptoServiceProvider rsa, string path, string id, string raw, string timestamp, string nonce) {
        if (path != "/api/fixer/register" && path != "/api/fixer/report" && path != "/api/fixer/delete") throw new ArgumentException("reporting route is not allowed");
        string bodyHash;
        using (var sha = SHA256.Create()) bodyHash = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(raw)));
        string message = "fixer-report-v1\nPOST\n" + Origin + path + "\n" + id + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash;
        return new Dictionary<string, string> { { "x-fixer-id", id }, { "x-fixer-time", timestamp }, { "x-fixer-nonce", nonce },
            { "x-fixer-signature", Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(message), CryptoConfig.MapNameToOID("SHA256"))) } };
    }
    static Dictionary<string, object> Post(RSACryptoServiceProvider rsa, string path, string id, Dictionary<string, object> body, string expectedRun) {
        string raw = Json.Serialize(body);
        string timestamp = ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var request = (HttpWebRequest)WebRequest.Create(Origin + path);
        request.Method = "POST"; request.ContentType = "application/json"; request.AllowAutoRedirect = false;
        request.Timeout = request.ReadWriteTimeout = 8000; request.UserAgent = "matcha-fixer/" + Program.Version;
        foreach (var header in Sign(rsa, path, id, raw, timestamp, Guid.NewGuid().ToString("N"))) request.Headers[header.Key] = header.Value;
        lock (sync) { if (expectedRun != null && (!enabled || !running || runId != expectedRun)) throw new OperationCanceledException(); inFlight = request; }
        try {
            byte[] bytes = Encoding.UTF8.GetBytes(raw); request.ContentLength = bytes.Length;
            using (var stream = request.GetRequestStream()) stream.Write(bytes, 0, bytes.Length);
            using (var response = (HttpWebResponse)request.GetResponse()) {
                if (response.StatusCode != HttpStatusCode.OK) throw new InvalidOperationException("reporting unavailable");
                using (var reader = new StreamReader(response.GetResponseStream())) {
                    char[] chars = new char[4097]; int count = 0, read;
                    while (count < chars.Length && (read = reader.Read(chars, count, chars.Length - count)) > 0) count += read;
                    if (count > 4096) throw new InvalidOperationException("invalid reporting reply");
                    var value = Json.Deserialize<Dictionary<string, object>>(new string(chars, 0, count));
                    if (!value.ContainsKey("ok") || !(value["ok"] is bool) || !(bool)value["ok"]) throw new InvalidOperationException("reporting unavailable");
                    return value;
                }
            }
        } finally { lock (sync) { if (inFlight == request) inFlight = null; } }
    }
    static async Task Send(bool ended) {
        // At most one sender. Queued work never grows with status changes.
        if (!await sendGate.WaitAsync(0)) {
            if (!ended) return;
            await sendGate.WaitAsync();
        }
        try {
            Dictionary<string, object> report;
            lock (sync) {
                if (!enabled || !running) return;
                if (!ended && (DateTime.UtcNow - lastSent).TotalSeconds < 5) return;
                lastSent = DateTime.UtcNow;
                report = Snapshot(runId, ++sequence, status, mode, update, tunnel, error, Math.Min(7 * 86400, (int)elapsed.Elapsed.TotalSeconds), ended);
            }
            await Task.Run(delegate {
                string expectedRun = (string)report["run"];
                using (var rsa = LoadKey()) {
                    installation = Id(rsa);
                    if (!registered) {
                        var reply = Post(rsa, "/api/fixer/register", "-", new Dictionary<string, object> { { "policy", Policy }, { "publicKey", PublicKey(rsa) } }, expectedRun);
                        if (Convert.ToString(reply["installation"]) != installation || Convert.ToString(reply["policy"]) != Policy) throw new InvalidOperationException("invalid registration reply");
                        lock (sync) { if (!enabled || !running || runId != expectedRun) return; registered = true; }
                    }
                    Post(rsa, "/api/fixer/report", installation, report, expectedRun);
                    lock (sync) { if (runId == expectedRun) delivery = "status shared"; }
                }
            });
        } catch (Exception) { lock (sync) delivery = "website unavailable · retrying"; /* Never log raw replies or keys. */ }
        finally { sendGate.Release(); }
    }
    internal static Dictionary<string, object> Snapshot(string run, int seq, string state, string selectedMode, string result, string tunnelResult, string code, int seconds, bool ended) {
        var version = Environment.OSVersion.Version;
        string os = version.Major >= 10 ? version.Build >= 22000 ? "windows-11" : "windows-10" : "windows";
        return new Dictionary<string, object> { { "run", run }, { "seq", seq }, { "version", Program.Version }, { "os", os },
            { "status", state }, { "mode", selectedMode }, { "update", result }, { "tunnel", tunnelResult }, { "error", code }, { "duration", seconds }, { "ended", ended } };
    }
    internal static async Task<bool> DeleteHistory() {
        SetChoice(false); // Persist opt-out before any deletion request or possible error.
        await sendGate.WaitAsync();
        try {
            if (!File.Exists(KeyFile)) return true;
            return await Task.Run(delegate {
                using (var rsa = LoadKey()) Post(rsa, "/api/fixer/delete", Id(rsa), new Dictionary<string, object>(), null);
                File.Delete(KeyFile); return true;
            });
        } catch (Exception) { return false; }
        finally { sendGate.Release(); }
    }
}

enum ReportingChoice { Cancel, Share, Local, Delete }
sealed class ReportingWindow : Form {
    internal ReportingChoice Choice = ReportingChoice.Cancel;
    internal ReportingWindow(bool shared) {
        Text = "basic diagnostics"; ClientSize = new Size(520, 470); FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false; StartPosition = FormStartPosition.CenterParent;
        BackColor = Color.FromArgb(14,18,16); ForeColor = Color.FromArgb(235,239,236); Font = new Font("Segoe UI",10);
        Controls.Add(new Label { Text = "help adorablewhale", Location = new Point(28,25), Size = new Size(464,40), Font = new Font("Segoe UI",23), ForeColor = Color.FromArgb(160,225,193) });
        Controls.Add(new Label { Text = Reporting.Disclosure, Location = new Point(30,85), Size = new Size(460,270), ForeColor = ForeColor });
        AddButton("share basic status", 30, 370, 220, ReportingChoice.Share, true);
        AddButton(shared ? "turn sharing off" : "keep local", 260, 370, 230, ReportingChoice.Local, false);
        AddButton("delete shared history", 30, 425, 220, ReportingChoice.Delete, false);
        AddButton("close", 260, 425, 230, ReportingChoice.Cancel, false);
    }
    void AddButton(string text, int x, int y, int width, ReportingChoice choice, bool primary) {
        var button = new Button { Text = text, Location = new Point(x,y), Size = new Size(width,36), FlatStyle = FlatStyle.Flat,
            BackColor = primary ? Color.FromArgb(160,225,193) : Color.FromArgb(23,29,26), ForeColor = primary ? Color.FromArgb(14,24,18) : ForeColor };
        button.FlatAppearance.BorderColor = Color.FromArgb(53,65,58);
        button.Click += delegate { Choice = choice; DialogResult = DialogResult.OK; Close(); }; Controls.Add(button);
    }
    internal void RenderPreview(string path) {
        Opacity = 0; Show(); Application.DoEvents();
        using (var bitmap = new Bitmap(Width,Height)) { DrawToBitmap(bitmap,new Rectangle(0,0,Width,Height)); bitmap.Save(path); } Hide();
    }
}
