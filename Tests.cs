using System;
using System.Drawing;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Linq;
using Microsoft.Win32;

static class Tests {
    [DllImport("kernel32.dll")] static extern bool IsDebuggerPresent();
    static int checks;
    static void Check(bool condition, string name) { if (!condition) throw new Exception(name); checks++; Console.WriteLine("pass: " + name); }
    static FileStamp Stamp(long length, long time) { return new FileStamp { Length = length, WriteTicks = time, CreateTicks = 1 }; }
    static LoaderSnapshot Snapshot(int height, bool auth, long bytes, long version, DateTime now) {
        return new LoaderSnapshot { Window = new Size(380, height), AuthExists = auth, Files = new[] { Stamp(bytes, bytes), Stamp(bytes, bytes), Stamp(bytes, bytes) }, Version = Stamp(6, version), Now = now };
    }
    [STAThread] static int Main(string[] args) {
        try {
            if(args.Length == 2 && args[1] == "--test-path-filter") { VerifyWindowsFilter(args[0]); return 0; }
            if (args.Length >= 4 && args[0] == "--from-loader" && args[2] == "--launch-fixture") {
                using(var child=LoaderLink.StartDetached(args[1],args.Skip(2).ToArray())) {
                    if (!child.WaitForExit(10000)) return 1;
                    File.WriteAllText(args[3]+".hook","exact-path launch rule fired");return 0;
                }
            }
            if (args.Length >= 2 && args[0] == "--hook-fixture") {
                using(var child=LoaderLink.StartDetached(args[1],args.Skip(2).ToArray())) return child.WaitForExit(10000) ? 0 : 1;
            }
            if (args.Length >= 2 && args[0] == "--launch-fixture") {
                File.WriteAllText(args[1],new JavaScriptSerializer().Serialize(new Dictionary<string,object>{{"debugger",IsDebuggerPresent()},{"arguments",args}}));
                return 0;
            }
            Program.Logging = false;
            var now = DateTime.UtcNow; var tracker = new LoaderTracker();
            tracker.Begin(Snapshot(460, false, -1, 1, now));
            Check(tracker.Observe(Snapshot(460, false, -1, 1, now)) == Stage.SignIn, "missing auth means sign-in");
            Check(tracker.Observe(Snapshot(460, true, -1, 1, now.AddSeconds(1))) == Stage.Authenticating, "auth present means checking sign-in");
            Check(tracker.Observe(Snapshot(380, true, 100, 1, now.AddSeconds(2))) == Stage.Ready, "up-to-date path without download");
            tracker.Begin(Snapshot(460, true, -1, 1, now));
            Check(tracker.Observe(Snapshot(320, true, 10, 1, now.AddSeconds(1))) == Stage.Updating, "download starts");
            Check(tracker.Observe(Snapshot(320, true, 100, 2, now.AddSeconds(2))) == Stage.Updating, "wait for files to settle after marker");
            Check(tracker.Observe(Snapshot(320, true, 100, 2, now.AddSeconds(3))) == Stage.UpdateDone, "completion requires rewritten marker and settled files");
            var missing = Snapshot(320, true, 100, 3, now.AddSeconds(4)); missing.Files[1] = Stamp(-1, 0);
            Check(tracker.Observe(missing) == Stage.Updating, "missing usermode prevents completion");
            Check(tracker.Stalled(now.AddSeconds(35)), "stall only after inactivity threshold");
            tracker.Begin(Snapshot(320, true, 100, 2, now));
            Check(tracker.Observe(Snapshot(320, true, 100, 2, now.AddSeconds(2))) == Stage.Updating, "stale marker does not report completion when attaching");
            Check(tracker.Observe(Snapshot(500, true, 100, 2, now.AddSeconds(3))) == Stage.Starting, "unknown window is not failure");
            var scaled = Snapshot(380, true, 100, 2, now.AddSeconds(4)); scaled.Window = new Size(475,475);
            Check(tracker.Observe(scaled) == Stage.Ready, "proportional dpi scaling preserves mode detection");
            const string profile = "[Interface]\nPrivateKey = fixture\nAddress = 172.16.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = fixture\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = example:2408\n";
            string scoped = Tunnel.ScopeProfile(profile, new[] { IPAddress.Parse("104.21.73.85"), IPAddress.Parse("2606:4700::1"), IPAddress.Parse("127.0.0.1"), IPAddress.Parse("192.168.1.1") });
            Check(!scoped.Contains("0.0.0.0/0") && !scoped.Contains("::/0") && !scoped.Contains("DNS ="), "no default routes or system dns override");
            Check(scoped.Contains("104.21.73.85/32") && scoped.Contains("2606:4700::1/128") && !scoped.Contains("127.0.0.1") && !scoped.Contains("192.168.1.1"), "only public host routes");
            bool rejected = false; try { Tunnel.ScopeProfile(profile + "PostUp = unsafe\n", new[] { IPAddress.Parse("1.1.1.1") }); } catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "reject executable profile hooks");
            rejected = false; try { Tunnel.ScopeProfile(profile, new[] { IPAddress.Loopback }); } catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "no routes fails closed");
            rejected = false; try { Tunnel.ScopeProfile(profile + "[Peer]\nAllowedIPs = 0.0.0.0/0\n", new[] { IPAddress.Parse("1.1.1.1") }); } catch (InvalidOperationException) { rejected = true; }
            Check(rejected, "multiple peers rejected");
            string fixture = Path.Combine(args[0], "stamp-fixture.txt"); Directory.CreateDirectory(args[0]); File.WriteAllText(fixture, "first");
            var before = FileStamp.Read(fixture); File.WriteAllText(fixture, "larger-content");
            Check(!FileStamp.Read(fixture).Same(before), "real file growth detected"); File.Delete(fixture);
            File.WriteAllText(fixture,"abc");
            Check(FileChecks.Hash(fixture)=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "actual sha256 detects launch file contents");
            File.WriteAllText(fixture,"abd"); Check(FileChecks.Hash(fixture)!="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "same-size replacement changes sha256");
            File.Delete(fixture);Check(FileChecks.Hash(fixture)==null,"missing file is never verified");
            var referenceFiles=new Dictionary<string,object>();
            foreach(string name in FileChecks.Names)referenceFiles[name]=new Dictionary<string,object>{{"url","https://files.matcha.pink/normal/"+name+".exe"},{"sha256",new string('a',64)},{"size",4096}};
            var reference=new Dictionary<string,object>{{"ok",true},{"checkedAt",now.ToString("o")},{"upstreamCheckedAt",now.ToString("o")},{"files",referenceFiles}};
            var referenceJson=new JavaScriptSerializer();
            var expected=FileChecks.ParseReference(referenceJson.Serialize(reference),now);
            var fileResult=new FileCheckResult{Expected=expected};foreach(string name in FileChecks.Names)fileResult.Hashes[name]=new string('a',64);
            Check(fileResult.Matches,"all launch files must match the release reference");fileResult.Hashes["map"]=new string('b',64);
            Check(!fileResult.Matches,"mismatched map also requires update");
            Check(fileResult.ModeReady(false) && !fileResult.ModeReady(true),"usermode remains available when map is outdated");
            fileResult.Hashes["kernel"]=null; fileResult.Hashes["map"]=null;
            Check(fileResult.ModeReady(false) && !fileResult.ModeReadable(true),"usermode needs neither kernel nor mapper");
            fileResult.Hashes["usermode"]=new string('b',64); Check(!fileResult.ModeReady(false),"outdated usermode is unavailable with a valid reference");
            reference["checkedAt"]=now.AddDays(-2).ToString("o");rejected=false;
            try{FileChecks.ParseReference(referenceJson.Serialize(reference),now);}catch(InvalidDataException){rejected=true;}
            Check(rejected,"stale server hash reference is rejected");
            reference["checkedAt"]=now.ToString("o");((Dictionary<string,object>)referenceFiles["kernel"])["url"]="https://example.invalid/other.exe";rejected=false;
            try{FileChecks.ParseReference(referenceJson.Serialize(reference),now);}catch(InvalidDataException){rejected=true;}
            Check(rejected,"release reference cannot substitute other download urls");
            string configRoot=Path.Combine(args[0],"config-fixture-"+Guid.NewGuid().ToString("N"));
            string configs=Path.Combine(configRoot,"configurations");Directory.CreateDirectory(configs);
            File.WriteAllText(Path.Combine(configs,"first.init"),"old config");File.WriteAllText(Path.Combine(configs,"second.init"),"second config");
            File.WriteAllText(Path.Combine(configRoot,"auth.exe"),"fixture auth must survive");File.WriteAllText(Path.Combine(configs,"keep.lua"),"script");
            Directory.CreateDirectory(Path.Combine(configs,"nested"));File.WriteAllText(Path.Combine(configs,"nested","nested.init"),"nested");
            string backup=ConfigBackup.Reset(configs,Path.Combine(configRoot,"backups"));
            Check(!File.Exists(Path.Combine(configs,"first.init")) && File.ReadAllText(Path.Combine(backup,"first.init"))=="old config", "configuration reset preserves a recoverable backup");
            Check(File.ReadAllText(Path.Combine(configRoot,"auth.exe"))=="fixture auth must survive" && File.Exists(Path.Combine(configs,"keep.lua")) && File.Exists(Path.Combine(configs,"nested","nested.init")),"reset leaves auth, scripts and nested files in place");
            File.WriteAllText(Path.Combine(configs,"first.init"),"new config");
            Check(ConfigBackup.Restore(configs,backup)==1 && File.ReadAllText(Path.Combine(configs,"first.init"))=="new config" && File.Exists(Path.Combine(backup,"first.init")),"restore skips new same-name configurations and keeps skipped backups");
            Directory.Delete(configRoot,true);
            string testKey=@"Software\matcha-fixer-test-"+Guid.NewGuid().ToString("N"), loaderPath=Path.Combine(Path.GetFullPath(args[0]),"loader.exe");
            try {
                using(var root=Registry.CurrentUser.CreateSubKey(testKey)) {
                    LoaderLink.AddAt(root,loaderPath,Application.ExecutablePath);
                    Check(LoaderLink.IsLinkedAt(root,loaderPath,Application.ExecutablePath) && !LoaderLink.IsLinkedAt(root,Path.Combine(Path.GetDirectoryName(loaderPath),"other","loader.exe"),Application.ExecutablePath),"launch rule matches only the selected full loader path");
                    using(var foreign=root.CreateSubKey("foreign")){foreign.SetValue("FilterFullPath",Path.Combine(Path.GetDirectoryName(loaderPath),"other","loader.exe"));foreign.SetValue("Debugger","foreign-debugger");}
                    LoaderLink.RemoveAt(root,loaderPath,Application.ExecutablePath);
                    using(var foreign=root.OpenSubKey("foreign"))Check(foreign!=null && (string)foreign.GetValue("Debugger")=="foreign-debugger" && (int)root.GetValue("UseFilter")==1,"unlink preserves another application's filter and usefilter");
                    root.DeleteSubKey("foreign"); LoaderLink.RemoveAt(root,loaderPath,Application.ExecutablePath);
                    Check(root.ValueCount==0 && root.SubKeyCount==0,"unlink removes only the owned filter settings");
                    root.SetValue("Debugger","foreign-global");rejected=false;
                    try{LoaderLink.AddAt(root,loaderPath,Application.ExecutablePath);}catch(InvalidOperationException){rejected=true;}
                    Check(rejected && (string)root.GetValue("Debugger")=="foreign-global" && root.SubKeyCount==0,"global debugger conflicts are rejected unchanged");
                }
            }finally{Registry.CurrentUser.DeleteSubKeyTree(testKey);}
            string childOutput=Path.Combine(Path.GetFullPath(args[0]),"launch-fixture.json");
            using(var child=LoaderLink.StartDetached(Application.ExecutablePath,new[]{"--launch-fixture",childOutput,"space argument","quote\"and\\tail\\"}))
                Check(child.WaitForExit(10000),"linked loader bypass starts and exits without recursive launches");
            var childResult=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(childOutput));
            var childArguments=(System.Collections.ArrayList)childResult["arguments"];
            Check(!(bool)childResult["debugger"] && (string)childArguments[2]=="space argument" && (string)childArguments[3]=="quote\"and\\tail\\","debugger detaches before entry and forwards quoted arguments intact");File.Delete(childOutput);
            Reporting.DataDirectory = Path.Combine(args[0], "consent-fixture-" + Guid.NewGuid().ToString("N"));
            Check(!Reporting.Enabled && Reporting.NeedsChoice && !Directory.Exists(Reporting.DataDirectory), "default consent is off without creating a key or preference");
            Reporting.SetChoice(false);
            Check(!Reporting.Enabled && !Reporting.NeedsChoice, "keep local persists without enabling reporting");
            Reporting.SetChoice(true); Reporting.Stop();
            Check(Reporting.Enabled && !File.Exists(Path.Combine(Reporting.DataDirectory, "reporting-key.dpapi")), "opt-in is remembered; stopped sender generates no key");
            string consentDirectory = Reporting.DataDirectory;
            Reporting.DataDirectory = fixture; File.WriteAllText(fixture, "not a directory");
            rejected = false; try { Reporting.SetChoice(false); } catch (IOException) { rejected = true; }
            Check(rejected && !Reporting.Enabled, "opt-out still stops reporting when preferences cannot be saved");
            File.Delete(fixture); Reporting.DataDirectory = consentDirectory; Reporting.SetChoice(false);
            File.Delete(Path.Combine(consentDirectory,"reporting.json")); Directory.Delete(consentDirectory);
            var json = new JavaScriptSerializer();
            using (var rsa = Reporting.NewKey()) {
                var pub = Reporting.PublicKey(rsa);
                Check(rsa.KeySize == 2048 && pub.Count == 3 && (string)pub["e"] == "AQAB", "independent rsa key exposes only public parameters");
                byte[] plain = rsa.ExportCspBlob(true);
                byte[] protectedKey = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);
                Check(Convert.ToBase64String(protectedKey) != Convert.ToBase64String(plain) &&
                    Convert.ToBase64String(ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser)) == Convert.ToBase64String(plain), "private key encryption round trips with windows dpapi");
                string time = ((long)(DateTime.UtcNow - new DateTime(1970,1,1)).TotalSeconds).ToString();
                string raw = json.Serialize(new Dictionary<string,object> { {"policy", Reporting.Policy}, {"publicKey", pub} });
                var headers = Reporting.Sign(rsa, "/api/fixer/register", "-", raw, time, Guid.NewGuid().ToString("N"));
                var report = Reporting.Snapshot(Guid.NewGuid().ToString("N"), 1, "ready", "none", "completed", "off", "none", 20, false);
                Check(report.Count == 11 && !report.ContainsKey("key") && !report.ContainsKey("path") && !report.ContainsKey("logs"), "snapshot is limited to disclosed fields");
                string reportRaw = json.Serialize(report), id = Reporting.Id(rsa);
                Check(id.Length == 64 && Reporting.Id(rsa) == id, "installation id is derived consistently from its public key");
                var reportHeaders = Reporting.Sign(rsa, "/api/fixer/report", id, reportRaw, time, Guid.NewGuid().ToString("N"));
                Check(Convert.FromBase64String(reportHeaders["x-fixer-signature"]).Length == 256, "rsa sha256 request signature has expected size");
                rejected = false; try { Reporting.Sign(rsa, "/api/admin/fixer", id, reportRaw, time, Guid.NewGuid().ToString("N")); } catch (ArgumentException) { rejected = true; }
                Check(rejected, "client cannot sign an admin route");
                File.WriteAllText(Path.Combine(args[0], "reporting-vector.json"), json.Serialize(new Dictionary<string, object> {
                    {"registration", new Dictionary<string,object> {{"raw",raw},{"headers",headers}}},
                    {"report", new Dictionary<string,object> {{"raw",reportRaw},{"headers",reportHeaders}}}, {"installation",id} }));
            }
            Application.EnableVisualStyles();
            using (var window = new FixerWindow(true)) window.RenderPreview(args[0]);
            Check(File.Exists(Path.Combine(args[0], "Ready.png")), "ui previews rendered with no client or tunnel activity");
            using (var window = new ReportingWindow(false)) window.RenderPreview(Path.Combine(args[0], "reporting.png"));
            Check(File.Exists(Path.Combine(args[0], "reporting.png")), "lowercase consent dialog preview rendered");
            using(var window=new ConnectionWindow())window.RenderPreview(Path.Combine(args[0],"connection-checks.png"));
            using(var window=new TunnelConsentWindow("a redirect suggests a router or network filter."))window.RenderPreview(Path.Combine(args[0],"tunnel-consent.png"));
            Check(File.Exists(Path.Combine(args[0],"connection-checks.png"))&&File.Exists(Path.Combine(args[0],"tunnel-consent.png")),"repair steps and opt-in tunnel previews rendered");
            using(var window=new TroubleshootingWindow(null,delegate{return false;},delegate{},true))window.RenderPreview(Path.Combine(args[0],"troubleshooting.png"));
            Check(File.Exists(Path.Combine(args[0],"troubleshooting.png")),"troubleshooting guide preview renders without configuring the pc");
            Console.WriteLine(checks + " checks passed"); return 0;
        } catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
    static void VerifyWindowsFilter(string directory) {
        string rootPath=@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\loader.exe";
        string fixtureRoot=Path.Combine(Path.GetFullPath(directory),"hook-fixture-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixtureRoot);Directory.CreateDirectory(Path.Combine(fixtureRoot,"other"));
        string loader=Path.Combine(fixtureRoot,"loader.exe"), other=Path.Combine(fixtureRoot,"other","loader.exe");
        File.Copy(Application.ExecutablePath,loader);File.Copy(Application.ExecutablePath,other);
        using(var hive=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) {
            bool existed;using(var before=hive.OpenSubKey(rootPath))existed=before!=null;
            try {
                using(var root=hive.CreateSubKey(rootPath))LoaderLink.AddAt(root,loader,Application.ExecutablePath);
                string output=Path.Combine(fixtureRoot,"selected.json");
                using(var process=Process.Start(new ProcessStartInfo(loader,"--launch-fixture "+LoaderLink.Quote(output)+" "+LoaderLink.Quote("argument with spaces")){UseShellExecute=false}))
                    Check(process.WaitForExit(10000),"windows starts the selected loader through its exact-path rule");
                var selected=new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(File.ReadAllText(output));
                Check(File.Exists(output+".hook") && !(bool)selected["debugger"] && (string)((System.Collections.ArrayList)selected["arguments"])[2]=="argument with spaces","windows path filter fires once, detaches, and preserves arguments");
                output=Path.Combine(fixtureRoot,"other.json");
                using(var process=Process.Start(new ProcessStartInfo(other,"--launch-fixture "+LoaderLink.Quote(output)){UseShellExecute=false}))Check(process.WaitForExit(10000),"another loader.exe starts normally");
                Check(File.Exists(output) && !File.Exists(output+".hook"),"another full loader path is unaffected by the registered filter");
            } finally {
                using(var root=hive.OpenSubKey(rootPath,true))LoaderLink.RemoveAt(root,loader,Application.ExecutablePath);
                using(var root=hive.OpenSubKey(rootPath))if(!existed && root!=null && root.ValueCount==0 && root.SubKeyCount==0){root.Close();hive.DeleteSubKey(rootPath);}
                Directory.Delete(fixtureRoot,true);
            }
        }
        Console.WriteLine("4 windows launch integration checks passed; temporary filter removed");
    }
}
