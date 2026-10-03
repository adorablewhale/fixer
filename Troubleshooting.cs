using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

static class ConfigBackup {
    internal static void RegularDirectory(string path) {
        for (var current = new DirectoryInfo(Path.GetFullPath(path)); current != null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("a configuration or backup folder is a link. leave it unchanged.");
    }
    internal static string Reset(string source, string backups) {
        RegularDirectory(source); RegularDirectory(backups);
        if (!Directory.Exists(source)) throw new IOException("no configuration folder was found.");
        var files = Directory.GetFiles(source, "*.init", SearchOption.TopDirectoryOnly);
        if (files.Length == 0) throw new IOException("there are no .init configurations to reset.");
        foreach (var file in files) if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("a configuration file is a link. leave it unchanged.");
        string backup = Path.Combine(backups, DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(backup); var moved = new List<string>();
        try {
            foreach (string file in files) { string target = Path.Combine(backup, Path.GetFileName(file)); File.Move(file, target); moved.Add(target); }
        } catch {
            foreach (string file in moved) if (!File.Exists(Path.Combine(source, Path.GetFileName(file)))) File.Move(file, Path.Combine(source, Path.GetFileName(file)));
            throw;
        }
        return backup;
    }
    internal static int Restore(string source, string backup) {
        RegularDirectory(source); RegularDirectory(backup); Directory.CreateDirectory(source);
        var files = Directory.GetFiles(backup, "*.init", SearchOption.TopDirectoryOnly);
        foreach (var file in files) if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("a backup file is a link. leave it unchanged.");
        int restored = 0;
        foreach (string file in files) {
            string target = Path.Combine(source, Path.GetFileName(file));
            if (!File.Exists(target)) { File.Move(file, target); restored++; }
        }
        return restored;
    }
}

static class Troubleshooting {
    internal const string RuntimeUrl = "https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist";
    internal static readonly string[] Issues = { "connection / updater / whitelist", "not live / version mismatch / not in game", "failed to map / driver blocked", "no ui / visual engine / black screen", "features / configurations / scripts", "auth / keyauth / closes early", "fps / memory / performance" };
    internal static readonly string[] Guidance = {
        "extract the loader into a normal folder before opening it. use fix connection for the visible repair checks. a tunnel is offered only if matcha's hosts remain unreachable.\r\n\r\nif sign-in still stalls with a working tunnel, a different vpn may behave differently. warp is not a guaranteed fix. review the original loader's message; successful tls does not prove downloads or authentication are healthy.",
        "join a game using the regular roblox client, then retry usermode. being open does not prove roblox is in a game. run the official matcha updater / loader to check support for the current roblox version.\r\n\r\nif a custom bootstrapper is in use, try regular roblox first. the current live deployment below is a comparison, not proof that matcha supports it. version rollout differences may need matcha support or time. use roblox's official reinstall instructions if its own installation is broken.",
        "check that your loader matches your subscription: standard, pro or beta. update through that loader. choose usermode if kernel mapping fails; it does not need map.exe.\r\n\r\na real restart can clear a previous mapping attempt. save your work and choose restart from the windows power menu. security settings below are observations, not proof of the cause. review windows security / vendor support if blocked.",
        "try usermode with roblox in windowed mode. if a runtime is missing, use microsoft's supported visual c++ installer to install or repair it. leave other runtime versions installed.\r\n\r\nreview graphics updates through windows update or your gpu manufacturer. driver cleanup utilities and disabling windows protections are not an automatic repair. if the ui appears but features fail, try the backed-up configuration reset.",
        "close matcha and the loader, then back up and reset .init configurations. sign in through the original loader and create a fresh configuration. your scripts and login file stay in place. restore skips any new configuration with the same name.\r\n\r\nif scripts still do not execute, verify the current matcha version and report the error to its support team. a configuration reset cannot guarantee a fix for a luau vm issue.",
        "check the original loader's error. run its updater if it reports a keyauth / version issue. a server-side authentication change needs matcha's support team; repeated local resets will not fix that.\r\n\r\ncheck connection, clock and installed runtimes. sign in inside the original loader; the fixer never reads or edits your credentials. an early exit alone does not prove an antivirus block. use the configuration reset only when its symptoms fit.",
        "start with matcha's own options: turn blur off, lower usage, and try vertical sync. if available, try a roblox fps cap below your monitor refresh rate.\r\n\r\ncheck windows update and your gpu driver's official updates, then restart after saving your work. high memory use can be a matcha bug; a reset is not a guaranteed cure. graphics scheduling changes require a restart and are left to windows settings."
    };
    static string Value(string path, string name) {
        try { using (var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (var key = hive.OpenSubKey(path)) return key == null || key.GetValue(name) == null ? "not explicitly configured" : Convert.ToString(key.GetValue(name)); }
        catch (Exception) { return "could not read"; }
    }
    internal static string Facts(int issue, string folder) {
        if (issue == 1) {
            var paths = new List<string>();
            foreach (var process in Process.GetProcessesByName("RobloxPlayerBeta")) using (process) {
                string path = Win.ProcessPath(process);
                if (path != null) { string parent = Path.GetFileName(Path.GetDirectoryName(path)); paths.Add(parent.StartsWith("version-", StringComparison.OrdinalIgnoreCase) ? parent : "client running outside a version folder"); }
                else paths.Add("client running · version unreadable");
            }
            string live = "live deployment unavailable";
            try {
                var request = (HttpWebRequest)WebRequest.Create("https://clientsettingscdn.roblox.com/v2/client-version/WindowsPlayer");
                request.AllowAutoRedirect = false; request.Timeout = request.ReadWriteTimeout = 6000;
                using (var response = request.GetResponse()) using (var reader = new StreamReader(response.GetResponseStream())) {
                    char[] buffer = new char[4097]; int n = 0, read;
                    while (n < buffer.Length && (read = reader.Read(buffer,n,buffer.Length-n)) > 0) n += read;
                    if (n <= 4096) { var data = new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(new string(buffer,0,n));
                        object version; if (data.TryGetValue("clientVersionUpload",out version) && System.Text.RegularExpressions.Regex.IsMatch(Convert.ToString(version), "^version-[a-fA-F0-9]{8,64}$")) live = "current live deployment: " + Convert.ToString(version); }
                }
            } catch (Exception) {}
            return "roblox: " + (paths.Count == 0 ? "not running" : String.Join(" · ",paths)) + "\r\n" + live;
        }
        if (issue == 2) return "memory integrity configured value: " + Value(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled") +
            "\r\nvulnerable driver blocklist configured value: " + Value(@"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable") +
            "\r\n1 = explicitly enabled · 0 = explicitly disabled. defaults and active policy may differ.\r\n" + (folder == null ? "choose your loader folder first." : "usermode file: " + (File.Exists(Path.Combine(folder,"usermode","app.exe")) ? "present" : "missing"));
        if (issue == 3 || issue == 5) return "visual c++ x64 runtime: " + Value(@"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64", "Version") + "\r\ninstalled metadata does not prove every runtime file is healthy.";
        if (issue == 4) return "only top-level .init files in c:\\matcha\\configurations are reset.\r\nbackups stay on this pc. auth.exe is never opened, copied or reset.";
        return "these checks and guidance stay on this pc. no logs, configurations or credentials are sent.";
    }
}

sealed class TroubleshootingWindow : Form {
    readonly string folder; readonly Func<bool> running; readonly Action editionChanged;
    readonly bool preview;
    ComboBox issue, edition; TextBox body; Button action, reset, restore, link; Label state;
    readonly string receipt = Path.Combine(Program.Data,"last-config-backup.txt");
    public TroubleshootingWindow(string selectedFolder, Func<bool> active, Action onEditionChanged, bool previewOnly = false) {
        folder = selectedFolder; running = active; editionChanged = onEditionChanged;
        preview = previewOnly;
        Text = "help with matcha"; BackColor = Color.FromArgb(14,18,16); ForeColor = Color.FromArgb(222,233,226); Font = new Font("Segoe UI",10);
        ClientSize = new Size(600,660); FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = MinimizeBox = false; StartPosition = FormStartPosition.CenterParent;
        Controls.Add(new Label { Text = "let's narrow it down", Location = new Point(24,20), Size = new Size(550,40), Font = new Font("Segoe UI",22), ForeColor = Color.FromArgb(160,225,193) });
        issue = new ComboBox { Location = new Point(24,78), Size = new Size(552,30), DropDownStyle = ComboBoxStyle.DropDownList }; issue.Items.AddRange(Troubleshooting.Issues); Controls.Add(issue);
        body = new TextBox { Location = new Point(24,122), Size = new Size(552,290), Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Color.FromArgb(23,29,26), ForeColor = ForeColor, BorderStyle = BorderStyle.FixedSingle }; Controls.Add(body);
        action = Button("open windows security",24,426,260,delegate { OpenAction(); });
        Button("done",446,426,130,delegate { Close(); });
        Controls.Add(new Label { Text = "loader edition · standard hashes apply only to standard", Location = new Point(24,480), Size = new Size(552,24) });
        edition = new ComboBox { Location = new Point(24,510), Size = new Size(260,30), DropDownStyle = ComboBoxStyle.DropDownList }; edition.Items.AddRange(new object[]{"standard", "pro / beta"}); edition.SelectedIndex = FileChecks.StandardEdition ? 0 : 1; Controls.Add(edition);
        edition.SelectedIndexChanged += delegate { try { FileChecks.SetStandardEdition(edition.SelectedIndex == 0); editionChanged(); state.Text = "edition saved · check updates through your matching loader."; } catch (Exception e) { state.Text = e.Message; } };
        link = Button("link loader",300,504,276,delegate { ChangeLink(); });
        reset = Button("back up + reset configs",24,553,260,delegate { Reset(); });
        restore = Button("restore last backup",300,553,276,delegate { Restore(); });
        state = new Label { Location = new Point(24,605), Size = new Size(552,46), Font = new Font("Segoe UI",9) }; Controls.Add(state);
        issue.SelectedIndexChanged += async delegate { await RefreshFacts(); };
        UpdateLink(); issue.SelectedIndex = 0;
    }
    Button Button(string text,int x,int y,int width,EventHandler click) {
        var b = new Button { Text=text, Location=new Point(x,y), Size=new Size(width,38), FlatStyle=FlatStyle.Flat, BackColor=Color.FromArgb(23,29,26), ForeColor=ForeColor };
        b.FlatAppearance.BorderColor=Color.FromArgb(53,65,58); b.Click+=click; Controls.Add(b); return b;
    }
    async Task RefreshFacts() {
        int selected=issue.SelectedIndex; body.Text=Troubleshooting.Guidance[selected]+"\r\n\r\nchecking…";
        action.Text=selected==1 ? "roblox reinstall help" : selected==3 || selected==5 ? "microsoft runtime repair" : selected==6 ? "open windows update" : "open windows security";
        string facts=preview ? "preview · usermode file present. security settings are reviewed in windows." : await Task.Run(delegate{return Troubleshooting.Facts(selected,folder);});
        if(!IsDisposed && issue.SelectedIndex==selected) body.Text=Troubleshooting.Guidance[selected]+"\r\n\r\n"+facts;
    }
    void OpenAction() {
        string url=issue.SelectedIndex==1 ? "https://en.help.roblox.com/hc/en-us/articles/203312910-How-to-Reinstall-the-Roblox-Software" :
            issue.SelectedIndex==3 || issue.SelectedIndex==5 ? Troubleshooting.RuntimeUrl : issue.SelectedIndex==6 ? "ms-settings:windowsupdate" : "windowsdefender://threat/";
        try { Process.Start(new ProcessStartInfo(url){UseShellExecute=true}); } catch(Exception e) { state.Text=e.Message; }
    }
    void UpdateLink() { try { link.Text=folder!=null && LoaderLink.IsLinked(Path.Combine(folder,"loader.exe")) ? "unlink loader" : "link loader"; } catch(Exception) { link.Enabled=false; } }
    void ChangeLink() {
        if(folder==null) {state.Text="choose a matcha folder first.";return;}
        try {
            string path=Path.Combine(folder,"loader.exe");
            if(LoaderLink.IsLinked(path)) { LoaderLink.Remove(path); state.Text="loader unlinked · it opens normally again."; }
            else {
                if(MessageBox.Show(this,"opening this selected loader will also open a visible fixer window. windows may ask for administrator access.\n\nthis installs a copy in program files and adds a rule for this exact loader path. it adds no tray app or startup watcher. you can undo it with unlink loader.\n\nlink this loader?","link loader",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;
                LoaderLink.Install(path); state.Text="linked · opening this loader now opens the visible fixer.";
            }
            UpdateLink();
        }catch(Exception e){state.Text=e.Message;}
    }
    void Reset() {
        if(running()){state.Text="close matcha and its loader before resetting configurations.";return;}
        if(MessageBox.Show(this,"move only .init configurations into a local backup? your current settings will be reset. scripts and sign-in stay in place.","reset configurations",MessageBoxButtons.YesNo)!=DialogResult.Yes)return;
        try { string backup=ConfigBackup.Reset(@"C:\matcha\configurations",Path.Combine(Program.Data,"config-backups")); File.WriteAllText(receipt,backup);state.Text="backed up · sign in with the loader and create a fresh configuration."; }
        catch(Exception e){state.Text=e.Message;}
    }
    void Restore() {
        if(running()){state.Text="close matcha and its loader before restoring configurations.";return;}
        try {
            string backup=File.ReadAllText(receipt).Trim(), root=Path.GetFullPath(Path.Combine(Program.Data,"config-backups"))+Path.DirectorySeparatorChar;
            if(!Path.GetFullPath(backup).StartsWith(root,StringComparison.OrdinalIgnoreCase) || Path.GetDirectoryName(Path.GetFullPath(backup))+Path.DirectorySeparatorChar!=root)throw new IOException("the backup location is invalid.");
            int count=ConfigBackup.Restore(@"C:\matcha\configurations",backup);state.Text=count+" configurations restored · existing names were left in place.";
        }catch(Exception e){state.Text=e.Message;}
    }
    internal void RenderPreview(string path) { Opacity=0;Show();issue.SelectedIndex=2;Application.DoEvents();using(var bitmap=new Bitmap(Width,Height)){DrawToBitmap(bitmap,new Rectangle(0,0,Width,Height));bitmap.Save(path);}Hide(); }
}
