using System;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.Win32;

static class RepairChecks {
    internal static readonly string[] Steps = { "folder and permissions", "system clock", "proxy and hosts file", "dns and matcha hosts", "windows security", "firewall and connection retest" };
    static string Clock() {
        var request = (HttpWebRequest)WebRequest.Create("https://www.cloudflare.com/cdn-cgi/trace"); request.Timeout = request.ReadWriteTimeout = 8000;
        using (var response = request.GetResponse()) using (var reader = new StreamReader(response.GetResponseStream())) {
            char[] chars = new char[8192]; int count = reader.ReadBlock(chars, 0, chars.Length);
            var match = Regex.Match(new string(chars,0,count), @"(?m)^ts=(\d+(?:\.\d+)?)");
            if (!match.Success) return "could not check internet time";
            var server = new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(Double.Parse(match.Groups[1].Value,CultureInfo.InvariantCulture));
            return Math.Abs((DateTime.UtcNow-server).TotalMinutes) > 5 ? "clock differs by more than five minutes · check windows time settings" : "clock matches internet time";
        }
    }
    static string ProxyAndHosts() {
        bool proxy = false;
        using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings"))
            if (key != null) proxy = Convert.ToInt32(key.GetValue("ProxyEnable",0)) == 1;
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
        bool entries = false;
        if (File.Exists(path)) foreach (string line in File.ReadLines(path)) {
            string active = line.Split('#')[0]; if (Regex.IsMatch(active,@"\b(?:matcha\.pink|keyauth\.win)\b",RegexOptions.IgnoreCase)) { entries=true;break; }
        }
        return (proxy ? "system proxy is enabled" : "no system proxy") + " · " + (entries ? "matcha entries found in hosts · review them" : "no matcha overrides in hosts");
    }
    static string Folder(string folder) {
        string test = Path.Combine(folder,"matcha-fixer-write-check-"+Guid.NewGuid().ToString("N")+".tmp");
        try { using (var stream=File.Create(test)) stream.WriteByte(1); }
        finally { if(File.Exists(test)) File.Delete(test); }
        return File.Exists(Path.Combine(folder,"loader.exe")) ? "loader found · folder is writable" : "loader.exe is missing";
    }
    static string Firewall(string folder) {
        string literal=folder.Replace("'","''");
        return Program.PowerShell("$ErrorActionPreference='Stop'; $f='"+literal+"'; $paths=@((Join-Path $f 'loader.exe'),(Join-Path $f 'app.exe'),(Join-Path $f 'usermode\\app.exe'),(Join-Path $f 'map.exe')); " +
            "$rules=@(Get-NetFirewallRule -Action Block -Enabled True -Direction Outbound | Get-NetFirewallApplicationFilter | Where-Object { $paths -contains $_.Program }); " +
            "'matching outbound block rules: '+$rules.Count; 'default outbound-block profiles: '+@(Get-NetFirewallProfile | Where-Object { $_.Enabled -and $_.DefaultOutboundAction -eq 'Block' }).Count");
    }
    static void Inspect(int step,Func<string> check,Action<int,string> progress) {
        progress(step,"checking…");
        try { progress(step,check().Trim().ToLowerInvariant()); }
        catch(Exception) { progress(step,"check unavailable · open windows settings to review"); }
    }
    internal static NetReport Run(string folder,Action<int,string> progress) {
        Inspect(0,delegate{return Folder(folder);},progress);
        Inspect(1,Clock,progress);Inspect(2,ProxyAndHosts,progress);
        progress(3,"clearing cached dns, then checking each host…");
        try { Program.Run(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"ipconfig.exe"),"/flushdns",null,15000); } catch(Exception) {}
        var first=Net.Check(delegate(string text){progress(3,text);});
        progress(3,first.Ok ? "download and sign-in hosts are reachable" : "a host is unreachable · testing encrypted dns and filter redirects");
        Inspect(4,delegate{return Defender.Check(folder);},progress);Inspect(5,delegate{return Firewall(folder);},progress);
        if(first.Ok)return first;
        progress(5,"checking the hosts again before offering a temporary connection…");
        var final=Net.Check(delegate(string text){progress(5,text);});
        progress(5,final.Ok ? "hosts are reachable · no tunnel needed" : "hosts still unreachable · temporary connection may help");
        return final;
    }
}
sealed class ConnectionWindow : Form {
    readonly Label[] steps=new Label[6]; readonly Label status;
    readonly Button close;
    internal ConnectionWindow() {
        Text="connection checks";ClientSize=new Size(570,565);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=MinimizeBox=false;ControlBox=false;StartPosition=FormStartPosition.CenterParent;
        BackColor=Color.FromArgb(14,18,16);ForeColor=Color.FromArgb(235,239,236);Font=new Font("Segoe UI",10);
        Controls.Add(new Label{Text="checking the connection",Location=new Point(28,24),Size=new Size(515,42),Font=new Font("Segoe UI",22),ForeColor=Color.FromArgb(160,225,193)});
        for(int i=0;i<steps.Length;i++){steps[i]=new Label{Text=(i+1)+". "+RepairChecks.Steps[i]+"\nwaiting",Location=new Point(30,85+i*65),Size=new Size(510,60)};Controls.Add(steps[i]);}
        status=new Label{Text="these checks help find why the loader cannot connect.",Location=new Point(30,485),Size=new Size(360,56)};Controls.Add(status);
        close=new Button{Text="close",Location=new Point(410,493),Size=new Size(130,36),Enabled=false,FlatStyle=FlatStyle.Flat};close.Click+=delegate{Close();};Controls.Add(close);
    }
    internal void Step(int index,string result){if(IsDisposed)return;steps[index].Text=(index+1)+". "+RepairChecks.Steps[index]+"\n"+result;}
    internal void Finish(bool okay){status.Text=okay?"the hosts are reachable. no tunnel is needed.":"the hosts are still unreachable. review the temporary connection option.";close.Enabled=true;}
    internal void RenderPreview(string path){Opacity=0;Show();for(int i=0;i<6;i++)Step(i,i==3?"download host unreachable · encrypted dns checked":"check complete");Finish(false);Application.DoEvents();using(var bitmap=new Bitmap(Width,Height)){DrawToBitmap(bitmap,new Rectangle(0,0,Width,Height));bitmap.Save(path);}Hide();}
}
sealed class TunnelConsentWindow : Form {
    internal bool Accepted;
    internal TunnelConsentWindow(string cause) {
        Text="temporary connection";ClientSize=new Size(550,455);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=MinimizeBox=false;StartPosition=FormStartPosition.CenterParent;
        BackColor=Color.FromArgb(14,18,16);ForeColor=Color.FromArgb(235,239,236);Font=new Font("Segoe UI",10);
        Controls.Add(new Label{Text="help the update connect",Location=new Point(28,24),Size=new Size(490,42),Font=new Font("Segoe UI",22),ForeColor=Color.FromArgb(160,225,193)});
        Controls.Add(new Label{Location=new Point(30,84),Size=new Size(490,290),Text=cause+"\n\n"+
            "the loader still cannot reach matcha's hosts. if you skip this, the update stays blocked on this connection unless the network problem is fixed another way.\n\n"+
            "connect temporarily using wireguard? if needed, this installs official wireguard and downloads third-party wgcf 2.3.0 to register a cloudflare warp account. accepting also accepts cloudflare's terms.\n\n"+
            "only matcha's resolved server addresses use the tunnel. other apps reaching those shared addresses may use it too. i'll turn it off after the update or when you close the fixer. the installed tools remain."});
        var terms=new LinkLabel{Text="cloudflare terms",Location=new Point(30,373),Size=new Size(220,24),LinkColor=Color.FromArgb(160,225,193)};terms.LinkClicked+=delegate{System.Diagnostics.Process.Start("https://www.cloudflare.com/application/terms/");};Controls.Add(terms);
        var yes=new Button{Text="connect temporarily",Location=new Point(30,410),Size=new Size(235,32),FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(160,225,193),ForeColor=BackColor};yes.Click+=delegate{Accepted=true;Close();};Controls.Add(yes);
        var no=new Button{Text="skip",Location=new Point(280,410),Size=new Size(240,32),FlatStyle=FlatStyle.Flat};no.Click+=delegate{Close();};Controls.Add(no);
    }
    internal void RenderPreview(string path){Opacity=0;Show();Application.DoEvents();using(var bitmap=new Bitmap(Width,Height)){DrawToBitmap(bitmap,new Rectangle(0,0,Width,Height));bitmap.Save(path);}Hide();}
}
