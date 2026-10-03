using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

// Opt-in, exact-path IFEO filter. No startup entry, service, tray or process watcher.
static class LoaderLink {
    const string Root = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\loader.exe";
    const string Owner = "matcha-fixer-path-link-v1";
    internal static readonly string InstalledExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "matcha-fixer", "matcha-fixer.exe");
    internal static string Canonical(string path) {
        string full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\") || !String.Equals(Path.GetFileName(full), "loader.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("choose a local matcha loader.exe.");
        return full;
    }
    internal static string Id(string path) {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(Canonical(path).ToUpperInvariant()))).Replace("-", "").Substring(0, 24).ToLowerInvariant();
    }
    internal static string EventName(string path) { return "Local\\matcha-fixer-launch-" + WindowsIdentity.GetCurrent().User.Value + "-" + Id(path); }
    internal static string Quote(string value) {
        var b = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') b.Append('\\', slashes * 2 + 1); else b.Append('\\', slashes);
            b.Append(c); slashes = 0;
        }
        return b.Append('\\', slashes * 2).Append('"').ToString();
    }
    static string Debugger(string fixer) { return Quote(fixer) + " --from-loader"; }
    static bool Owned(RegistryKey key, string path, string fixer) {
        return key != null && (string)key.GetValue("MatchaFixerOwner", "") == Owner &&
            String.Equals((string)key.GetValue("FilterFullPath", ""), Canonical(path), StringComparison.OrdinalIgnoreCase) &&
            (string)key.GetValue("Debugger", "") == Debugger(fixer);
    }
    internal static bool IsLinked(string path) {
        using (var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var root = hive.OpenSubKey(Root)) return IsLinkedAt(root, path, InstalledExe);
    }
    internal static bool IsLinkedAt(RegistryKey root, string path, string fixer) {
        if (root == null || root.GetValue("Debugger") != null || Convert.ToInt32(root.GetValue("UseFilter", 0)) != 1) return false;
        using (var key = root.OpenSubKey("matcha-fixer-" + Id(path))) return Owned(key, path, fixer);
    }
    internal static void ValidateAt(RegistryKey root, string path, string fixer) {
        if (root == null) return;
        path = Canonical(path); string name = "matcha-fixer-" + Id(path);
        if (root.GetValue("Debugger") != null) throw new InvalidOperationException("another loader launch rule exists. leave it unchanged and use the fixer directly.");
        bool filtered = Convert.ToInt32(root.GetValue("UseFilter", 0)) == 1;
        if (!filtered && (root.GetValueNames().Length != 0 || root.GetSubKeyNames().Length != 0))
            throw new InvalidOperationException("existing loader options need to be preserved. use the fixer directly.");
        foreach (string child in root.GetSubKeyNames()) using (var existing = root.OpenSubKey(child)) {
            if (child == name && !Owned(existing, path, fixer)) throw new InvalidOperationException("a different launch rule uses this slot.");
            if (child != name && String.Equals(Convert.ToString(existing.GetValue("FilterFullPath")), path, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("this loader already has a different launch rule.");
        }
    }
    internal static void AddAt(RegistryKey root, string path, string fixer) {
        ValidateAt(root,path,fixer);
        path = Canonical(path); string name = "matcha-fixer-" + Id(path);
        bool filtered = Convert.ToInt32(root.GetValue("UseFilter", 0)) == 1;
        bool existed; using (var old = root.OpenSubKey(name)) existed = old != null;
        try {
            using (var key = root.CreateSubKey(name)) {
                key.SetValue("MatchaFixerOwner", Owner); key.SetValue("FilterFullPath", path);
                key.SetValue("Debugger", Debugger(fixer));
            }
            if (!filtered) { root.SetValue("MatchaFixerAddedFilter", Owner); root.SetValue("UseFilter", 1, RegistryValueKind.DWord); }
        } catch {
            // A newly-created incomplete child must not strand an unusable owned slot.
            if (!existed && root.GetSubKeyNames().Contains(name)) root.DeleteSubKeyTree(name);
            if (!filtered) RemoveAt(root,path,fixer);
            throw;
        }
    }
    internal static void RemoveAt(RegistryKey root, string path, string fixer) {
        if (root == null) return;
        string name = "matcha-fixer-" + Id(path); bool owned;
        using (var key = root.OpenSubKey(name)) owned = Owned(key, path, fixer);
        if (owned) root.DeleteSubKeyTree(name);
        if (root.GetSubKeyNames().Length == 0 && (string)root.GetValue("MatchaFixerAddedFilter", "") == Owner) {
            if (Convert.ToInt32(root.GetValue("UseFilter", 0)) == 1) root.DeleteValue("UseFilter");
            root.DeleteValue("MatchaFixerAddedFilter");
        }
    }
    internal static void Install(string path) {
        path = Canonical(path); if (!File.Exists(path)) throw new FileNotFoundException("the selected loader is missing.");
        // Validate conflicts before installing a copy; revalidate when the registry is changed.
        using (var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var root = hive.OpenSubKey(Root)) {
            ValidateAt(root,path,InstalledExe);
        }
        string dir = Path.GetDirectoryName(InstalledExe);
        if (Directory.Exists(dir) && (File.GetAttributes(dir) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("the install folder is a link. choose the portable fixer instead.");
        string ownerFile = Path.Combine(dir,"install-owner.txt");
        if (Directory.Exists(dir) && Directory.EnumerateFileSystemEntries(dir).Any() && (!File.Exists(ownerFile) || (File.GetAttributes(ownerFile) & FileAttributes.ReparsePoint) != 0 || File.ReadAllText(ownerFile) != Owner))
            throw new InvalidOperationException("the program files folder is already occupied. leave it unchanged and use the portable fixer.");
        if (File.Exists(InstalledExe) && (File.GetAttributes(InstalledExe) & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException("the installed copy is a link. leave it unchanged.");
        string source = System.Windows.Forms.Application.ExecutablePath, sourceHash = FileChecks.Hash(source);
        if (sourceHash == null) throw new IOException("the fixer copy could not be verified. no launch rule was added.");
        Directory.CreateDirectory(dir);
        var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinUsersSid })
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), sid == WellKnownSidType.BuiltinUsersSid ? FileSystemRights.ReadAndExecute : FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        Directory.SetAccessControl(dir, security);
        if (!String.Equals(Path.GetFullPath(source), InstalledExe, StringComparison.OrdinalIgnoreCase) && sourceHash != FileChecks.Hash(InstalledExe)) {
            string temp = Path.Combine(dir, Guid.NewGuid().ToString("N") + ".tmp");
            try { File.Copy(source, temp); if(FileChecks.Hash(temp) != sourceHash) throw new IOException("the fixer changed while installing. no launch rule was added."); if (File.Exists(InstalledExe)) File.Replace(temp, InstalledExe, null); else File.Move(temp, InstalledExe); }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }
        File.WriteAllText(ownerFile,Owner);
        using (var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var root = hive.CreateSubKey(Root)) AddAt(root, path, InstalledExe);
    }
    internal static void Remove(string path) {
        using (var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) {
            using (var root = hive.OpenSubKey(Root, true)) RemoveAt(root, path, InstalledExe);
            using (var root = hive.OpenSubKey(Root)) if (root != null && root.ValueCount == 0 && root.SubKeyCount == 0) { root.Close(); hive.DeleteSubKey(Root); }
        }
    }
    internal static Process Start(string path, string[] args) {
        if (!IsLinked(path)) return Process.Start(new ProcessStartInfo(path, String.Join(" ", args.Select(Quote))) { WorkingDirectory = Path.GetDirectoryName(path), UseShellExecute = true });
        return StartDetached(path, args);
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct STARTUPINFO {
        internal int cb; internal string reserved, desktop, title; internal int x,y,width,height,xcount,ycount,fill,flags; internal short show,reserved2; internal IntPtr reservedPtr,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { internal IntPtr process, thread; internal int pid, tid; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcessW(string app, StringBuilder command, IntPtr ps, IntPtr ts, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO startup, out PROCESS_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool DebugSetProcessKillOnExit(bool kill);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool DebugActiveProcessStop(int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    // DEBUG_ONLY_THIS_PROCESS avoids reapplying IFEO. Detach before the suspended child runs.
    // No process memory access and no ongoing debugger. Tested with our own executable fixture.
    internal static Process StartDetached(string path, string[] args) {
        var startup = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)) }; PROCESS_INFORMATION info;
        var command = new StringBuilder(Quote(path) + (args.Length == 0 ? "" : " " + String.Join(" ", args.Select(Quote))));
        if (!CreateProcessW(path, command, IntPtr.Zero, IntPtr.Zero, false, 0x2 | 0x4, IntPtr.Zero, Path.GetDirectoryName(path), ref startup, out info)) throw new Win32Exception();
        bool resumed = false;
        try {
            if (!DebugSetProcessKillOnExit(false) || !DebugActiveProcessStop(info.pid)) throw new Win32Exception();
            if (ResumeThread(info.thread) == UInt32.MaxValue) throw new Win32Exception();
            resumed = true; return Process.GetProcessById(info.pid);
        } finally { if (!resumed) TerminateProcess(info.process, 1); CloseHandle(info.thread); CloseHandle(info.process); }
    }
}
