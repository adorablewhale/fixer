using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

sealed class FileCheckResult {
    internal readonly Dictionary<string,string> Hashes = new Dictionary<string,string>();
    internal Dictionary<string,string> Expected;
    internal bool Standard = true;
    internal bool ModeReadable(bool kernel) { return Hashes.ContainsKey(kernel ? "kernel" : "usermode") && Hashes[kernel ? "kernel" : "usermode"] != null && (!kernel || (Hashes.ContainsKey("map") && Hashes["map"] != null)); }
    internal bool ModeMatches(bool kernel) { return ModeReadable(kernel) && Expected != null && Hashes[kernel ? "kernel" : "usermode"] == Expected[kernel ? "kernel" : "usermode"] && (!kernel || Hashes["map"] == Expected["map"]); }
    internal bool ModeReady(bool kernel) { return Expected == null ? ModeReadable(kernel) : ModeMatches(kernel); }
    internal bool Complete { get { return Hashes.Count == 3 && !Hashes.ContainsValue(null); } }
    internal bool Matches { get { return Complete && Expected != null && Expected.Count == 3 &&
        Hashes["kernel"] == Expected["kernel"] && Hashes["usermode"] == Expected["usermode"] && Hashes["map"] == Expected["map"]; } }
    internal string Summary { get { return !Standard ? "pro / beta files hashed. use your matching loader to check updates." : !Complete ? "some launch files are missing, changing or unreadable. the loader needs to check them." :
        Expected == null ? "files hashed · current release reference unavailable. the loader will check updates." :
        Matches ? "all three files match matcha's current checked release." : "an update is needed · installed files differ from the current release."; } }
}
static class FileChecks {
    internal static bool StandardEdition { get { try { return !File.Exists(Path.Combine(Program.Data,"edition.txt")) || File.ReadAllText(Path.Combine(Program.Data,"edition.txt")).Trim() != "pro-beta"; } catch(IOException) { return true; } } }
    internal static void SetStandardEdition(bool value) { Directory.CreateDirectory(Program.Data); File.WriteAllText(Path.Combine(Program.Data,"edition.txt"),value ? "standard" : "pro-beta"); }
    internal static readonly string[] Names = {"kernel", "usermode", "map"};
    internal static string Hash(string path) {
        try {
            var before = FileStamp.Read(path); if (before.Length <= 0) return null;
            string hash;
            using (var sha = SHA256.Create())
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                hash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
            return FileStamp.Read(path).Same(before) ? hash : null;
        } catch (IOException) { return null; } catch (UnauthorizedAccessException) { return null; }
    }
    internal static Dictionary<string,string> ParseReference(string raw, DateTime now) {
        var root = new JavaScriptSerializer().Deserialize<Dictionary<string,object>>(raw);
        if (!(root["ok"] is bool) || !(bool)root["ok"]) throw new InvalidDataException();
        DateTime checkedAt, upstream;
        if (!DateTime.TryParse(Convert.ToString(root["checkedAt"]), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out checkedAt) ||
            !DateTime.TryParse(Convert.ToString(root["upstreamCheckedAt"]), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out upstream) ||
            (now - checkedAt).TotalHours > 24 || checkedAt > now.AddMinutes(5) || (now - upstream).TotalMinutes > 5 || upstream > now.AddMinutes(5)) throw new InvalidDataException();
        var files = (Dictionary<string,object>)root["files"]; if (files.Count != 3) throw new InvalidDataException();
        var result = new Dictionary<string,string>();
        foreach (string name in Names) {
            var f = (Dictionary<string,object>)files[name];
            string url = "https://files.matcha.pink/normal/" + (name == "kernel" ? "kernel" : name == "usermode" ? "usermode" : "map") + ".exe";
            string hash = Convert.ToString(f["sha256"]); long size = Convert.ToInt64(f["size"]);
            if (Convert.ToString(f["url"]) != url || !System.Text.RegularExpressions.Regex.IsMatch(hash, "^[a-f0-9]{64}$") || size < 1024 || size > 128 * 1024 * 1024) throw new InvalidDataException();
            result[name] = hash;
        }
        return result;
    }
    static Dictionary<string,string> Reference() {
        try {
            var req = (HttpWebRequest)WebRequest.Create("https://adorablewhale.world/api/fixer/release");
            req.AllowAutoRedirect = false; req.Timeout = req.ReadWriteTimeout = 12000; req.UserAgent = "matcha-fixer/" + Program.Version;
            using (var response = (HttpWebResponse)req.GetResponse()) {
                if (response.StatusCode != HttpStatusCode.OK) return null;
                using (var reader = new StreamReader(response.GetResponseStream())) {
                    char[] chars = new char[4097]; int count = 0, read;
                    while (count < chars.Length && (read = reader.Read(chars, count, chars.Length - count)) > 0) count += read;
                    return count > 4096 ? null : ParseReference(new string(chars, 0, count), DateTime.UtcNow);
                }
            }
        } catch (Exception) { return null; }
    }
    internal static FileCheckResult Check(string folder, Action<string> progress) {
        var result = new FileCheckResult { Standard = StandardEdition }; var reference = Task.Run(delegate { return result.Standard ? Reference() : null; });
        var paths = new[] { Path.Combine(folder, "app.exe"), Path.Combine(folder, "usermode", "app.exe"), Path.Combine(folder, "map.exe") };
        for (int i = 0; i < Names.Length; i++) { if (progress != null) progress("checking " + Names[i] + " sha256…"); result.Hashes[Names[i]] = Hash(paths[i]); }
        if (progress != null) progress("comparing with the current release reference…");
        result.Expected = reference.Result; return result;
    }
}
