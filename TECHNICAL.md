# matcha fixer · technical notes

a windows app that starts matcha's loader, watches updates, detects kernel or usermode launches, and offers an optional temporary connection tunnel. the dark and mint interface follows matcha-helper.

run `package/matcha-fixer.exe`, accept the windows admin prompt, select the folder containing `loader.exe`, then choose **start matcha**. sign in through matcha's own window when needed. once ready, choose a mode or close the loader. you can also use matcha's own mode buttons; the fixer detects the new process.

the fixer hashes installed `app.exe`, `usermode/app.exe` and `map.exe` with sha256 before and after checking their metadata for changes. it compares standard files with the public `https://adorablewhale.world/api/fixer/release` reference: exact file urls, bounded sizes, a hash reference under 24 hours old, and a fresh upstream check. usermode needs only its own matching file; kernel needs kernel and map. launch buttons recheck before opening a mode. unavailable references are clearly labelled. pro / beta uses the matching vendor loader, with standard comparison disabled by the user's edition selection.

the website checks the current official urls' etag, modification time and size before returning its separately computed hashes. metadata freshness is not a cryptographic publisher signature. only the vendor loader downloads and replaces matcha files. the fixer never reads the contents of `c:\matcha\auth.exe`, and file hashes are not reported.

## optional loader link

`LoaderLink.cs` adds an explicitly confirmed hklm 64-bit image file execution options path filter for the selected full `loader.exe` path. it refuses global debugger conflicts and another filter targeting the same file. a protected copy in `%programfiles%\matcha-fixer` is the launch handler. unlink removes only the owned filter and removes the `UseFilter` flag only if the fixer originally added it and no other filters remain. there is no run key, scheduled task, service or persistent watcher for this feature.

windows appends the original loader command line to `--from-loader`. the visible gui checks files and starts the original loader. to avoid recursively applying its launch rule, it creates only that child suspended with `DEBUG_ONLY_THIS_PROCESS`, detaches immediately, then resumes. it never reads or writes process memory. two real disposable windows loader fixtures verified exact-path filtering, intact arguments, no debugger at program entry, and another loader path being unaffected. compatibility with matcha's own protection has not been tested; unlink if its loader rejects this launch method.

when the fixer is already visible, another argument-free start of that linked loader signals the existing window through a per-user, per-path event. only the visible gui polls it. extra arguments require closing the existing fixer first. moving the loader does not update the registry rule automatically; unlink the old path before linking a new path. recovery from a missing installed copy: open the portable fixer with `--unlink-loader "c:\path\to\loader.exe"` as administrator. unlink leaves the inactive installed copy for reuse.

## targeted troubleshooting

`Troubleshooting.cs` maps the supplied community reports to local checks and conditional guidance. it reads the running roblox version-folder name and the public live deployment endpoint, runtime registration and configured driver-security values. process presence does not prove a game is joined; registry values do not prove the effective policy or cause of a failure. no setting is changed by those checks.

configuration reset requires the loader and matcha to be closed and a separate confirmation. it moves only top-level `.init` files under `c:\matcha\configurations` into a timestamped local backup. it rejects reparse folders/files, leaves login/scripts/nested files in place, and restore never overwrites a new same-name file. no blanket `c:\matcha` deletion, security-disabling registry file, nalfix, third-party roblox download, antivirus removal or wholesale runtime uninstall is included.

official references: [microsoft runtime repair/downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist), [driver blocklist policy](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules), [roblox reinstall help](https://en.help.roblox.com/hc/en-us/articles/203312910-How-to-Reinstall-the-Roblox-Software), [windows child process creation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), [debugger detach](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop).

## optional tunnel

after a connection check fails, **fix connection** offers a confirmation. accepting it installs official wireguard through winget if missing, downloads the pinned and sha256-verified third-party wgcf 2.3.0 executable, and accepts cloudflare's terms to register a warp account. no official cloudflare desktop app is installed.

wireguard receives routes for the current public ipv4/ipv6 addresses of `files.matcha.pink` and `keyauth.win`. these are ip routes, not per-app routes: unrelated apps contacting the same shared cloudflare ips can also use the tunnel. system dns is unchanged. refreshed server addresses are gathered whenever the tunnel starts. an installed/running service is insufficient: a handshake and successful tls server checks are required.

the fixer removes its `matchafixer` tunnel after completion, mode launch, loader exit, or normal app exit. a hidden guardian also attempts cleanup if the fixer process crashes. a power loss cannot run cleanup; the next fixer run removes its stale named tunnel. **emergency cleanup:** run `matcha-fixer.exe --tunnel-off` as administrator, or disconnect `matchafixer` in wireguard. tunnel dependencies remain installed.

wgcf is unofficial. registration and connectivity may fail or change upstream; errors leave the loader available for retry. this build's tunnel installation, registration and live routing have not been verified. a signed release, self-updater, and official warp fallback are not included in this local build.

account and tunnel files are under `%programdata%\matcha-fixer-tunnel`, restricted to administrators and system. local logs and saved folder selection are under `%localappdata%\matcha-fixer`. no account keys are logged. **view source** opens the embedded readable source. **review pc** reports detections for the selected folder and opens windows security; it does not add antivirus exclusions, restore quarantine, or change firewall settings.

## build and verify

windows 10/11 x64 with .net framework 4.7.2 or later. build uses the built-in framework compiler and downloads nothing:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Test
```

verification uses synthetic snapshots, cryptographic fixtures, temporary files and disposable registry keys. preview rendering does not capture the desktop or read another app. the regular suite starts only its own child executable; it does not start matcha, connect a tunnel or change security settings. a separate `tests.exe previews --test-path-filter` integration check temporarily adds an exact-path windows rule for a disposable workspace loader and removes it in `finally`. reporting tests exercise the actual worker service against an in-memory database, including c# signatures verified by webcrypto.

captured loader states on october 3, 2026: 380×460 authentication, 380×320 updating/ready, 380×380 mode selection. `version.txt` is rewritten after downloads. both launch paths are confirmed by the original recorder. unknown window sizes remain unclassified; an idle download plus failed server checks is only a suspected failure. successful tls checks do not prove http downloads will succeed. a loader attached after its completion marker was already written needs **continue** clicked inside the loader to expose mode selection.

sources: [wgcf](https://github.com/ViRb3/wgcf), [wireguard services](https://git.zx2c4.com/wireguard-windows/about/docs/enterprise.md), [cloudflare dns addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/).

## optional diagnostics

`Reporting.cs` uses an explicit, versioned opt-in before generating an installation key or making a request. its fixed https origin is `adorablewhale.world`. only the documented enum fields and numbers can be serialized. auth-file contents, keys, screenshots and local logs are never inputs to a report.

the preference is local. opting out stops the timer and aborts an in-flight request immediately, even if saving the preference fails. requests already received cannot be recalled; separate signed deletion removes shared history. each enable starts a new run. one serialized sender, short timeouts, a five-second minimum interval and a 60-second heartbeat prevent status changes building an unbounded request queue. the exit attempts a final status for at most two seconds, then aborts. abrupt termination can leave a last status without an ended marker; the admin tab labels stale sessions accordingly.

the local rsa private key is dpapi-encrypted for the current windows account. no site admin password or shared bearer token is distributed. normal tls certificate checks remain enabled; requests cannot redirect to another website. a session check prevents an old sender continuing after an opt-out/re-enable. delivery errors appear in the sharing status and never block the loader.

see [server protocol and limits](server/README.md). signatures do not establish trustworthy usage from an open-source client. the dashboard is intended for troubleshooting, not identifying people or measuring verified adoption.
