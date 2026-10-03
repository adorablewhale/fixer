<div align="center">

<img src="assets/matcha-fixer.png" width="72" alt="matcha fixer whale with a bandage">

# fixer

**a little help getting matcha running.**

free · open source · windows 10/11 x64

</div>

starts your matcha loader, follows its downloads, and shows when kernel or usermode is ready. if the servers are unreachable, it can offer a temporary connection tunnel.

- simple interface with a dark and mint theme
- watches the loader's progress and launches your chosen mode
- checks launch-file hashes against the current standard release
- helps with version, runtime, mapping and configuration problems
- can open alongside your selected loader, with no tray app or startup watcher
- optional connection repair, with a confirmation before installing or connecting anything
- optional basic diagnostics to help adorablewhale see whether the fixer is working
- readable source included inside the exe and licensed under [mit](LICENSE)

## getting started

download the windows zip from [releases](https://github.com/adorablewhale/fixer/releases/latest), extract it, then open the fixer.

open `matcha-fixer.exe`, accept the windows administrator prompt, and choose the folder containing your matcha `loader.exe`. click **start matcha** and sign in through matcha's own window. choose kernel or usermode when it is ready.

the administrator prompt is needed for managing the optional wireguard tunnel. **review pc** helps you check windows security; it does not automatically add exclusions or restore quarantined files.

open **help** for the common issues. choose **pro / beta** if you use one of those loaders; the standard release hashes do not apply to them. usermode can be ready even when kernel or map needs attention.

## opening it with your loader

choose **help → link loader** once. opening that exact `loader.exe` then opens a visible fixer and starts the original loader. the fixer checks its launch files and offers a temporary tunnel only if its hosts cannot be reached. nothing waits in the tray or starts with windows.

the link installs a copy of the fixer in program files and adds a windows launch rule for your selected loader path. **unlink loader** removes that rule. moving the loader means selecting its new location; unlink the old location first. keep the installed fixer in place until you unlink it.

## common problems

**help** has guidance and local checks for connection failures, roblox versions, driver mapping, missing runtimes, black screens, configurations, authentication and performance. it explains when the original updater, usermode, windows settings or matcha support is the next step.

**back up + reset configs** moves only top-level `.init` files into a local backup after you confirm. close matcha and its loader first. your login file and scripts stay in place. **restore last backup** brings configurations back without replacing any fresh files with the same names.

## what it does on your pc

the fixer checks the loader's window, running processes, download sizes and version marker. it does not read your matcha login key. folder preferences and basic logs stay on your pc.

hash checks read only kernel, usermode and map. they stay on your pc. a current reference can show that standard files need an update; the original loader still handles all downloads. when that reference is unavailable, the app says so and relies on the loader's update check.

connection repair uses the official wireguard client and the third-party **wgcf** tool to create a cloudflare warp profile. you see a separate confirmation first. it temporarily routes matcha's server addresses and disconnects after the loader finishes or you close the fixer. other apps contacting those same shared addresses can also use that route. the installed tools remain available afterward.

## sharing is your choice

the first-run disclosure says: **this helps adorablewhale check that matcha fixer is working and fix problems on other people's pcs.** sharing starts only if you choose **share basic status**. **keep local** gives you every fixer feature.

if enabled, it sends run times, fixer and windows versions, launch mode, update and tunnel results, runtime, and short error codes to [adorablewhale.world](https://adorablewhale.world). a random installation identifier groups the reports. each run keeps only its latest status and expires 30 days after its last report.

it does not send login keys, passwords, roblox identities, file paths, screenshots, or logs. open **reporting** to turn sharing off or delete your shared history. if the website cannot be reached, deletion is shown as unconfirmed and you can retry.

reports travel over encrypted https and are signed with a key created on your pc. your private signing key stays encrypted on that pc; website credentials are never included. the website checks signatures, rejects reused requests, limits submissions, and keeps the admin tab private. reports describe what the client says happened; a modified open-source client can still invent its own results.

## open source

click **view source** in the app to read its source, or browse the files here. there is no obfuscated payload or bundled website password. you can inspect the reporting code, change it, or build your own copy.

build on windows with the included script; no compiler downloads are needed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -Test
```

more detail: [how it works and verification](TECHNICAL.md) · [reporting server](server/README.md)

### something broke?

message me on [discord](https://discord.com/users/599705734002769920), it works way better than issues here. tell me what you were doing and what happened.

<sub>[mit license](LICENSE)</sub>

---

<div align="center"><sub>🐳 <b>adorablewhale</b> · <a href="https://adorablewhale.world/me">website</a> · <a href="https://discord.com/users/599705734002769920">discord</a> · <a href="https://github.com/adorablewhale">other projects</a></sub></div>
