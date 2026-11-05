# Lazeyka — recovered repository

This repo was restored on 2026-11-05 by Muse from the Notion AI chat
"Morning brief Setup" (workspace zerewg.we123213's space), after the builder's
Notion AI credits ran out mid-work ("Stopped by a usage policy." / "Interrupted",
Oct 31, 22:02). The chat itself contained almost no code as text — all code
lived in the git bundles attached as chat artifacts. All 8 Lazeyka artifacts
were downloaded and verified locally; the bundles form one unbroken chain:

| # | commit | bundle | state |
|---|--------|--------|-------|
| 1-4 | 90764d5..eb9f7b9 | lazeyka-src-eb9f7b9.bundle | first version (core + Windows Slint UI) |
| 5 | 5b6d77b | lazeyka-src-0.2-wip1.bundle | WIP 0.2 core |
| 6 | 71c8dd7 | lazeyka-src-0.2-wip2.bundle | WIP 0.2 UI dialogs, portable install |
| 7 | f7add27 | lazeyka-src-0.2.0.bundle | RELEASE 0.2.0 |
| 8 | e551b80 | lazeyka-wip-routes-core.bundle | WIP routes in core |
| 9 | a633f79 | lazeyka-wip-routes-ui.bundle | WIP routes UI — HEAD before this recovery note |

Windows release zips recovered alongside: lazeyka-0.1.0-windows-x64.zip and
lazeyka-0.2.0-windows-x64.zip (lazeyka.exe + mihomo.exe + dbip-country-lite.mmdb).
Full backup (original artifacts + chat timeline + sha256): 
~/workspace/notion-chat-backup-v020/ on Muse's machine.

## Where development stopped

HEAD (a633f79) is NOT a release: it is 0.2.0 + routes core + routes UI.
Cargo.toml still says version 0.2.0.

Two final builder steps were NEVER saved as a bundle and are not in this repo:
1. (~7 min) splitting the route-direction dialog into three separate modal
   windows without wrapper conditional blocks + layout check;
2. (~8 min) test servers run, engine start with migration of old settings,
   engine responsiveness / hang investigation, config reload, route-adding study.
They exist only as step descriptions in the chat trace and must be re-done,
not restored. Everything before them is here, verbatim.

Next sensible step: re-do step 1 on top of a633f79, then step 2 as a live
engine test, then cut a 0.3.0 release (routes) per the original plan
(0.3 routes/rules, 0.4 tray menu / notifications / connections list).

## Build

See README.md / docs in this repo. Rust workspace: root package `lazeyka`
(Slint UI, Windows service) + `core` (lazeyka-core). mihomo is an external
sidecar binary, not part of this source tree.
