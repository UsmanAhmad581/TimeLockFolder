# Time-Lock Folder (Windows) - Level 1

A small desktop app that makes an **encrypted copy** of a folder and refuses to open it until a deadline you choose.

> ## ⚠️ SECURITY LEVEL 1 - BYPASSABLE BY DESIGN
> This is a **self-discipline tool**, not real security. The deadline is checked by this program using your PC's clock.
> It can be bypassed by:
> - **Anyone who knows the password** and writes a short script that skips the time check (the encryption itself has no clock).
> - **Changing the Windows clock** (the app has a basic "clock set backwards" warning, but it is only a hint).
> - **Using the original folder** - it is never deleted, so it is still there.
>
> Don't use it to protect secrets from other people, or for anything where a bypass would be harmful.

## ⚠️ Backup and recovery warnings (read before use)
1. **Your original folder is never deleted or changed.** Deleting it later is *your* decision - only after you've successfully test-unlocked the vault.
2. **There is no password recovery.** Lose the password = the vault is permanently unreadable. Store it in a password manager or on paper.
3. **Back up the `.tlvault` file** (USB drive / cloud). If it is damaged or deleted, there is no other copy of the encrypted data.
4. **Do not edit or rename the inside of a vault.** Any modification (even to the unlock time) makes it fail its integrity check.
5. Unlocking **never overwrites** anything: the destination must be a new or empty folder, and the vault stays in place.
6. Shortcuts/symbolic links are skipped (the app tells you how many). Everything else is included; if a file can't be read, the process stops with an error instead of silently skipping it.

## Setup (beginners)
1. Install Python 3.9+ from <https://www.python.org/downloads/>. **Tick "Add python.exe to PATH"** in the installer.
2. Unzip this folder somewhere normal (e.g. Documents).
3. Double-click **`run.bat`**. The first run creates a private environment and installs one library (needs internet); the window then opens. Later runs start instantly.

Optional: double-click `run_tests.bat` to run the automated checks (should end with `OK`), or `build_exe.bat` to make a standalone `dist\TimeLockFolder.exe`.

## Safe test (do this first - 5 minutes)
1. Make a folder `C:\TimeLockTest` with 2-3 junk text files. **Do not use real data for testing.**
2. Open the app → **Lock a folder** tab → choose `C:\TimeLockTest`. The vault name is suggested next to it.
3. Click **+10 min** (the minimum is 1 minute in the future), enter a test password such as `test-pass-123`, tick the three boxes, create the vault.
4. Confirm `C:\TimeLockTest` is still intact and `TimeLockTest.tlvault` exists.
5. **Unlock a vault** tab → pick the vault. It shows the countdown. Click Unlock *now* → you should get "Still locked".
6. Try a wrong password after the deadline → "Wrong password" and nothing is created.
7. After the deadline, unlock with the right password into a new folder and compare the files to the originals.
8. Only when all of this works, use it on real data - **always with your own separate backup**.

## How it works
- Files → temporary zip (a copy) → encrypted in 1 MB chunks with **AES-256-GCM**; key from your password via **scrypt**.
- The header (unlock time, salt) is authenticated, so edits, truncation or reordering are detected.
- After creating a vault, the app **re-reads and verifies the whole file** before accepting it; a half-written file never becomes a vault.
- The only things the app deletes are its own temporary files (`timelock_*` in your Temp folder) and an unfinished `.partial` output of a failed run.

## Troubleshooting
| Problem | Fix |
|---|---|
| "Python not found" | Reinstall Python and tick *Add to PATH*. |
| "Wrong password - or modified/damaged" | Check caps lock/keyboard layout; if sure, the file may be damaged - try your backup copy. |
| "System clock appears set backwards" | Correct the Windows date/time. (Delete `%APPDATA%\TimeLockFolder\state.json` only if the clock was legitimately wrong earlier.) |
| Very large folders | Needs free disk space of roughly 2× the folder size temporarily, plus the vault. |

## Files
`timelock_app.py` GUI · `timelock_core.py` engine · `tests/test_core.py` 10 tests · `selftest.bat` (checks the engine on YOUR PC) · `run.bat` / `run_tests.bat` / `build_exe.bat` helpers
