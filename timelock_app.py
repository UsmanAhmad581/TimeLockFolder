"""Time-Lock Folder - GUI (Level 1, bypassable). Run: python timelock_app.py"""
import os, queue, threading, time, traceback, tkinter as tk
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import timelock_core as core

BANNER = ("LEVEL 1 - BYPASSABLE. Uses your PC clock; anyone with the password or technical skill "
          "can open it early. Originals are never deleted - you keep your own copy.")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Time-Lock Folder  (Level 1 - bypassable)")
        self.geometry("760x700")
        self.minsize(700, 640)
        self.q = queue.Queue()
        self.busy = False
        self.unlock_ts = None
        core.record_time_seen()

        tk.Label(self, text=BANNER, bg="#fff3cd", fg="#664d03", wraplength=720,
                 justify="left", padx=10, pady=6).pack(fill="x")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=8)
        self.lock_tab, self.unlock_tab = ttk.Frame(nb, padding=10), ttk.Frame(nb, padding=10)
        nb.add(self.lock_tab, text="  Lock a folder  ")
        nb.add(self.unlock_tab, text="  Unlock a vault  ")
        self._build_lock()
        self._build_unlock()

        ttk.Button(self, text="Run self-test (fake data, safe)", command=self._selftest).pack(anchor="e", padx=10)
        self.bar = ttk.Progressbar(self, maximum=1000)
        self.bar.pack(fill="x", padx=10)
        self.status = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=10, pady=(2, 8))
        self.after(100, self._poll)
        self.after(1000, self._tick)

    # ------------------------------------------------------------ helpers
    def _row(self, parent, r, label, var, browse=None, show=None):
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", pady=4)
        e = ttk.Entry(parent, textvariable=var, show=show or "")
        e.grid(row=r, column=1, sticky="ew", padx=6)
        if browse:
            ttk.Button(parent, text="Browse...", command=browse).grid(row=r, column=2)
        parent.columnconfigure(1, weight=1)

    def _build_lock(self):
        f = self.lock_tab
        self.src, self.vault = tk.StringVar(), tk.StringVar()
        self.date, self.time_ = tk.StringVar(), tk.StringVar()
        self.pw, self.pw2 = tk.StringVar(), tk.StringVar()
        self.ck1, self.ck2, self.ck3 = tk.BooleanVar(), tk.BooleanVar(), tk.BooleanVar()
        self._row(f, 0, "Folder to lock:", self.src, self._pick_src)
        self._row(f, 1, "Save vault as:", self.vault, self._pick_vault)
        ttk.Label(f, text="Unlock date (YYYY-MM-DD):").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.date, width=14).grid(row=2, column=1, sticky="w", padx=6)
        ttk.Label(f, text="Unlock time (HH:MM, 24h):").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(f, textvariable=self.time_, width=14).grid(row=3, column=1, sticky="w", padx=6)
        q = ttk.Frame(f)
        q.grid(row=4, column=1, sticky="w", padx=6)
        for txt, d in [("+10 min", timedelta(minutes=10)), ("+1 hour", timedelta(hours=1)),
                       ("+1 day", timedelta(days=1)), ("+7 days", timedelta(days=7)),
                       ("+30 days", timedelta(days=30))]:
            ttk.Button(q, text=txt, width=9, command=lambda d=d: self._quick(d)).pack(side="left", padx=2)
        self._quick(timedelta(days=1))
        self._row(f, 5, "Password:", self.pw, show="*")
        self._row(f, 6, "Repeat password:", self.pw2, show="*")
        ttk.Label(f, text="Min. 8 characters. If you lose it, your data CANNOT be recovered by anyone.",
                  foreground="#842029").grid(row=7, column=1, sticky="w", padx=6)
        for i, (v, t) in enumerate([
                (self.ck1, "I saved my password somewhere safe (password manager / paper)."),
                (self.ck2, "I understand Level 1 can be bypassed and is not strong protection."),
                (self.ck3, "I keep my own backup of the original folder (it is never deleted for me).")]):
            ttk.Checkbutton(f, text=t, variable=v).grid(row=8 + i, column=0, columnspan=3, sticky="w", pady=2)
        self.lock_btn = ttk.Button(f, text="Create encrypted time-lock vault", command=self._do_lock)
        self.lock_btn.grid(row=11, column=0, columnspan=3, pady=14, ipadx=10, ipady=4)

    def _build_unlock(self):
        f = self.unlock_tab
        self.uv, self.ud, self.upw = tk.StringVar(), tk.StringVar(), tk.StringVar()
        self._row(f, 0, "Vault file (.tlvault):", self.uv, self._pick_uv)
        self._row(f, 1, "Extract into NEW/empty folder:", self.ud, self._pick_ud)
        self._row(f, 2, "Password:", self.upw, show="*")
        self.info = tk.StringVar(value="Choose a vault to see its unlock time.")
        tk.Label(f, textvariable=self.info, justify="left", anchor="w", wraplength=680).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=10)
        self.unlock_btn = ttk.Button(f, text="Unlock vault", command=self._do_unlock)
        self.unlock_btn.grid(row=4, column=0, columnspan=3, pady=10, ipadx=10, ipady=4)
        ttk.Label(f, text="Nothing is overwritten and the .tlvault file is kept. Keep it as your backup.",
                  foreground="#555").grid(row=5, column=0, columnspan=3)

    # ---------------------------------------------------------- pickers
    def _quick(self, delta):
        t = datetime.now() + delta
        self.date.set(t.strftime("%Y-%m-%d"))
        self.time_.set(t.strftime("%H:%M"))

    def _pick_src(self):
        p = filedialog.askdirectory(title="Folder to lock (a COPY is encrypted)")
        if p:
            self.src.set(p)
            base = Path(p)
            cand = base.parent / (base.name + core.EXT)
            if cand.exists():
                cand = base.parent / f"{base.name}_{datetime.now():%Y%m%d_%H%M%S}{core.EXT}"
            self.vault.set(str(cand))

    def _pick_vault(self):
        p = filedialog.asksaveasfilename(defaultextension=core.EXT, filetypes=[("Time-Lock vault", "*.tlvault")])
        if p:
            self.vault.set(p)

    def _pick_uv(self):
        p = filedialog.askopenfilename(filetypes=[("Time-Lock vault", "*.tlvault"), ("All files", "*.*")])
        if p:
            self.uv.set(p)
            if not self.ud.get():
                self.ud.set(str(Path(p).with_suffix("")) + "_unlocked")
            self._inspect()

    def _pick_ud(self):
        p = filedialog.askdirectory(title="Choose a NEW or EMPTY folder")
        if p:
            self.ud.set(p)

    def _inspect(self):
        try:
            h, _, _ = core.read_header(self.uv.get())
            self.unlock_ts = h["unlock_ts"]
            self.hdr = (f"Original folder name: {h.get('source_name', '?')}\n"
                        f"Created:  {core.fmt_ts(h['created_ts'])}\nUnlocks: {core.fmt_ts(h['unlock_ts'])}")
            self._tick()
        except Exception as e:
            self.unlock_ts = None
            self.info.set(f"Cannot read vault: {e}")

    def _tick(self):
        if self.unlock_ts is not None and hasattr(self, "hdr"):
            left = self.unlock_ts - time.time()
            self.info.set(self.hdr + "\n" + (f"Time remaining: {core.fmt_delta(left)}" if left > 0
                                             else "Deadline has passed - you may unlock now."))
        self.after(1000, self._tick)

    # ----------------------------------------------------------- actions
    def _do_lock(self):
        if self.busy:
            return
        try:
            ts = datetime.strptime(f"{self.date.get().strip()} {self.time_.get().strip()}",
                                   "%Y-%m-%d %H:%M").timestamp()
        except ValueError:
            return messagebox.showerror("Invalid date/time", "Use YYYY-MM-DD and HH:MM (24-hour), e.g. 2026-12-31 and 18:30.")
        if self.pw.get() != self.pw2.get():
            return messagebox.showerror("Passwords differ", "The two passwords do not match.")
        if not (self.ck1.get() and self.ck2.get() and self.ck3.get()):
            return messagebox.showwarning("Please confirm", "Tick all three confirmation boxes first.")
        if not messagebox.askyesno("Confirm", f"Create vault?\n\nFolder: {self.src.get()}\nVault: {self.vault.get()}\n"
                                   f"Unlocks: {core.fmt_ts(ts)}\n\nYour original folder will NOT be deleted or changed."):
            return
        pw, s, v = self.pw.get(), self.src.get(), self.vault.get()
        self._run(lambda p: core.lock_folder(s, v, pw, ts, p), self._lock_done)

    def _lock_done(self, r):
        self.pw.set(""); self.pw2.set("")
        messagebox.showinfo("Vault created and verified",
                            f"Vault: {r['vault']}\nFiles: {r['files']}   Size: {r['bytes']:,} bytes\n"
                            + (f"Skipped shortcuts/links: {r['skipped_links']}\n" if r['skipped_links'] else "")
                            + "\nYour ORIGINAL folder is still in place - nothing was deleted.\n"
                              "Decide yourself whether to move it away. Back up the .tlvault file too.")

    def _do_unlock(self):
        if self.busy:
            return
        v, d, pw = self.uv.get(), self.ud.get(), self.upw.get()
        if not v or not d:
            return messagebox.showerror("Missing info", "Choose the vault and a destination folder.")
        dp = Path(d)
        if dp.exists() and (not dp.is_dir() or any(dp.iterdir())):
            alt, n = dp.parent / (dp.name + "_restored"), 2
            while alt.exists():
                alt, n = dp.parent / f"{dp.name}_restored_{n}", n + 1
            if not messagebox.askyesno("Folder not empty", f"'{dp}' already has content and is never overwritten.\n\nRestore into a new folder instead?\n{alt}"):
                return
            d = str(alt); self.ud.set(d)
        self._run(lambda p: core.unlock_vault(v, pw, d, p), self._unlock_done)

    def _unlock_done(self, r):
        self.upw.set("")
        messagebox.showinfo("Unlocked", f"Restored {r['restored']} file(s) to:\n{r['dest']}\n\nThe vault file was kept as a backup. The folder will open now.")
        try:
            os.startfile(r["dest"])
        except Exception:
            pass

    def _selftest(self):
        if self.busy:
            return
        self.status.set("Running self-test (takes a few seconds)...")
        self.update_idletasks()
        ok, rep = core.self_test()
        self.status.set("Self-test " + ("passed." if ok else "FAILED."))
        (messagebox.showinfo if ok else messagebox.showerror)("Self-test " + ("PASSED" if ok else "FAILED"),
            rep + ("\n\nThe engine works on this PC." if ok else "\n\nPlease send this text to the developer."))

    def _run(self, fn, done):
        self.busy = True
        self.lock_btn.state(["disabled"]); self.unlock_btn.state(["disabled"])
        self.bar["value"] = 0
        def work():
            try:
                self.q.put(("ok", done, fn(lambda f, t: self.q.put(("p", f, t)))))
            except core.TooEarlyError as e:
                self.q.put(("err", "Still locked", f"Not yet! Unlocks at {core.fmt_ts(e.unlock_ts)}\n"
                            f"({core.fmt_delta(e.unlock_ts - time.time())} remaining)."))
            except core.TimeLockError as e:
                core.log_error(traceback.format_exc())
                self.q.put(("err", "Error", str(e)))
            except Exception as e:
                core.log_error(traceback.format_exc())
                self.q.put(("err", "Unexpected error", f"{type(e).__name__}: {e}\n\nDetails saved to:\n{core.log_path()}"))
        threading.Thread(target=work, daemon=True).start()

    def _poll(self):
        try:
            while True:
                m = self.q.get_nowait()
                if m[0] == "p":
                    self.bar["value"] = int(m[1] * 1000); self.status.set(m[2])
                else:
                    self.busy = False
                    self.lock_btn.state(["!disabled"]); self.unlock_btn.state(["!disabled"])
                    core.record_time_seen()
                    if m[0] == "ok":
                        self.status.set("Finished."); m[1](m[2])
                    else:
                        self.status.set("Stopped: " + m[2].split("\n")[0]); self.bar["value"] = 0
                        messagebox.showerror(m[1], m[2])
        except queue.Empty:
            pass
        self.after(100, self._poll)


if __name__ == "__main__":
    App().mainloop()
