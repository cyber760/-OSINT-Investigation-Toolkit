import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from .analyzer import domain_report, ip_report, email_domain_report, save_report


class ToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OSINT Investigation Toolkit v1.0")
        self.root.geometry("1080x720")
        self.root.minsize(820, 560)
        self.root.configure(bg="#07110d")
        self.last_report = None
        self._style()
        self._build()

    def _style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#07110d")
        style.configure("TLabel", background="#07110d", foreground="#d8f5e5", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 22, "bold"), foreground="#20f58a")
        style.configure("Sub.TLabel", foreground="#91b8a3")
        style.configure("TButton", background="#08a95c", foreground="#001b0d", padding=8, font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#20f58a")])
        style.configure("TNotebook", background="#07110d", borderwidth=0)
        style.configure("TNotebook.Tab", background="#10251a", foreground="#c8f5dc", padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", "#087a46")])
        style.configure("TEntry", fieldbackground="#102019", foreground="#e4fff0")

    def _build(self):
        header = ttk.Frame(self.root, padding=18)
        header.pack(fill="x")
        ttk.Label(header, text="OSINT INVESTIGATION TOOLKIT", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Gather • Analyze • Investigate | Public-source research only", style="Sub.TLabel").pack(anchor="w", pady=(4, 0))

        controls = ttk.Frame(self.root, padding=(18, 4, 18, 12))
        controls.pack(fill="x")
        ttk.Label(controls, text="Investigation target").pack(side="left")
        self.target = tk.StringVar()
        self.entry = ttk.Entry(controls, textvariable=self.target, width=55)
        self.entry.pack(side="left", padx=10, fill="x", expand=True)
        self.run_button = ttk.Button(controls, text="Start Analysis", command=self.run_analysis)
        self.run_button.pack(side="left")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        self.output = tk.Text(self.notebook, bg="#081811", fg="#c8f5dc", insertbackground="white",
                              font=("Consolas", 10), wrap="word", relief="flat", padx=14, pady=14)
        self.notebook.add(self.output, text="Investigation Results")
        info = tk.Text(self.notebook, bg="#081811", fg="#c8f5dc", font=("Consolas", 10),
                       wrap="word", relief="flat", padx=14, pady=14)
        info.insert("1.0", self.help_text())
        info.configure(state="disabled")
        self.notebook.add(info, text="Help & Safety")

        footer = ttk.Frame(self.root, padding=(18, 4, 18, 14))
        footer.pack(fill="x")
        ttk.Button(footer, text="Save JSON Report", command=self.save_json).pack(side="left")
        ttk.Button(footer, text="Export TXT", command=self.export_txt).pack(side="left", padx=8)
        ttk.Button(footer, text="Clear", command=self.clear).pack(side="left")
        ttk.Label(footer, text="For lawful, ethical, authorized research.", style="Sub.TLabel").pack(side="right")

    def help_text(self):
        return (
            "SUPPORTED LOOKUPS\n\n"
            "1. Domain / URL: public DNS records, RDAP registration data, HTTP response metadata.\n"
            "   Example: example.com\n\n"
            "2. Public IP: IP classification, reverse DNS, approximate public IP geolocation/ISP.\n"
            "   Example: 8.8.8.8\n\n"
            "3. Email domain: basic syntax check and public MX records only.\n"
            "   Example: name@example.com\n\n"
            "IMPORTANT SAFETY NOTES\n\n"
            "- Use only information you are legally allowed to access.\n"
            "- Do not use this tool to stalk, dox, harass, or identify private individuals.\n"
            "- IP geolocation is approximate and does not reveal an exact home address.\n"
            "- Email lookup does not confirm that a mailbox exists or belongs to someone.\n"
            "- No password attacks, private-account access, exploitation, or stealth scanning.\n"
            "- Respect privacy laws, API terms, and website terms of service.\n"
        )

    def run_analysis(self):
        target = self.target.get().strip()
        if not target:
            messagebox.showwarning("Missing target", "Enter a domain, public IP, or email address.")
            return
        self.run_button.configure(state="disabled")
        self.output.delete("1.0", "end")
        self.output.insert("end", "Running public-source lookups...\nPlease wait.\n")
        threading.Thread(target=self._worker, args=(target,), daemon=True).start()

    def _worker(self, target):
        try:
            if "@" in target:
                result = email_domain_report(target)
            else:
                try:
                    import ipaddress
                    ipaddress.ip_address(target.strip())
                    result = ip_report(target)
                except ValueError:
                    result = domain_report(target)
            self.root.after(0, self._show_result, result)
        except Exception as exc:
            self.root.after(0, self._show_error, str(exc))

    def _show_result(self, result):
        self.last_report = result
        self.output.delete("1.0", "end")
        self.output.insert("1.0", json.dumps(result, indent=2, ensure_ascii=False))
        self.run_button.configure(state="normal")

    def _show_error(self, error):
        self.output.delete("1.0", "end")
        self.output.insert("1.0", f"Analysis failed:\n{error}")
        self.run_button.configure(state="normal")

    def save_json(self):
        if not self.last_report:
            messagebox.showinfo("No report", "Run an investigation first.")
            return
        path = save_report(self.last_report)
        messagebox.showinfo("Saved", f"JSON report saved to:\n{path}")

    def export_txt(self):
        if not self.last_report:
            messagebox.showinfo("No report", "Run an investigation first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as file:
                file.write(json.dumps(self.last_report, indent=2, ensure_ascii=False))
            messagebox.showinfo("Exported", f"Text report exported to:\n{path}")

    def clear(self):
        self.target.set("")
        self.output.delete("1.0", "end")
        self.last_report = None


def main():
    root = tk.Tk()
    ToolkitApp(root)
    root.mainloop()
