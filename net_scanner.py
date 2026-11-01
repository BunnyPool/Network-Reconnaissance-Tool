#!/usr/bin/env python3
"""Network Scanner GUI for authorized educational lab use only."""
import csv
import ipaddress
import queue
import socket
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 8080: "HTTP-Alt",
}
MAX_HOSTS = 1024


class ScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Network Scanner | Major Project")
        root.geometry("1050x660")
        root.minsize(820, 500)
        self.events = queue.Queue()
        self.results = []
        self.scanning = False
        self.stop_event = threading.Event()

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("TkDefaultFont", 19, "bold"))
        style.configure("Treeview", rowheight=24)

        main = ttk.Frame(root, padding=16)
        main.pack(fill="both", expand=True)
        ttk.Label(main, text="Network Scanner", style="Title.TLabel").pack(anchor="w")
        ttk.Label(main, text="Host discovery • Common, specific, or all TCP ports • CSV export").pack(anchor="w", pady=(3, 12))

        settings = ttk.LabelFrame(main, text="Scan settings", padding=10)
        settings.pack(fill="x", pady=(0, 10))
        ttk.Label(settings, text="Target network/IP:").grid(row=0, column=0, sticky="w")
        self.target = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(settings, textvariable=self.target, width=22).grid(row=0, column=1, padx=(7, 14))
        ttk.Label(settings, text="Port selection:").grid(row=0, column=2, sticky="w")
        self.port_mode = tk.StringVar(value="Common ports")
        self.port_mode_box = ttk.Combobox(
            settings, textvariable=self.port_mode, state="readonly", width=15,
            values=("Common ports", "Specific ports", "All ports (1-65535)")
        )
        self.port_mode_box.grid(row=0, column=3, padx=(7, 8), sticky="w")
        self.port_mode_box.bind("<<ComboboxSelected>>", self.update_port_mode)
        self.ports = tk.StringVar(value="21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080")
        self.ports_entry = ttk.Entry(settings, textvariable=self.ports, width=38)
        self.ports_entry.grid(row=0, column=4, padx=(0, 8), sticky="ew")
        self.start_btn = ttk.Button(settings, text="Start scan", command=self.start_scan)
        self.start_btn.grid(row=0, column=5, padx=3)
        self.stop_btn = ttk.Button(settings, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=6, padx=3)
        settings.columnconfigure(4, weight=1)
        self.update_port_mode()

        statusrow = ttk.Frame(main)
        statusrow.pack(fill="x", pady=(0, 8))
        self.status = tk.StringVar(value="Ready — scan only networks you own or are authorized to assess.")
        self.host_count = tk.StringVar(value="Hosts: 0")
        self.port_count = tk.StringVar(value="Open ports: 0")
        ttk.Label(statusrow, textvariable=self.status).pack(side="left", fill="x", expand=True)
        ttk.Label(statusrow, textvariable=self.host_count).pack(side="left", padx=10)
        ttk.Label(statusrow, textvariable=self.port_count).pack(side="left", padx=10)
        self.progress = ttk.Progressbar(main, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 10))

        frame = ttk.Frame(main)
        frame.pack(fill="both", expand=True)
        cols = ("ip", "hostname", "state", "port", "service", "detail")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        headings = [
            ("ip", "IP address", 130), ("hostname", "Hostname", 170),
            ("state", "Host state", 90), ("port", "TCP port", 80),
            ("service", "Common service", 130), ("detail", "Result", 230),
        ]
        for key, label, width in headings:
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, minwidth=65, anchor="w")
        ybar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        xbar = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        bottom = ttk.Frame(main)
        bottom.pack(fill="x", pady=(10, 0))
        ttk.Button(bottom, text="Export CSV", command=self.export_csv).pack(side="left")
        ttk.Button(bottom, text="Clear results", command=self.clear).pack(side="left", padx=8)
        ttk.Label(bottom, text="TCP connect checks do not identify all service versions.").pack(side="right")
        root.after(100, self.process_events)

    def parse_targets(self):
        value = self.target.get().strip()
        try:
            if "/" in value:
                network = ipaddress.ip_network(value, strict=False)
                if network.version != 4:
                    raise ValueError("Only IPv4 targets are supported.")
                if network.num_addresses > MAX_HOSTS:
                    raise ValueError(f"Please limit the scan to {MAX_HOSTS} addresses.")
                hosts = list(network.hosts())
                if not hosts and network.num_addresses == 1:
                    hosts = [network.network_address]
            else:
                addr = ipaddress.ip_address(value)
                if addr.version != 4:
                    raise ValueError("Only IPv4 targets are supported.")
                hosts = [addr]
        except ValueError as exc:
            raise ValueError(f"Invalid target: {exc}")
        return [str(host) for host in hosts]

    def update_port_mode(self, _event=None):
        mode = self.port_mode.get()
        if mode == "Specific ports":
            self.ports_entry.configure(state="normal")
            self.ports_entry.focus_set()
        elif mode == "All ports (1-65535)":
            self.ports_entry.configure(state="disabled")
        else:
            self.ports_entry.configure(state="disabled")

    def parse_ports(self):
        mode = self.port_mode.get()
        if mode == "All ports (1-65535)":
            return range(1, 65536)
        if mode == "Common ports":
            return [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]
        result = []
        try:
            for item in self.ports.get().split(","):
                item = item.strip()
                if not item:
                    continue
                port = int(item)
                if not 1 <= port <= 65535:
                    raise ValueError(f"Port out of range: {port}")
                if port not in result:
                    result.append(port)
        except ValueError as exc:
            raise ValueError(f"Invalid port list: {exc}")
        if not result:
            raise ValueError("Enter ports separated by commas.")
        return result

    def start_scan(self):
        if self.scanning:
            return
        try:
            hosts, ports = self.parse_targets(), self.parse_ports()
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))
            return
        if not messagebox.askyesno("Permission check", "Do you own this network or have explicit permission to scan it?"):
            return
        if self.port_mode.get() == "All ports (1-65535)":
            if not messagebox.askyesno(
                "Full TCP port scan",
                "This checks TCP ports 1–65535 on each host that responds to ping. It can take a long time. Continue?"
            ):
                return
        self.results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.stop_event.clear()
        self.scanning = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.host_count.set("Hosts: 0")
        self.port_count.set("Open ports: 0")
        self.status.set(f"Discovering hosts across {len(hosts)} address(es)…")
        self.progress.start(10)
        threading.Thread(target=self.worker, args=(hosts, ports), daemon=True).start()

    def stop_scan(self):
        self.stop_event.set()
        self.status.set("Stopping scan…")

    @staticmethod
    def ping(ip):
        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=2, check=False
            )
            if proc.returncode == 0:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except (socket.herror, socket.gaierror, OSError):
                    hostname = "Unknown"
                return {"ip": ip, "hostname": hostname}
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def check_port(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.45)
                if sock.connect_ex((ip, port)) == 0:
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        service = "Unknown"
                    return {"ip": ip, "port": port, "service": SERVICE_NAMES.get(port, service)}
        except OSError:
            pass
        return None

    def worker(self, targets, ports):
        try:
            discovered = []
            with ThreadPoolExecutor(max_workers=64) as pool:
                futures = [pool.submit(self.ping, ip) for ip in targets]
                for future in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    result = future.result()
                    if result:
                        discovered.append(result)
                        self.events.put(("host", result))
            self.events.put(("status", f"Discovery finished: {len(discovered)} host(s) replied to ping."))
            if not self.stop_event.is_set():
                # Process bounded batches so an all-ports scan does not allocate
                # tens of thousands of futures per host at once.
                total = len(discovered) * len(ports)
                completed = 0
                batch_size = 1000
                with ThreadPoolExecutor(max_workers=100) as pool:
                    for host in discovered:
                        if self.stop_event.is_set():
                            break
                        port_iter = iter(ports)
                        while not self.stop_event.is_set():
                            batch_ports = []
                            try:
                                for _ in range(batch_size):
                                    batch_ports.append(next(port_iter))
                            except StopIteration:
                                pass
                            if not batch_ports:
                                break
                            futures = [pool.submit(self.check_port, host["ip"], port) for port in batch_ports]
                            for future in as_completed(futures):
                                if self.stop_event.is_set():
                                    break
                                result = future.result()
                                completed += 1
                                if result:
                                    self.events.put(("port", result))
                                if completed % 100 == 0 or completed == total:
                                    self.events.put(("progress", (completed, total)))
                            if len(batch_ports) < batch_size:
                                break
            self.events.put(("done", "Scan stopped." if self.stop_event.is_set() else "Scan completed."))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def add_row(self, row):
        self.results.append(row)
        self.tree.insert("", "end", values=tuple(row[k] for k in ("ip", "hostname", "state", "port", "service", "detail")))

    def process_events(self):
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "host":
                    self.add_row({
                        "ip": payload["ip"], "hostname": payload["hostname"], "state": "Up",
                        "port": "", "service": "", "detail": "Responded to ping",
                    })
                    self.host_count.set(f"Hosts: {sum(1 for r in self.results if r['detail'] == 'Responded to ping')}")
                elif event == "port":
                    hostname = next((r["hostname"] for r in self.results if r["ip"] == payload["ip"]), "Unknown")
                    self.add_row({
                        "ip": payload["ip"], "hostname": hostname, "state": "Up",
                        "port": payload["port"], "service": payload["service"],
                        "detail": "TCP connection accepted",
                    })
                    self.port_count.set(f"Open ports: {sum(1 for r in self.results if r['port'] != '')}")
                elif event == "status":
                    self.status.set(payload)
                elif event == "progress":
                    self.status.set(f"Checking TCP ports: {payload[0]}/{payload[1]}")
                elif event == "done":
                    self.finish(payload)
                elif event == "error":
                    self.finish("Scan failed.")
                    messagebox.showerror("Scan error", payload)
        except queue.Empty:
            pass
        self.root.after(100, self.process_events)

    def finish(self, message):
        self.scanning = False
        self.progress.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status.set(message)

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("No results", "Run a scan before exporting.")
            return
        default = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path = filedialog.asksaveasfilename(
            title="Save CSV report", defaultextension=".csv", initialfile=default,
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=["ip", "hostname", "state", "port", "service", "detail"])
                writer.writeheader()
                writer.writerows(self.results)
            messagebox.showinfo("Export complete", f"Saved report to:\n{path}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))

    def clear(self):
        if self.scanning:
            messagebox.showwarning("Scan running", "Stop the scan first.")
            return
        self.results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.host_count.set("Hosts: 0")
        self.port_count.set("Open ports: 0")
        self.status.set("Results cleared.")


if __name__ == "__main__":
    root = tk.Tk()
    ScannerGUI(root)
    root.mainloop()
