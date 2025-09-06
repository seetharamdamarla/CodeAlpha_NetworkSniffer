import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import queue
from sniffer import PacketSniffer
from utils import save_packets_to_csv, generate_filename

class PacketSnifferGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Packet Sniffer")
        self.root.geometry("1300x500")
        self.root.resizable(False, False)

        self.packet_queue = queue.Queue()
        self.sniffer = PacketSniffer(self.packet_queue)

        self.columns = (
            "Capture_Time", "Source IP", "Destination IP", "Protocol",
            "Source Port", "Destination Port", "Length", "Payload"
        )

        self._create_widgets()
        self.root.after(200, self.update_table)

    def _create_widgets(self):
        title_label = tk.Label(self.root, text="Network Packet Sniffer",
                               font=("Helvetica", 18, "bold"), fg="blue")
        title_label.pack(pady=10)

        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=5)

        start_btn = tk.Button(button_frame, text="Start Sniffing",
                              command=self.start_sniffing, bg="green", fg="white", width=15)
        start_btn.grid(row=0, column=0, padx=10)

        stop_btn = tk.Button(button_frame, text="Stop Sniffing",
                             command=self.stop_sniffing, bg="red", fg="white", width=15)
        stop_btn.grid(row=0, column=1, padx=10)

        clear_btn = tk.Button(button_frame, text="Clear Table",
                              command=self.clear_table, bg="orange", fg="white", width=15)
        clear_btn.grid(row=0, column=2, padx=10)

        save_btn = tk.Button(button_frame, text="Save to CSV",
                             command=self.save_to_csv, bg="blue", fg="white", width=15)
        save_btn.grid(row=0, column=3, padx=10)

        table_frame = tk.Frame(self.root)
        table_frame.pack(pady=10)

        scroll_y = tk.Scrollbar(table_frame, orient=tk.VERTICAL)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)

        scroll_x = tk.Scrollbar(table_frame, orient=tk.HORIZONTAL)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree = ttk.Treeview(
            table_frame,
            columns=self.columns,
            show="headings",
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
            height=15
        )

        for col in self.columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER)
            self.tree.column(col, width=170 if col == "Payload" else 140)

        self.tree.pack(fill=tk.BOTH)
        scroll_y.config(command=self.tree.yview)
        scroll_x.config(command=self.tree.xview)

    def start_sniffing(self):
        threading.Thread(target=self.sniffer.start_sniffing, daemon=True).start()

    def stop_sniffing(self):
        self.sniffer.stop_sniffing()

    def update_table(self):
        while not self.packet_queue.empty():
            data = self.packet_queue.get()
            self.tree.insert("", tk.END, values=data)
        self.root.after(200, self.update_table)

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def save_to_csv(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=generate_filename(),
            filetypes=[("CSV files", "*.csv")]
        )
        if not filepath:
            return

        data = [self.tree.item(item)["values"] for item in self.tree.get_children()]
        save_packets_to_csv(filepath, self.columns, data)
        messagebox.showinfo("Success", "Packets saved successfully!")

    def run(self):
        self.root.mainloop()
