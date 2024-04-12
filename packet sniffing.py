import tkinter as tk
from tkinter import scrolledtext, ttk
from scapy.all import sniff, AsyncSniffer
import threading

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.sniffer = None
        self.packet_count = 0
        
        # Setup the style
        style = ttk.Style(self.root)
        style.theme_use('clam')

        # Frame for buttons
        self.frame = ttk.Frame(self.root)
        self.frame.pack(pady=10, padx=10, fill='x', expand=True)

        # Start Button
        self.start_btn = ttk.Button(self.frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(side='left', expand=True, fill='x', padx=5)

        # Stop Button
        self.stop_btn = ttk.Button(self.frame, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_btn.pack(side='left', expand=True, fill='x', padx=5)

        # Text Field
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=20)
        self.text_area.pack(padx=10, pady=10, fill='both', expand=True)
        self.text_area.config(state='disabled')

    def start_sniffing(self):
        if self.sniffer is None:
            self.sniffer = AsyncSniffer(prn=self.process_packet, store=False)
            self.sniffer.start()
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')

    def process_packet(self, packet):
        self.packet_count += 1
        packet_info = f"Packet #{self.packet_count}: {packet.summary()}\n"
        self.update_text_area(packet_info)

    def update_text_area(self, content):
        self.text_area.config(state='normal')
        self.text_area.insert(tk.END, content)
        self.text_area.yview(tk.END)
        self.text_area.config(state='disabled')

def main():
    root = tk.Tk()
    gui = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
