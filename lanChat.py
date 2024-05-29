import tkinter as tk
from tkinter import scrolledtext, ttk
import socket
import threading
import subprocess
from scapy.all import sr1, IP, ICMP, conf
import netifaces
import sys
import select       

PORT = 9090
TAG = ""
class LANChat: # TODO: Enchance UI/UX
    def __init__(self, root, interface_name):
        self.root = root
        self.root.title("LAN Socket Chat - " + interface_name)
        
        # Label
        text_var = tk.StringVar()
        text_var.set("Message To Send...")
        self.msg_display = tk.Label(self.root, textvariable=text_var, anchor=tk.CENTER )
        self.msg_display.grid(row=1, column=0, padx=0, pady=0)

        # Message display area
        self.msg_display = scrolledtext.ScrolledText(self.root, width=50, height=15)
        self.msg_display.grid(row=0, column=0, padx=10, pady=10)
        
        # LAN users display area
        self.users_display = scrolledtext.ScrolledText(self.root, width=30, height=15)
        self.users_display.grid(row=0, column=1, padx=10, pady=10)
        
        # Interface dropdown list
        self.interface_var = tk.StringVar()
        self.interface_var.set(interface_name)
        self.interface_list = ttk.Combobox(self.root, textvariable=self.interface_var)
        self.interface_list['values'] = self.get_interfaces()
        self.interface_list.grid(row=1, column=1, padx=10, pady=10)
        
        # Message entry field
        self.message_entry = tk.Entry(self.root, width=40)
        self.message_entry.grid(row=2, column=0, padx=10, pady=10)
        
        # Buttons
        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.grid(row=2, column=1, padx=5, pady=10, sticky='w')
        
        self.clear_button = tk.Button(self.root, text="Clear", command=self.clear_messages)
        self.clear_button.grid(row=2, column=1, padx=5, pady=10)
        
        self.scan_button = tk.Button(self.root, text="Scan", command=self.start_scan_network_thread)
        self.scan_button.grid(row=2, column=1, padx=5, pady=10, sticky='e')
        
        # Network properties
        self.hostname = socket.gethostname()
        self.local_ip = self.get_ip_from_interface(interface_name)
        self.users = []
        self.sockets = []
        self.TAG = interface_name
        
        # Start listening thread
        threading.Thread(target=self.listen_for_messages, daemon=True).start()

    def get_interfaces(self):
        interfaces = netifaces.interfaces()
        return interfaces

    def get_ip_from_interface(self, interface):
        addresses = netifaces.ifaddresses(interface)
        return addresses[netifaces.AF_INET][0]['addr'] if netifaces.AF_INET in addresses else None

    def start_scan_network_thread(self):
        threading.Thread(target=self.scan_network, daemon=True).start()

    def scan_network(self):
        self.update_users_display(clear=True)
        self.users = []
        selected_interface = self.interface_var.get()
        
        if not selected_interface:
            self.update_msg_display("Please select a network interface.\n")
            return
        
        self.local_ip = self.get_ip_from_interface(selected_interface)
        
        if not self.local_ip:
            self.update_msg_display("Unable to get IP for the selected interface.\n")
            return
        
        ip_base = ".".join(self.local_ip.split('.')[:-1]) + '.'
        subnet = ip_base + '0/24'
        self.scan_button.config(state=tk.DISABLED)
        try:
            # TODO: This assumes class C network in LAN (needs to be modified to read subnet mask)
            # Execute the nmap command and capture the output
            result = subprocess.run(
                ["bash", "-c", f"for ip in $(nmap -sn -T5 --min-rate=300 {subnet} -oG - | awk '/Up$/{{print $2}}'); do nmap -T5 -p 9090 --open -oG - $ip | awk '/9090\\/open/{{print $2}}'; done"],
                capture_output=True,
                text=True
            )
            self.scan_button.config(state=tk.NORMAL)
            alive_hosts = result.stdout.strip().split('\n')
            for ip in alive_hosts:
                if ip:
                    self.users.append(ip)
                    self.update_users_display(f"{ip}: Online\n")
            self.notify_users()
        except Exception as e:
            self.update_msg_display(f"Error scanning network: {e}\n")

    def notify_users(self):
        for user in self.users:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((user, PORT))
                s.sendall(f"NOTIFY {self.hostname}".encode())
                s.close()
            except Exception as e:
                print(f"Could not notify {user}: {e}")

    def listen_for_messages(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.local_ip, PORT))
        server_socket.listen(5)
        
        inputs = [server_socket]
        while True:
            readable, _, _ = select.select(inputs, [], [])
            for s in readable:
                if s is server_socket:
                    client_socket, addr = server_socket.accept()
                    inputs.append(client_socket)
                else:
                    try:
                        msg = s.recv(1024).decode()
                        if not msg:
                            inputs.remove(s)
                            s.close()
                        elif msg.startswith("NOTIFY"):
                            _, hostname = msg.split()
                            self.update_msg_display(f"{hostname} is online\n")
                        elif len(msg) > 0:
                            self.update_msg_display(f"{msg}\n")
                    except:
                        inputs.remove(s)
                        s.close()

    def send_message(self):
        msg = self.message_entry.get()
        if msg == "":
            print(self.TAG + "Can not send empty message...")
            return
        self.update_msg_display(f"{self.hostname}: {msg}\n")
        self.message_entry.delete(0, tk.END)
        
        for user in self.users:
            print(self.TAG + ": User: " + user + ", MYIP: " + self.local_ip)
            if user != self.local_ip: # TEST
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((user, PORT))
                    s.sendall(f"{self.hostname}: {msg}".encode())
                    s.close()
                except Exception as e:
                    print(f"Could not send message to {user}: {e}")

    def clear_messages(self):
        self.update_msg_display(clear=True)

    def update_msg_display(self, msg=None, clear=False):
        self.msg_display.config(state=tk.NORMAL)
        if clear:
            self.msg_display.delete(1.0, tk.END)
        else:
            self.msg_display.insert(tk.END, msg)
        self.msg_display.config(state=tk.DISABLED)

    def update_users_display(self, msg=None, clear=False):
        self.users_display.config(state=tk.NORMAL)
        if clear:
            self.users_display.delete(1.0, tk.END)
        else:
            self.users_display.insert(tk.END, msg)
        self.users_display.config(state=tk.DISABLED)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python lanChat.py <interface_name>")
        sys.exit(1)
    
    interface_name = sys.argv[1]
    root = tk.Tk()
    app = LANChat(root, interface_name)
    root.mainloop()
