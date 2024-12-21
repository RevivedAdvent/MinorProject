from kivy.uix.screenmanager import Screen
from kivy.properties import StringProperty, BooleanProperty
from kivy.clock import mainthread
import subprocess
import threading
import socket
import time
from utils.encryption import ZeroKnowledgeEncryption

class Home(Screen):
    status_text = StringProperty("Server Status: DISCONNECTED")
    logout_enabled = BooleanProperty(True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # VPN Configuration dictionary to map server names to their OVPN file paths
        self.vpn_servers = {
            "Vietnam": "config/Vietnam.ovpn",
            "Japan_alt": "config/Japan_alt.ovpn"
        }
        self.ovpn_path = "config/Vietnam.ovpn"
        self.is_connecting = False
        self.is_connected = False  # Flag to track connection status
        self.connection_thread = None
        self.network_monitor_thread = None
        self.monitoring_active = False
        self.encryption = ZeroKnowledgeEncryption(password="user_secure_password")  # Replace with dynamic input

    def connect_to_vpn(self, ovpn_path=None):
        """
        Enhanced VPN connection method with conditional fallback
        Only switches network if exactly one connection fails
        """
        # Use the default Japan.ovpn first
        ovpn_path = ovpn_path or self.ovpn_path
        
        # Set connecting flag and disable logout
        self.is_connecting = True
        self.logout_enabled = False
        
        # Update status to connecting
        self.update_status("VPN Connecting...")
        
        def attempt_vpn_connection():
            try:
                # Track connection attempts and results
                connection_attempts = []
                
                # Attempt connection with primary VPN config
                result_primary = self.run_openvpn_connection(ovpn_path)
                connection_attempts.append(result_primary)
                
                # If primary fails, try alternative only if it's a different path
                alt_path = self.vpn_servers.get("Japan_alt")
                if not result_primary and alt_path and alt_path != ovpn_path:
                    result_alt = self.run_openvpn_connection(alt_path)
                    connection_attempts.append(result_alt)
                
                # Determine final connection status
                if connection_attempts.count(False) == 1 and connection_attempts.count(True) == 1:
                    # Success: exactly one connection worked
                    self.update_status("VPN Connected")
                    self.is_connecting = False
                    self.is_connected = True
                    self.logout_enabled = True
                    self.start_network_monitoring()  # Start monitoring after successful connection
                elif all(attempt is False for attempt in connection_attempts):
                    # Failure: all attempts failed
                    self.update_status("VPN Connection Failed")
                    self.is_connecting = False
                    self.is_connected = False
                    self.logout_enabled = True

            except Exception as e:
                self.update_status(f"VPN Connection Error: {str(e)}")
                self.is_connecting = False
                self.is_connected = False
                self.logout_enabled = True

        # Run connection in a separate thread
        self.connection_thread = threading.Thread(target=attempt_vpn_connection)
        self.connection_thread.start()

    def run_openvpn_connection(self, ovpn_path):
        try:
            process = subprocess.Popen(
                ['sudo', 'openvpn', '--config', ovpn_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                universal_newlines=True
            )

            for line in process.stdout:
                print(line.strip())
                if "Initialization Sequence Completed" in line:
                    self.update_status("VPN Connected")
                    self.is_connecting = False
                    self.is_connected = True
                    self.logout_enabled = True
                    return True
                if "Exiting due to fatal error" in line:
                    process.terminate()
                    return False

            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def disconnect_vpn(self):
        try:
            subprocess.run(['sudo', 'killall', 'openvpn'], check=True)
            self.update_status("VPN Disconnected Successfully")
            self.logout_enabled = True
            self.is_connecting = False
            self.is_connected = False
            self.monitoring_active = False  # Stop monitoring on disconnect
        except subprocess.CalledProcessError:
            self.update_status("No Active VPN Connection")
        except Exception as e:
            self.update_status(f"Disconnect Error: {str(e)}")

    def start_network_monitoring(self):
        if not self.network_monitor_thread or not self.network_monitor_thread.is_alive():
            self.monitoring_active = True
            self.network_monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
            self.network_monitor_thread.start()

    def monitor_network(self):
        current_ip = self.get_current_ip()
        while self.monitoring_active:
            try:
                time.sleep(5)  # Avoid immediate checks to prevent false triggers
                new_ip = self.get_current_ip()
                if new_ip and new_ip != current_ip and self.is_connected:  # Only reconnect if already connected
                    current_ip = new_ip
                    print(f"Network switched. New IP: {current_ip}. Reconnecting VPN...")
                    self.connect_to_vpn()
            except Exception as e:
                print(f"Error monitoring network: {e}")

    def get_current_ip(self):
        try:
            # Use a socket to get the primary IP address
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception as e:
            print(f"Error retrieving IP: {e}")
            return None

    def encrypt_and_send(self, data):
        encrypted = self.encryption.encrypt_data(data)
        print(f"Encrypted data: {encrypted}")
        return encrypted

    def receive_and_decrypt(self, encrypted_data, salt):
        decrypted = self.encryption.decrypt_data(encrypted_data, salt)
        print(f"Decrypted data: {decrypted}")
        return decrypted

    def attempt_logout(self):
        if not self.is_connecting:
            self.manager.current = 'login'
            self.manager.get_screen('login').clear_fields()

    @mainthread
    def update_status(self, message):
        print(message)
        self.status_text = message