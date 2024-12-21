from kivy.uix.screenmanager import Screen
from kivy.properties import StringProperty, BooleanProperty
from kivy.clock import mainthread
import subprocess
import threading
import time
import os
from utils.encryption import ZeroKnowledgeEncryption

class Home(Screen):
    """
    Home screen for VPN application with stable connection management.
    Handles VPN connections without automatic network monitoring for more
    predictable behavior.
    """
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
        # Connection state tracking
        self.is_connecting = False
        self.is_connected = False
        self.connection_thread = None
        # Process management
        self.vpn_process = None
        self.process_lock = threading.Lock()
        # Encryption setup
        self.encryption = ZeroKnowledgeEncryption(password="user_secure_password")

    def connect_to_vpn(self, ovpn_path=None):
        """
        Establishes VPN connection with conservative fallback behavior.
        Only attempts alternate configuration if primary connection explicitly fails.
        """
        if self.is_connecting or self.is_connected:
            self.update_status("Connection already in progress or established")
            return

        ovpn_path = ovpn_path or self.ovpn_path
        self.is_connecting = True
        self.logout_enabled = False
        self.update_status("VPN Connecting...")

        def attempt_vpn_connection():
            try:
                # Clean up any existing connections first
                self.cleanup_existing_connections()
                
                # Attempt primary connection
                result_primary = self.run_openvpn_connection(ovpn_path)
                
                # Only attempt alternate if primary explicitly failed
                if result_primary == False:  # Must be exactly False, not None or other values
                    alt_path = self.vpn_servers.get("Japan_alt")
                    if alt_path and alt_path != ovpn_path:
                        self.update_status("Primary connection failed, trying alternate...")
                        time.sleep(2)  # Brief pause before retry
                        self.run_openvpn_connection(alt_path)

                # If still not connected after attempts, update status
                if not self.is_connected:
                    self.update_status("VPN Connection Failed")
                    self.cleanup_connection()

            except Exception as e:
                self.update_status(f"VPN Connection Error: {str(e)}")
                self.cleanup_connection()

        self.connection_thread = threading.Thread(target=attempt_vpn_connection)
        self.connection_thread.daemon = True
        self.connection_thread.start()

    def run_openvpn_connection(self, ovpn_path):
        """
        Executes OpenVPN connection with explicit failure detection.
        Returns:
            - True: Connection successful
            - False: Connection explicitly failed (should try alternate)
            - None: Uncertain state (should not try alternate)
        """
        try:
            if not os.path.exists(ovpn_path):
                self.update_status(f"Error: Config file not found: {ovpn_path}")
                return None

            with self.process_lock:
                self.vpn_process = subprocess.Popen(
                    ['sudo', '/usr/sbin/openvpn', '--config', os.path.abspath(ovpn_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1
                )

            connection_timeout = 30
            start_time = time.time()

            # Define explicit failure conditions
            failure_indicators = [
                "connection reset",
                "connection refused",
                "cannot load certificate",
                "error opening configuration file",
                "all tap-windows adapters on this system are currently in use",
                "cannot open /dev/net/tun",
                "auth-failure",
                "tls-error",
                "initialization sequence failed"
            ]

            while time.time() - start_time < connection_timeout:
                if self.vpn_process.poll() is not None:
                    error_output = self.vpn_process.stderr.read()
                    if error_output:
                        print(f"OpenVPN Error: {error_output}")
                        if any(indicator in error_output.lower() for indicator in failure_indicators):
                            return False
                    break

                line = self.vpn_process.stdout.readline().strip()
                if not line:
                    continue

                print(f"OpenVPN: {line}")

                if "Initialization Sequence Completed" in line:
                    with self.process_lock:
                        self.is_connected = True
                        self.is_connecting = False
                        self.logout_enabled = True
                        self.update_status("VPN Connected")
                        return True

                if any(indicator in line.lower() for indicator in failure_indicators):
                    print(f"Explicit failure detected: {line}")
                    self.cleanup_connection()
                    return False

            self.cleanup_connection()
            return None

        except Exception as e:
            print(f"Connection error: {e}")
            self.cleanup_connection()
            return None

    def cleanup_existing_connections(self):
        """Safely terminates any existing OpenVPN processes."""
        try:
            # Check if OpenVPN is running
            check_process = subprocess.run(
                ['pgrep', 'openvpn'],
                capture_output=True,
                text=True
            )
            
            if check_process.stdout.strip():
                # Kill only if process exists
                subprocess.run(
                    ['sudo', 'killall', 'openvpn'],
                    check=False,
                    stderr=subprocess.PIPE
                )
                time.sleep(2)
        except Exception as e:
            print(f"Cleanup error: {e}")

    def cleanup_connection(self):
        """Cleans up connection state and terminates VPN process."""
        with self.process_lock:
            self.is_connecting = False
            self.is_connected = False
            self.logout_enabled = True

            if self.vpn_process:
                try:
                    # Try graceful termination first
                    self.vpn_process.terminate()
                    time.sleep(1)
                    
                    # Force kill if still running
                    if self.vpn_process.poll() is None:
                        subprocess.run(['sudo', 'killall', 'openvpn'], 
                                    check=False,
                                    stderr=subprocess.PIPE)
                except Exception as e:
                    print(f"Process cleanup error: {e}")
                finally:
                    self.vpn_process = None

    def disconnect_vpn(self):
        """Disconnects VPN and cleans up resources."""
        if self.is_connected or self.is_connecting:
            try:
                self.cleanup_connection()
                self.cleanup_existing_connections()
                self.update_status("VPN Disconnected Successfully")
            except Exception as e:
                self.update_status(f"Disconnect Error: {str(e)}")
        else:
            self.update_status("No Active VPN Connection")

    def encrypt_and_send(self, data):
        """Encrypts data for transmission."""
        encrypted = self.encryption.encrypt_data(data)
        print(f"Encrypted data: {encrypted}")
        return encrypted

    def receive_and_decrypt(self, encrypted_data, salt):
        """Decrypts received data."""
        decrypted = self.encryption.decrypt_data(encrypted_data, salt)
        print(f"Decrypted data: {decrypted}")
        return decrypted

    def attempt_logout(self):
        """Handles user logout attempt."""
        if not self.is_connecting:
            self.manager.current = 'login'
            self.manager.get_screen('login').clear_fields()

    @mainthread
    def update_status(self, message):
        """Updates the UI status message."""
        print(message)
        self.status_text = message