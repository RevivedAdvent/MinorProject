from kivy.uix.screenmanager import Screen
from kivy.properties import StringProperty, BooleanProperty
from kivy.clock import mainthread
import subprocess
import threading

class Home(Screen):
    status_text = StringProperty("Server Status: DISCONNECTED")
    logout_enabled = BooleanProperty(True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # VPN Configuration dictionary to map server names to their OVPN file paths
        self.vpn_servers = {
            "Japan": "config/Japan.ovpn",
            "Japan_alt": "config/Japan_alt.ovpn"
        }
        # Default path 
        self.ovpn_path = "config/Japan.ovpn"
        
        # Connection state tracking
        self.is_connecting = False
        self.connection_thread = None
        
    def connect_to_vpn(self, ovpn_path=None):
        """
        Enhanced VPN connection method with fallback
        """
        # Use the default Vietnam.ovpn first
        ovpn_path = ovpn_path or self.ovpn_path
        
        # Set connecting flag and disable logout
        self.is_connecting = True
        self.logout_enabled = False
        
        # Update status to connecting
        self.update_status("VPN Connecting...")
        
        def attempt_vpn_connection():
            try:
                # First attempt with primary VPN config
                result = self.run_openvpn_connection(ovpn_path)
                if result:
                    return
                
                # If first attempt fails, try alternative
                alt_path = self.vpn_servers.get("Japan_alt")
                if alt_path and alt_path != ovpn_path:
                    result = self.run_openvpn_connection(alt_path)
                    if result:
                        return
                
                # If both attempts fail
                self.update_status("VPN Connection Failed")
                self.is_connecting = False
                self.logout_enabled = True

            except Exception as e:
                self.update_status(f"VPN Connection Error: {str(e)}")
                self.is_connecting = False
                self.logout_enabled = True

        # Run connection in a separate thread
        self.connection_thread = threading.Thread(target=attempt_vpn_connection)
        self.connection_thread.start()

    def run_openvpn_connection(self, ovpn_path):
        """
        Run OpenVPN connection and check for successful initialization
        """
        try:
            # Run OpenVPN process
            process = subprocess.Popen(
                ['sudo', 'openvpn', '--config', ovpn_path], 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                universal_newlines=True
            )
            
            # Monitor output for successful connection
            for line in process.stdout:
                print(line.strip())  # Log all output
                
                # Check for successful initialization
                if "Initialization Sequence Completed" in line:
                    self.update_status("VPN Connected")
                    self.is_connecting = False
                    self.logout_enabled = True
                    return True
                
                # Check for connection errors
                if "Exiting due to fatal error" in line:
                    process.terminate()
                    return False
            
            return False
        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def disconnect_vpn(self):
        """
        Disconnect VPN
        """
        try:
            # Use subprocess to run sudo killall openvpn
            subprocess.run(['sudo', 'killall', 'openvpn'], check=True)
            
            # Update UI
            self.update_status("VPN Disconnected Successfully")
            self.logout_enabled = True
            self.is_connecting = False
        except subprocess.CalledProcessError:
            self.update_status("No Active VPN Connection")
        except Exception as e:
            self.update_status(f"Disconnect Error: {str(e)}")

    def attempt_logout(self):
        # Logout is only allowed when not connecting or connected to VPN
        if not self.is_connecting:
            self.manager.current = 'login'
            # Clear login fields when returning to login screen
            self.manager.get_screen('login').clear_fields()

    @mainthread
    def update_status(self, message):
        """
        Update status text in the UI
        """
        print(message)  # Also print to console for debugging
        self.status_text = message