import os
import subprocess

def disable_ipv6():
    commands = [
        "sysctl -w net.ipv6.conf.all.disable_ipv6=1",
        "sysctl -w net.ipv6.conf.default.disable_ipv6=1"
    ]
    
    for command in commands:
        try:
            print(f"Executing: {command}")
            # Execute command without sudo
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            print(result.stdout.strip())
        except subprocess.CalledProcessError as e:
            print(f"Error executing {command}:")
            print(e.stderr.strip())

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root. Use 'sudo' or switch to the root user.")
    else:
        disable_ipv6()
