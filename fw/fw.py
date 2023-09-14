import subprocess

def run_command(command):
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {command}\n{e}")

def initialize_ufw():
    # Enable UFW
    run_command(["sudo", "ufw", "enable"])

    # Deny all incoming and outgoing requests by default
    run_command(["sudo", "ufw", "default", "deny", "incoming"])
    run_command(["sudo", "ufw", "default", "deny", "outgoing"])

    # Allow SSH (change the port if SSH isn't on port 22)
    run_command(["sudo", "ufw", "allow", "22/tcp"])

    # to allow other services, follow the above format
    # For example, to allow HTTP and HTTPS:
    # run_command(["sudo", "ufw", "allow", "80/tcp"])
    # run_command(["sudo", "ufw", "allow", "443/tcp"])

    # Reload UFW for the changes to take effect
    run_command(["sudo", "ufw", "reload"])

    # Print UFW status to confirm
    result = subprocess.run(["sudo", "ufw", "status"], stdout=subprocess.PIPE, text=True)
    print(result.stdout)

if __name__ == "__main__":
    initialize_ufw()
