import socket
import argparse
from concurrent.futures import ThreadPoolExecutor


def scan_port(ip, port):
    """Scan a single port on the given IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)  # Set a timeout for the socket connection
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:  # Port is open
                return port
        except (socket.error, OSError):
            return None  # Handle connection errors gracefully
    return None  # Port is closed or unreachable


def scan_ports(ip, start_port, end_port):
    """Scan a range of ports on the given IP address."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port 
            for port in range(start_port, end_port + 1)
        }
        for future in futures:
            port = future.result()
            if port is not None:
                open_ports.append(port)
    return open_ports


def main():
    """Main function to handle input and execute port scanning."""
    parser = argparse.ArgumentParser(description="Simple TCP Port Scanner")
    parser.add_argument("target", 
                       help="Target IP address or domain name")
    parser.add_argument("--start", type=int, default=1, 
                       help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, 
                       help="End port (default: 1024)")
    
    args = parser.parse_args()
    
    target = args.target
    start_port = args.start
    end_port = args.end
    
    try:
        print(f"Scanning {target} for open ports from {start_port} "
              f"to {end_port}...")
        open_ports = scan_ports(target, start_port, end_port)
        
        if open_ports:
            port_list = ', '.join(map(str, open_ports))
            print(f"Open ports on {target}: {port_list}")
        else:
            print(f"No open ports found on {target}.")
    except socket.gaierror:
        print(f"Error: Invalid host '{target}'. Please check the input.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()