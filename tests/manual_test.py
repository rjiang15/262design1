#!/usr/bin/env python3
import socket

HOST = "127.0.0.1"  # adjust if needed
PORT = 54400        # adjust if needed

def manual_test():
    # Create a TCP socket and connect to the server.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # Prepare a command string (note the newline at the end).
    command = "SHOW_DB\n"
    data = command.encode("utf-8")
    bytes_to_send = len(data)
    print(f"Sending command: {command.strip()}")
    print(f"Bytes to send: {bytes_to_send}")
    
    # Send the data to the server.
    s.sendall(data)
    
    # Set a timeout so that we do not block forever waiting for data.
    s.settimeout(1.0)
    
    total_received = 0
    response_parts = []
    
    # Read from the server until a timeout occurs.
    while True:
        try:
            part = s.recv(4096)
        except socket.timeout:
            # If no data is received for 1 second, break out of the loop.
            break
        if not part:
            break
        total_received += len(part)
        response_parts.append(part)
    
    response = b"".join(response_parts).decode("utf-8").strip()
    
    print(f"Response from server:\n{response}")
    print(f"Total bytes received: {total_received}")
    
    s.close()

if __name__ == "__main__":
    manual_test()
