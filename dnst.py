#!/usr/bin/python3

import socket
import sys
import os

CMD_SOCKET_PATH = "/tmp/nftabels.sock"
BUFFER_SIZE = 1024

def main():
    if not os.path.exists(CMD_SOCKET_PATH):
        print(f"Error: {SOCKET_PATH} does not exist. Is the daemon running?")
        return

    # TODO: show --help instead
    if len(sys.argv) < 2:
        print("Error: Please provide arguments.")
        return

    # Ignore the script name (sys.argv[0])
    message = " ".join(sys.argv[1:])

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect(CMD_SOCKET_PATH)
            client_socket.sendall(message.encode())

            response = b""
            while True:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break  # No more data, the daemon closed the connection
                response += chunk  # Append the chunk to the response
            print(response.decode())

        except ConnectionRefusedError:
            print(f"Could not connect to {CMD_SOCKET_PATH}. Is the daemon running?")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
