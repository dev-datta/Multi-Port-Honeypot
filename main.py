import socket
import threading
import base64
from ftplib import FTP
import paramiko
import ssl
import multiprocessing
import datetime

class SSH_Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        print(f"SSH - {username}:{password}")
        log_data = f"{datetime.datetime.now()} - SSH - {username}:{password}\n"
        write_to_log(log_data, 22)  # Passing port number
        print(log_data)
        # Access client_sock using self.client_sock here
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        # Access client_sock using self.client_sock here
        return paramiko.AUTH_FAILED

class Telnet_Server:
    def handle_connection(self, client_sock, server_key):
        print("Telnet - Connection established.")
        # Add Telnet connection logic here
        client_sock.send(b"Microsoft Telnet> ")

        try:
            # Initialize an empty string to store the received data
            received_data = b""

            # Receive data from the client continuously until client disconnects
            while True:
                # Receive data from the client
                data = client_sock.recv(1024)  # Receive up to 1024 bytes at a time
                if not data:
                    break  # No more data to receive, exit the loop

                # Append the received data to the received_data string
                received_data += data

                # Decode the received data
                decoded_data = data.decode('utf-8')

                # Check if the received data contains a newline character
                if '\n' in decoded_data:
                    # If a newline character is found, process the command
                    self.process_command(received_data.strip(), client_sock)
                    # Clear received_data for the next command
                    received_data = b""

            client_sock.close()
        except Exception as e:
            print(f"An error occurred: {e}")
            client_sock.close()

    def process_command(self, command, client_sock):
        # Split the command into words
        log_data = f"{datetime.datetime.now()} - Telnet - Connection established with {client_sock.getpeername()}\n"
        words = command.split()

        # Print each word
        for word in words:
            word_str = word.decode('utf-8')
            print(f"Telnet - Received command: {word}")

            write_to_telnet_log(word_str, 23, log_data)

        # Respond with an "Invalid command" message
        client_sock.send("Invalid command. Enter '?' for help.\n".encode('utf-8'))

def write_to_telnet_log(word, port, log_data):
    log_file = f"log_{port}.txt"  # Name of the log file with port number
    with open(log_file, 'a') as file:
        file.write(log_data + word + '\n')

class Http_Server:
    def handle_connection(self, client_sock, server_key):
        print(f"HTTP - Connection established with {client_sock.getpeername()}")
        log_data = f"{datetime.datetime.now()} - HTTPS - Connection established with {client_sock.getpeername()}\n"
        write_to_log(log_data, 80)  # Passing port number
        try:
            # Add HTTP connection logic here
            client_sock.send(b"HTTP/1.1 401 Unauthorized\r\n")
            client_sock.send(b"WWW-Authenticate: Basic realm=\"Restricted\"\r\n\r\n")
            client_sock.send(b"Enter your username and password:\r\n")

            # Receive data
            data = client_sock.recv(1024).strip()
            print(f"HTTP - Received data: {data}")

            # Parse Authorization header
            auth_headers = data.split(b'\r\n')
            auth_header = None

            # Find Authorization header
            for header in auth_headers:
                if header.startswith(b"Authorization: Basic"):
                    auth_header = header
                    break

            if auth_header:
                encoded_credentials = auth_header.split(b" ")[2]
                decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
                username, password = decoded_credentials.split(":")
                print(f"HTTP - User ID: {username}, Password: {password}")
                log_data = f"{datetime.datetime.now()} - HTTP - User ID: {username}, Password: {password}\n"
                write_to_log(log_data, 80)  # Passing port number

            client_sock.send(b"HTTP/1.1 200 OK\r\n\r\nAuthenticated successfully!\n")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            client_sock.close()

class Https_Server:
    def handle_connection(self, client_sock, server_key):
        print(f"HTTPS - Connection established with {client_sock.getpeername()}")
        log_data = f"{datetime.datetime.now()} - HTTPS - Connection established with {client_sock.getpeername()}\n"
        write_to_log(log_data, 443)  # Passing port number
        try:
            # Create an SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile='server.crt', keyfile='server.key')

            # Wrap the client socket with SSL
            ssl_client_sock = context.wrap_socket(client_sock, server_side=True)

            # Handle HTTPS communication
            self.handle_https_request(ssl_client_sock, server_key)

        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            client_sock.close()

    def handle_https_request(self, ssl_client_sock, server_key):
        try:
            # Add HTTPS connection logic here
            ssl_client_sock.send(b"HTTP/1.1 401 Unauthorized\r\n")
            ssl_client_sock.send(b"WWW-Authenticate: Basic realm=\"Restricted\"\r\n\r\n")
            ssl_client_sock.send(b"Enter your username and password:\r\n")

            # Receive data
            data = ssl_client_sock.recv(1024).strip()
            print(f"HTTPS - Received data: {data}")

            if len(data) < 4:
                raise Exception("Malformed request: Data is too short")

            # Parse Authorization header
            auth_headers = data.split(b'\r\n')
            auth_header = None

            # Find Authorization header
            for header in auth_headers:
                if header.startswith(b"Authorization: Basic"):
                    auth_header = header
                    break

            if auth_header:
                encoded_credentials = auth_header.split(b" ")[2]
                decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
                username, password = decoded_credentials.split(":")
                print(f"HTTPS - User ID: {username}, Password: {password}")
                log_data = f"{datetime.datetime.now()} - HTTPS - User ID: {username}, Password: {password}\n"
                write_to_log(log_data, 443)  # Passing port number

            ssl_client_sock.send(b"HTTP/1.1 200 OK\r\n\r\nAuthenticated successfully!\n")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            ssl_client_sock.shutdown(socket.SHUT_RDWR)
            ssl_client_sock.close()

class Ftp_Server:
    def __init__(self):
        self.certfile = 'server.crt'
        self.keyfile = 'server.key'

    def handle_connection(self, client_sock, server_key):
        print("FTP - Connection established.")
        try:
            # User authentication
            max_attempts = 3
            attempts = 0
            incorrect_attempts = []

            while attempts < max_attempts:
                username, password = self.prompt_login(client_sock)
                incorrect_attempts.append((username, password))
                
                if self.authenticate(username, password):
                    # Successfully authenticated
                    client_sock.sendall(b"230 Login successful.\n")

                    # Display fabricated directory listing
                    client_sock.sendall(b"230-Directory listing:\n")
                    client_sock.sendall(b"drwxr-xr-x   2 owner  group       1024 Jan  1 00:00 inbox\n")
                    client_sock.sendall(b"-rw-r--r--   1 owner  group       2048 Dec 31 23:59 Reports.zip\n")
                    client_sock.sendall(b"-rw-r--r--   1 owner  group       1024 Dec 31 23:59 Account.csv\n")
                    client_sock.sendall(b"-rw-r--r--   1 owner  group       1024 Dec 31 23:59 Factories.csv\n")
                    client_sock.sendall(b"230 End of directory listing.\n")

                    # Close the connection gracefully
                    client_sock.close()
                    return
                else:
                    # Incorrect login, increment attempts and prompt again
                    attempts += 1
                    remaining_attempts = max_attempts - attempts
                    client_sock.sendall(f"530 Login incorrect. {remaining_attempts} attempts left.\n".encode('utf-8'))

            # Log incorrect attempts after max_attempts
            if attempts >= max_attempts:
                self.log_failed_attempts(incorrect_attempts, client_sock)

        except Exception as e:
            print(f"An error occurred: {e}")
            client_sock.close()

        # If the loop ends without successful authentication, close the connection
        client_sock.sendall(b"530 Maximum login attempts exceeded. Connection closed.\n")
        client_sock.close()

    def prompt_login(self, client_sock):
        client_sock.sendall(b"331 Please specify the username.\n")
        username = client_sock.recv(1024).strip().decode('latin-1')
        client_sock.sendall(b"331 Please specify the password.\n")
        password = client_sock.recv(1024).strip().decode('latin-1')
        return username, password

    def authenticate(self, username, password):
        # Simulate basic authentication (replace with actual authentication logic)
        return username == "admin" and password == "admin"

    def log_failed_attempts(self, attempts, client_sock):
        connection_info = client_sock.getpeername()
        log_data = f"{datetime.datetime.now()} - FTP - Connection from {connection_info[0]}:{connection_info[1]} - Failed login attempts:\n"
        for attempt in attempts:
            log_data += f"Username: {attempt[0]}, Password: {attempt[1]}\n"

        write_to_ftp_log(log_data, 21)  # Passing port number

def write_to_ftp_log(log_data, port):
    log_file = f"log_{port}.txt"  # Name of the log file with port number
    with open(log_file, 'a') as file:
        file.write(log_data)

def handle_ssh_connection(client_sock, server_key):
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(server_key)
    ssh = SSH_Server()
    ssh.client_sock = client_sock  # Assign client_sock to the SSH_Server instance
    transport.start_server(server=ssh)

def handle_connection(client_sock):
    print("Connection established on other port.")
    # Add connection logic for other ports here
    data = client_sock.recv(1024)  # Receive data from the client

def write_to_log(log_data, port):
    log_file = f"log_{port}.txt"  # Name of the log file with port number
    with open(log_file, 'a') as file:
        file.write(log_data)

# Main function
def main():
    # Start servers on different ports
    ports = [22, 23, 80, 443, 21]
    handlers = {
        22: handle_ssh_connection,
        23: Telnet_Server().handle_connection,
        80: Http_Server().handle_connection,
        443: Https_Server().handle_connection,
        21: Ftp_Server().handle_connection
    }

    # Start servers
    for port in ports:
        multiprocessing.Process(target=start_server, args=(port, handlers[port])).start()

# Start server function
def start_server(port, handle_func):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', port))
    server_sock.listen(100)

    server_key = paramiko.RSAKey.generate(2048)

    print(f"Listening on port {port}")

    while True:
        client_sock, client_addr = server_sock.accept()
        print(f"Connection {client_addr[0]}:{client_addr[1]} on port {port}")

        t = threading.Thread(target=handle_func, args=(client_sock, server_key))
        t.start()

if __name__ == "__main__":
    main()
