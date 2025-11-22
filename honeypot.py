import socket
import datetime

HOST = "0.0.0.0"
PORT = 2222  # Fake SSH port

def log_attempt(ip, username, password):
    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("logs/attempts.log", "a") as f:
        f.write(f"[{time_now}] {ip} tried {username}:{password}\n")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)

    print(f"[+] HoneyLogin is running on port {PORT}...")

    while True:
        conn, addr = sock.accept()
        ip = addr[0]

        conn.send(b"SSH-2.0-OpenSSH_8.9\r\n")
        conn.send(b"username: ")
        username = conn.recv(1024).strip().decode()

        conn.send(b"password: ")
        password = conn.recv(1024).strip().decode()

        log_attempt(ip, username, password)

        conn.send(b"Access denied.\n")
        conn.close()

if __name__ == "__main__":
    main()
