import logging
import socket
import paramiko
import threading
import argparse
import os
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = "server.key"  # Replace with a secure key

# --- Logging Setup for Honeypot ---
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Web Honeypot Logging
web_log_handler = RotatingFileHandler("web_honeypot.log", maxBytes=5000000, backupCount=5)
web_log_handler.setFormatter(log_formatter)
web_logger = logging.getLogger("Web_Honeypot")
web_logger.setLevel(logging.INFO)
web_logger.addHandler(web_log_handler)

# SSH Honeypot Logging
ssh_log_handler = RotatingFileHandler("ssh_honeypot.log", maxBytes=5000000, backupCount=5)
ssh_log_handler.setFormatter(log_formatter)
ssh_logger = logging.getLogger("SSH_Honeypot")
ssh_logger.setLevel(logging.INFO)
ssh_logger.addHandler(ssh_log_handler)

# --- Dummy User Database (for deception) ---
users = {"user@example.com": "password123"}

# --- WTForms Configuration ---
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')

# --- Web Honeypot Routes ---
@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    web_logger.info(f"Login form accessed, method: {request.method}")
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        client_ip = request.remote_addr

        # Log every login attempt
        web_logger.info(f"Web login attempt from {client_ip} - Email: {email}, Password: {password}")
        if email in users and users[email] == password:
            session['user'] = email
            flash("Login successful!", "success")
            web_logger.info(f"Successful login from {client_ip} using email: {email}")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")
            web_logger.warning(f"Failed login attempt from {client_ip} - Email: {email}")
    else:
        web_logger.warning("Form validation failed.")
    return render_template("login.html", form=form)

@app.route("/dashboard")
def dashboard():
    if 'user' not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session['user'])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ==========================
# ======= SSH HONEYPOT =====
# ==========================
import sys

SSH_BANNER = 'SSH-2.0-MySSHServer_1.0'
host_key = paramiko.RSAKey(filename='server.key')

# Emulated Shell (from your completed script)
def emulated_shell(channel, client_ip):
    """
    An advanced emulated shell that simulates a realistic Ubuntu environment.
    The prompt displays the current working directory.
    It supports command history (using up/down arrow keys) and additional Ubuntu commands.
    The cd command has been enhanced to handle no arguments (home), relative paths (including . and ..),
    the home shortcut (~), and switching to the previous directory (cd -).
    Additionally, a new 'stat' command has been added to simulate file status checks.
    """
    # Simulated filesystem for 'ls' and 'cd'
    filesystem = {
        "/": [],
        "/home": [],
        "/home/Vincent": ["documents", "downloads", "secret.txt", "notes.md"],
        "/home/Vincent/documents": ["resume.pdf", "project.txt"],
        "/home/Vincent/downloads": ["file1.iso", "file2.zip"]
    }
    current_dir = "/home/Vincent"
    previous_dir = current_dir
    history = []
    history_index = None

    def send_prompt():
        prompt_str = f"Vincent@honeypot:{current_dir}$ "
        channel.send(prompt_str.encode('utf-8'))

    def resolve_path(current, target):
        """
        Resolve the given target path relative to the current directory.
        Supports absolute paths, the home shortcut (~), and relative paths including '.' and '..'.
        Returns the normalized path if it exists in the simulated filesystem (or is '/'); otherwise, returns None.
        """
        if target.startswith("/"):
            candidate = target
        elif target.startswith("~"):
            candidate = "/home/Vincent" + target[1:]
        else:
            candidate = current.rstrip("/") + "/" + target

        parts = candidate.split("/")
        normalized = []
        for part in parts:
            if part == "" or part == ".":
                continue
            elif part == "..":
                if normalized:
                    normalized.pop()
            else:
                normalized.append(part)
        candidate = "/" + "/".join(normalized)
        if candidate in filesystem or candidate == "/":
            return candidate
        else:
            return None

    def simulate_stat(target):
        """
        Simulate the output of the 'stat' command.
        If the target is a directory (exists as a key in filesystem) or is found as a file in a valid directory,
        returns a string similar to Linux's stat output.
        Otherwise, returns None.
        """
        dummy_time = "2025-02-21 12:00:00.000000000 +0000"
        # Check if target is a directory.
        if target in filesystem:
            name = target.rstrip("/").split("/")[-1] or target
            return (
                f"  File: '{name}'\n"
                f"  Size: 4096         Blocks: 8          IO Block: 4096   directory\n"
                f"Device: 803h/2051d      Inode: 7654321     Links: 2\n"
                f"Access: (0755/drwxr-xr-x)  Uid: ( 1000/ vincent)   Gid: ( 1000/ vincent)\n"
                f"Access: {dummy_time}\n"
                f"Modify: {dummy_time}\n"
                f"Change: {dummy_time}\n"
            )
        else:
            # Attempt to split target into directory and file name.
            parts = target.rsplit("/", 1)
            if len(parts) == 2:
                dir_part, file_name = parts
                if dir_part == "":
                    dir_part = "/"
            else:
                dir_part = current_dir
                file_name = parts[0]
            if dir_part in filesystem and file_name in filesystem[dir_part]:
                return (
                    f"  File: '{file_name}'\n"
                    f"  Size: 1024         Blocks: 8          IO Block: 4096   regular file\n"
                    f"Device: 803h/2051d      Inode: 1234567     Links: 1\n"
                    f"Access: (0644/-rw-r--r--)  Uid: ( 1000/ vincent)   Gid: ( 1000/ vincent)\n"
                    f"Access: {dummy_time}\n"
                    f"Modify: {dummy_time}\n"
                    f"Change: {dummy_time}\n"
                )
            else:
                return None

    send_prompt()
    
    while True:
        # Reset for each new command
        command_bytes = b""
        history_index = None

        # Read a full command from the channel
        while True:
            char = channel.recv(1)
            if not char:
                channel.close()
                return

            if char == b'\x1b':
                seq = char + channel.recv(2)
                if seq == b'\x1b[A':  # Up arrow
                    if history:
                        for _ in range(len(command_bytes)):
                            channel.send(b'\b \b')
                        if history_index is None:
                            history_index = len(history) - 1
                        else:
                            history_index = max(0, history_index - 1)
                        command_bytes = history[history_index].encode('utf-8')
                        channel.send(command_bytes)
                    continue
                elif seq == b'\x1b[B':  # Down arrow
                    if history and history_index is not None:
                        for _ in range(len(command_bytes)):
                            channel.send(b'\b \b')
                        history_index = min(len(history) - 1, history_index + 1)
                        command_bytes = history[history_index].encode('utf-8')
                        channel.send(command_bytes)
                    continue
                else:
                    continue

            if char in [b'\x08', b'\x7f']:
                if len(command_bytes) > 0:
                    command_bytes = command_bytes[:-1]
                    channel.send(b'\b \b')
                continue

            if char in [b'\r', b'\n']:
                channel.send(char)
                break

            channel.send(char)
            command_bytes += char

        try:
            command_str = command_bytes.decode('utf-8').strip()
        except UnicodeDecodeError:
            channel.send(b"\nInvalid command encoding.\r\n")
            send_prompt()
            continue

        ssh_logger.info(f"Command '{command_str}' executed by {client_ip}")
        if command_str:
            history.append(command_str)

        # Process the command
        if command_str == "":
            pass
        elif command_str == "exit":
            channel.send(b"\nGoodbye!\r\n")
            channel.close()
            return
        elif command_str == "pwd":
            channel.send(('\n' + current_dir + "\r\n").encode('utf-8'))
        elif command_str == "ls":
            files = filesystem.get(current_dir, [])
            channel.send(('\n' + "  ".join(files) + "\r\n").encode('utf-8'))
        elif command_str.startswith("cd"):
            parts = command_str.split()
            if len(parts) == 1:
                previous_dir = current_dir
                current_dir = "/home/Vincent"
            elif len(parts) == 2:
                target = parts[1]
                if target == "-":
                    current_dir, previous_dir = previous_dir, current_dir
                    channel.send(('\n' + current_dir + "\r\n").encode('utf-8'))
                else:
                    new_dir = resolve_path(current_dir, target)
                    if new_dir is not None:
                        previous_dir = current_dir
                        current_dir = new_dir
                    else:
                        channel.send(f"\ncd: no such file or directory: {target}\r\n".encode('utf-8'))
            else:
                channel.send(b"\nUsage: cd <directory>\r\n")
        elif command_str == "whoami":
            channel.send(b"\nVincent\r\n")
        elif command_str == "uname -a":
            channel.send(b"\nLinux honeypot 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\r\n")
        elif command_str.startswith("cat "):
            parts = command_str.split()
            if len(parts) == 2:
                file = parts[1]
                if file == "secret.txt":
                    channel.send(b"\nThe secret is 'password123'\r\n")
                elif file == "notes.md":
                    channel.send(b"\n# Notes\r\nSome interesting information here...\r\n")
                else:
                    channel.send(f"\ncat: {file}: No such file or directory\r\n".encode('utf-8'))
            else:
                channel.send(b"\nUsage: cat <filename>\r\n")
        elif command_str.startswith("stat "):
            parts = command_str.split()
            if len(parts) == 2:
                target = parts[1]
                # If not an absolute path, resolve relative to current_dir
                if not target.startswith("/"):
                    target = current_dir.rstrip("/") + "/" + target
                file_stat = simulate_stat(target)
                if file_stat:
                    channel.send(('\n' + file_stat + "\n").encode('utf-8'))
                else:
                    channel.send(f"\nstat: cannot stat '{parts[1]}': No such file or directory\r\n".encode('utf-8'))
            else:
                channel.send(b"\nUsage: stat <filename>\r\n")
        elif command_str.startswith("echo "):
            channel.send(('\n' + command_str[5:] + "\r\n").encode('utf-8'))
        elif command_str == "clear":
            channel.send(("\n" * 50).encode('utf-8'))
        elif command_str == "apt update":
            channel.send(('\n' +
                "Hit:1 http://archive.ubuntu.com/ubuntu focal InRelease\r\n"
                "Get:2 http://archive.ubuntu.com/ubuntu focal-updates InRelease [114 kB]\r\n"
                "Get:3 http://archive.ubuntu.com/ubuntu focal-backports InRelease [101 kB]\r\n"
                "Reading package lists... Done\r\n"
                "Building dependency tree... Done\r\n"
                "Reading state information... Done\r\n"
                "All packages are up to date.\r\n"
            ).encode('utf-8'))
        elif command_str in ["ifconfig", "ip a"]:
            channel.send(('\n' +
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                "        inet 172.17.145.101  netmask 255.255.255.0  broadcast 172.17.145.255\r\n"
                "        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>\r\n"
                "        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\r\n"
                "        RX packets 1000  bytes 123456 (123.4 KB)\r\n"
                "        TX packets 800  bytes 654321 (654.3 KB)\r\n"
            ).encode('utf-8'))
        elif command_str == "netstat":
            channel.send(('\n' +
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
                "tcp        0      0 172.17.145.101:2250     0.0.0.0:*               LISTEN\r\n"
            ).encode('utf-8'))
        elif command_str == "lsb_release -a":
            channel.send(('\n' +
                "No LSB modules are available.\r\n"
                "Distributor ID: Ubuntu\r\n"
                "Description:    Ubuntu 20.04.6 LTS\r\n"
                "Release:        20.04\r\n"
                "Codename:       focal\r\n"
            ).encode('utf-8'))
        elif command_str == "df -h":
            channel.send(('\n' +
                "Filesystem      Size  Used Avail Use% Mounted on\r\n"
                "/dev/sda1        50G   15G   33G  32% /\r\n"
                "tmpfs           3.9G     0  3.9G   0% /dev/shm\r\n"
            ).encode('utf-8'))
        elif command_str == "ps aux":
            channel.send(('\n' +
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
                "root         1  0.0  0.1  22528  4104 ?        Ss   10:00   0:02 /sbin/init\r\n"
                "vincent   1234  0.1  0.5  54321 12345 ?        Sl   10:01   0:05 /usr/bin/python3 honeypot.py\r\n"
            ).encode('utf-8'))
        elif command_str == "top":
            channel.send(('\n' +
                "top - 10:05:00 up 10 days,  3:21,  2 users,  load average: 0.00, 0.01, 0.05\r\n"
                "Tasks: 123 total,   1 running, 122 sleeping,   0 stopped,   0 zombie\r\n"
                "Cpu(s):  1.0% us,  0.5% sy,  0.0% ni, 98.0% id,  0.0% wa,  0.0% hi,  0.5% si,  0.0% st\r\n"
                "Mem:   2048000k total,  1024000k used,  1024000k free,   512000k buffers\r\n"
            ).encode('utf-8'))
        elif command_str.startswith("sudo "):
            channel.send(b"\nsudo: a password is required\n")
        elif command_str == "history":
            hist_output = "\r\n".join(f"{i+1}  {cmd}" for i, cmd in enumerate(history)) + "\r\n"
            channel.send(hist_output.encode('utf-8'))
        elif command_str == "help":
            channel.send(('\n' +
                "Available commands:\r\n"
                "pwd, ls, cd, stat, whoami, uname -a, cat, echo, clear, apt update,\r\n"
                "ifconfig/ip a, netstat, lsb_release -a, df -h, ps aux, top, sudo, history, help, exit\r\n"
            ).encode('utf-8'))
        else:
            channel.send(f"\n{command_str}: command not found\r\n".encode('utf-8'))
        
        send_prompt()

# SSH Server + Sockets
class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip 
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auth(self):
        return "password"

    def check_auth_password(self, username, password):
        ssh_logger.info(f"SSH login attempt from {self.client_ip} - Username: {username}, Password: {password}")
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True

def client_handle(client, addr, username=None, password=None):
    client_ip = addr[0]
    ssh_logger.info(f"{client_ip} has connected to the SSH honeypot.")
    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = SSHServer(client_ip=client_ip, input_username=username, input_password=password)
        transport.add_server_key(host_key)
        transport.start_server(server=server)
        channel = transport.accept(100)  # 100 seconds
        if channel is None:
            ssh_logger.error("No channel was opened.")
        banner = "\nWelcome! "
        channel.send(banner.encode('utf-8'))
        emulated_shell(channel, client_ip=client_ip)
    except Exception as error:
        ssh_logger.error(f"Error: {error}")
    finally:
        try:
            transport.close()
        except Exception as error:
            ssh_logger.error(f"Error closing transport: {error}")
        client.close()

def start_ssh_honeypot(address="0.0.0.0", port=2228, username=None, password=None):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))
    socks.listen(100)
    ssh_logger.info(f"SSH honeypot listening on {address}:{port}")
    while True:
        try:
            client, addr = socks.accept()
            ssh_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_thread.daemon = True
            ssh_thread.start()
        except Exception as error:
            ssh_logger.error(f"Error: {error}")

# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WEB and SSH Honeypot")
    parser.add_argument("--ssh", action="store_true", help="Run SSH honeypot")
    parser.add_argument("--web", action="store_true", help="Run Web honeypot")
    parser.add_argument("--address", type=str, default=os.getenv("HONEYPOT_ADDRESS", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("HONEYPOT_PORT", 2228)))
    parser.add_argument("--username", type=str, default=os.getenv("HONEYPOT_USERNAME"))
    parser.add_argument("--password", type=str, default=os.getenv("HONEYPOT_PASSWORD"))
    parser.add_argument("--webport", type=int, default=int(os.getenv("WEB_PORT", 5006)))
    args = parser.parse_args()

    # By default, run both if none selected
    run_ssh = args.ssh or not (args.ssh or args.web)
    run_web = args.web or not (args.ssh or args.web)

    threads = []
    if run_ssh:
        ssh_thread = threading.Thread(
            target=start_ssh_honeypot,
            kwargs={
                'address': args.address,
                'port': args.port,
                'username': args.username,
                'password': args.password
            }
        )
        ssh_thread.daemon = True
        ssh_thread.start()
        threads.append(ssh_thread)
        print(f"[*] SSH honeypot running at {args.address}:{args.port}")

    if run_web:
        print(f"[*] Web honeypot running at 0.0.0.0:{args.webport}")
        app.run(debug=True, use_reloader=False, host="0.0.0.0", port=args.webport)

    for t in threads:
        t.join()

