import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import socket
import sys
import json
import string
import argparse
import time
import threading

from passlib.context import CryptContext
import ctypes
from pathlib import Path

BUFFER_SIZE = 1024

# Yescrypt C library
_lib = ctypes.CDLL(str(Path(__file__).with_name("libyescrypt_wrap.so")))
_lib.verify_yescrypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.verify_yescrypt.restype = ctypes.c_int

def verify_yescrypt(password: str, full_hash: str) -> bool:
    rc = _lib.verify_yescrypt(
        password.encode("utf-8"),
        full_hash.encode("utf-8"),
    )
    if rc == -1:
        raise RuntimeError("verify_yescrypt() failed")
    return rc == 1

class WorkerInfo:
    def __init__(self):
        self.connection = None
        self.ip = ""
        self.port = 0
        self.data = {}
        self.result = ""

        self.charset = (
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
        )

        self.timing = {
            "cracking_time": 0.0,
            "start_time": 0.0,
            "end_time": 0.0
        }

        self.tested_since_last = 0
        self.threads = 0

        self.found_event = threading.Event()
        self.lock = threading.Lock()

        self.checkpoint = 1000  # default fallback

        self.pwd_context = CryptContext(
            schemes=[
                "bcrypt",
                "sha512_crypt",
                "sha256_crypt",
                "md5_crypt"
            ],
            deprecated="auto"
        )

# -----------------------
# Basic utility functions
# -----------------------
def usage(message):
    print(message)
    sys.exit(1)

def validate_address(ip, port):
    if ip.lower() == "localhost":
        ip = "127.0.0.1"
    try:
        return ip, int(port)
    except:
        return None

def parse_arguments(worker_info):
    parser = argparse.ArgumentParser(description="Password Cracking Worker")
    parser.add_argument("-c", "--controller", required=True)
    parser.add_argument("-p", "--port", required=True, type=int)
    parser.add_argument("-t", "--thread", type=int, default=1)
    args = parser.parse_args()

    worker_info.ip = args.controller
    worker_info.port = args.port
    worker_info.threads = args.thread

def connect_to_server(worker_info):
    addr = validate_address(worker_info.ip, worker_info.port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(addr)
        sock.setblocking(False)
        worker_info.connection = sock
        print(f"Connected to server at {addr[0]}:{addr[1]}")
    except OSError as e:
        usage(f"Failed to connect to server: {e}")

# -----------------------
# Heartbeat handling
# -----------------------
def handle_heartbeat(worker_info):
    try:
        data = worker_info.connection.recv(BUFFER_SIZE)
        if not data:
            return
        msg = json.loads(data.decode())
        if msg.get("type") == "hb":
            with worker_info.lock:
                tested = worker_info.tested_since_last
                worker_info.tested_since_last = 0
            response = {"type": "hb_response", "tested_since_last": tested}
            try:
                worker_info.connection.sendall(json.dumps(response).encode())
            except (BrokenPipeError, OSError):
                print("[WORKER] Connection lost during heartbeat")
                worker_info.found_event.set()
    except BlockingIOError:
        return
    except (ConnectionResetError, OSError):
        print("[WORKER] Controller disconnected")
        worker_info.found_event.set()
        return
    except json.JSONDecodeError:
        return

def heartbeat_loop(worker_info):
    """Dedicated thread for heartbeat"""
    while not worker_info.found_event.is_set():
        handle_heartbeat(worker_info)
        time.sleep(0.05)

# -----------------------
# Password generation
# -----------------------
def gen_pass(val: int, search_space: str) -> str:
    n = len(search_space)
    size = 1
    block = n
    while val >= block:
        val -= block
        size += 1
        block *= n
    chars = [""] * size
    for i in range(size - 1, -1, -1):
        chars[i] = search_space[val % n]
        val //= n
    return "".join(chars)

# -----------------------
# Checkpoint & result
# -----------------------
def send_checkpoint(worker_info, current_index):
    msg = {"type": "checkpoint", "worker": socket.gethostname(), "current": current_index}
    try:
        worker_info.connection.sendall(json.dumps(msg).encode())
    except (BrokenPipeError, OSError):
        print("[WORKER] Connection lost during checkpoint")
        worker_info.found_event.set()

def send_found(worker_info):
    msg = {
        "type": "found",
        "password": worker_info.result,
        "who": worker_info.connection.getsockname(),
        "timing": worker_info.timing,
        "sent_time": time.perf_counter()
    }
    try:
        worker_info.connection.sendall(json.dumps(msg).encode())
    except (BrokenPipeError, OSError):
        print("[WORKER] Controller disconnected while sending result")

# -----------------------
# Cracking logic
# -----------------------
def crack_password(worker_info, chunk_start, chunk_end, full_hash, yescrypt_flag, thread_id):
    """
    Optimized password cracking loop.
    """
    local_tested = 0

    for i in range(chunk_start, chunk_end):
        if worker_info.found_event.is_set():
            return

        password = gen_pass(i, worker_info.charset)
        local_tested += 1

        # Batch update tested_since_last
        if local_tested >= 100:
            with worker_info.lock:
                worker_info.tested_since_last += local_tested
            local_tested = 0

        # Only thread 0 sends checkpoints
        if i % worker_info.checkpoint == 0:
            send_checkpoint(worker_info, i)

        # Verify password
        try:
            if yescrypt_flag:
                if verify_yescrypt(password, full_hash):
                    worker_info.result = password
                    worker_info.found_event.set()
                    return
            else:
                if worker_info.pwd_context.verify(password, full_hash):
                    worker_info.result = password
                    worker_info.found_event.set()
                    return
        except Exception:
            continue

    # Update any remaining tested count
    if local_tested > 0:
        with worker_info.lock:
            worker_info.tested_since_last += local_tested

def crack_chunk(worker_info, chunk_start, chunk_end):
    """
    Cracking chunk with multiple threads (no thread pool reuse).
    """
    worker_info.timing["start_time"] = time.perf_counter()
    worker_info.found_event.clear()

    print(f"[CHUNK] {chunk_start} -> {chunk_end}") 
    print("Cracking password...")

    algo = worker_info.data.get("algorithm")
    salt = worker_info.data.get("salt")
    options = worker_info.data.get("options", "")
    hashed = worker_info.data.get("password")

    yescrypt_flag = False
    if algo == "2b":
        full_hash = f"${algo}${options}${salt}{hashed}"
    elif algo == "y":
        yescrypt_flag = True
        full_hash = f"${algo}${options}${salt}${hashed}"
    else:
        full_hash = f"${algo}${salt}${hashed}"

    chunk_size = chunk_end - chunk_start
    per_thread = max(1, chunk_size // worker_info.threads)

    threads = []
    for i in range(worker_info.threads):
        s = chunk_start + i * per_thread
        e = chunk_start + (i + 1) * per_thread if i != worker_info.threads - 1 else chunk_end
        t = threading.Thread(
            target=crack_password,
            args=(worker_info, s, e, full_hash, yescrypt_flag, i)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if worker_info.found_event.is_set():
        send_found(worker_info)

    worker_info.timing["end_time"] = time.perf_counter()
    worker_info.timing["cracking_time"] += (
        worker_info.timing["end_time"] - worker_info.timing["start_time"]
    )

# -----------------------
# Server communication
# -----------------------
def request_chunk(worker_info):
    msg = {"type": "get_work"}
    try:
        worker_info.connection.sendall(json.dumps(msg).encode())
    except (BrokenPipeError, OSError):
        print("[WORKER] Controller disconnected during get_work")
        worker_info.found_event.set()

def receive_chunk(worker_info):
    while True:
        try:
            data = worker_info.connection.recv(BUFFER_SIZE)
            if not data:
                return {"type": "stop"}
            return json.loads(data.decode())
        except BlockingIOError:
            time.sleep(0.05)
        except (ConnectionResetError, OSError):
            print("[WORKER] Controller disconnected while receiving chunk")
            return {"type": "stop"}
        except json.JSONDecodeError:
            continue

# -----------------------
# Main
# -----------------------
def main():
    worker_info = WorkerInfo()
    parse_arguments(worker_info)
    connect_to_server(worker_info)

    # Start heartbeat thread
    threading.Thread(target=heartbeat_loop, args=(worker_info,), daemon=True).start()

    while not worker_info.found_event.is_set():
        request_chunk(worker_info)
        worker_info.data = receive_chunk(worker_info)

        if "checkpoint" in worker_info.data:
            worker_info.checkpoint = worker_info.data["checkpoint"]

        msg_type = worker_info.data.get("type")

        if msg_type == "data":
            crack_chunk(worker_info, worker_info.data["chunk_start"], worker_info.data["chunk_end"])
        elif msg_type == "stop":
            print("[STOP RECEIVED]")
            break

    worker_info.connection.close()
    print("[WORKER] Exiting gracefully")

if __name__ == "__main__":
    main()