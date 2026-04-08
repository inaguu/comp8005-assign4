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

BUFFER_SIZE = 1024

import ctypes
from pathlib import Path

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
        self.total_tested = 0

        self.threads = 0
        self.worker_id = socket.gethostname()

        self.found_event = threading.Event()
        self.lock = threading.Lock()

        self.checkpoint = 1000

        self.pwd_context = CryptContext(
            schemes=["bcrypt", "sha512_crypt", "sha256_crypt", "md5_crypt"],
            deprecated="auto"
        )


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

        print(f"[WORKER START]")
        print(f"[CONNECT] Connected to controller at {addr[0]}:{addr[1]}")
        print(f"[CONFIG] Threads: {worker_info.threads}")

    except OSError as e:
        usage(f"Failed to connect to server: {e}")


# ---------------- HEARTBEAT ----------------

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

            response = {
                "type": "hb_response",
                "worker": worker_info.worker_id,
                "tested_since_last": tested
            }

            worker_info.connection.sendall(json.dumps(response).encode())

            print(f"[HEARTBEAT] Sent progress: {tested}")

    except BlockingIOError:
        return
    except (ConnectionResetError, OSError):
        print("[WORKER] Controller disconnected")
        worker_info.found_event.set()
    except json.JSONDecodeError:
        return


# ---------------- CRACKING ----------------

def crack_chunk(worker_info, chunk_start, chunk_end):
    worker_info.timing["start_time"] = time.perf_counter()
    worker_info.found_event.clear()

    algo = worker_info.data.get("algorithm")
    salt = worker_info.data.get("salt")
    options = worker_info.data.get("options", "")
    hashed = worker_info.data.get("password")

    print(f"\n[WORK START]")
    print(f"[CHUNK] Range: {chunk_start} -> {chunk_end}")
    print(f"[ALGO] {algo}")

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

        # print(f"[THREAD-{i}] Assigned {s} -> {e}")

        password_chunk = get_chunk(worker_info, s, e)

        t = threading.Thread(
            target=crack_password,
            args=(worker_info, s, e, password_chunk, full_hash, yescrypt_flag)
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    worker_info.timing["end_time"] = time.perf_counter()
    worker_info.timing["cracking_time"] += (
        worker_info.timing["end_time"] - worker_info.timing["start_time"]
    )

    elapsed = worker_info.timing["cracking_time"]

    if worker_info.total_tested > 0:
        rate = worker_info.total_tested / elapsed
    else:
        rate = 0

    print(f"\n[WORK COMPLETE]")
    print(f"[STATS] Tested: {worker_info.total_tested}")
    print(f"[STATS] Time: {elapsed:.6f}s")
    print(f"[STATS] Throughput: {rate:.2f} passwords/sec")

    if worker_info.found_event.is_set():
        send_found(worker_info)


def crack_password(worker_info, chunk_start, chunk_end, password_chunk, full_hash, yescrypt_flag):
    for i in range(chunk_start, chunk_end):

        if worker_info.found_event.is_set():
            return

        handle_heartbeat(worker_info)

        password = password_chunk[i - chunk_start]

        with worker_info.lock:
            worker_info.tested_since_last += 1
            worker_info.total_tested += 1

            if i % worker_info.checkpoint == 0:
                send_checkpoint(worker_info, i)

        try:
            if yescrypt_flag and verify_yescrypt(password, full_hash):
                worker_info.result = password
                worker_info.found_event.set()
                return

            elif worker_info.pwd_context.verify(password, full_hash):
                worker_info.result = password
                worker_info.found_event.set()
                return

        except Exception:
            continue


# ---------------- CHECKPOINT ----------------

def send_checkpoint(worker_info, current_index):
    msg = {
        "type": "checkpoint",
        "worker": worker_info.worker_id,
        "current": current_index
    }

    try:
        worker_info.connection.sendall(json.dumps(msg).encode())
        # print(f"[CHECKPOINT] Sent at index {current_index}")
    except (BrokenPipeError, OSError):
        print("[WORKER] Connection lost during checkpoint")
        worker_info.found_event.set()


# ---------------- UTILS ----------------

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


def get_chunk(worker_info, chunk_start, chuck_end): 
    chunk_passwords = [] 
    for i in range(chunk_start, chuck_end): 
        chunk_passwords.append(gen_pass(i, worker_info.charset))
    return chunk_passwords


# ---------------- NETWORK ----------------

def request_chunk(worker_info):
    msg = {"type": "get_work"}
    worker_info.connection.sendall(json.dumps(msg).encode())


def receive_chunk(worker_info):
    while True:
        try:
            data = worker_info.connection.recv(BUFFER_SIZE)
            if not data:
                return {"type": "stop"}
            return json.loads(data.decode())
        except BlockingIOError:
            time.sleep(0.05)
        except:
            return {"type": "stop"}


def send_found(worker_info):
    msg = {
        "type": "found",
        "password": worker_info.result,
        "worker": worker_info.worker_id,
        "timing": worker_info.timing,
        "sent_time": time.perf_counter()
    }

    worker_info.connection.sendall(json.dumps(msg).encode())

    print("\n[RESULT]")
    print(f"[FOUND] Password: {worker_info.result}")


# ---------------- MAIN ----------------

def main():
    worker_info = WorkerInfo()

    parse_arguments(worker_info)
    connect_to_server(worker_info)

    while not worker_info.found_event.is_set():
        request_chunk(worker_info)
        worker_info.data = receive_chunk(worker_info)

        if "checkpoint" in worker_info.data:
            worker_info.checkpoint = worker_info.data["checkpoint"]

        msg_type = worker_info.data.get("type")

        if msg_type == "data":
            crack_chunk(
                worker_info,
                worker_info.data["chunk_start"],
                worker_info.data["chunk_end"]
            )

        elif msg_type == "stop":
            print("\n[STOP RECEIVED]")
            break

    worker_info.connection.close()
    print("[WORKER] Exiting gracefully")


if __name__ == "__main__":
    main()