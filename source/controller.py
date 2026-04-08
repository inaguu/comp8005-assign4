import socket
import sys
import json
import argparse
import time
import threading

BUFFER_SIZE = 1024

class ControllerInfo:
    def __init__(self):
        self.socket = None
        self.connection = None
        self.ip = "0.0.0.0"  # IPv6 unspecified address
        self.port = 0
        self.username = ""
        self.shadowfile = ""
        self.data = {
            "type": "data",
            "algorithm": "",
            "options": "",
            "salt": "",
            "password": ""
        }
        self.result = []
        
        self.start_time = 0.0
        self.end_time = 0.0

        self.parsing_time = 0.0
        self.dispatch_time = 0.0
        self.chunk_assign_time = 0.0

        self.total_chunks = 0

        self.hb_interval = 0
        self.worker_lock = threading.Lock()

        self.workers = []
        self.chunk_size = 0
        self.chunk_start = 0
        self.chunk_end = 0
        self.found = False

        self.checkpoint = 0
        self.worker_chunks = {}    
        self.worker_progress = {}
        self.requeue_chunks = []

def parse_arguments(controller_info):
    parser = argparse.ArgumentParser(description="Password Cracking Controller")
    parser.add_argument("-f", "--file", required=True, help="Path to shadow file")
    parser.add_argument("-u", "--user", required=True, help="Username to lookup")
    parser.add_argument("-p", "--port", required=True, help="Port number to listen on", type=int)
    parser.add_argument("-b", "--interval", type=int, help="Heartbeat interval in seconds", default=0)
    parser.add_argument("-c", "--chunk_size", type=int, help="Chunk size", default=0)
    parser.add_argument("-k", "--checkpoint", type=int, help="Checkpoint inteval", default=0)
    
    args = parser.parse_args()

    controller_info.shadowfile = args.file
    controller_info.username = args.user
    controller_info.port = args.port
    controller_info.hb_interval = args.interval
    controller_info.chunk_size = args.chunk_size
    controller_info.checkpoint = args.checkpoint

def validate_address(ip, port):
    try:
        return (ip, int(port))
    except (ValueError, OSError):
        return None

def usage(message):
    print(message)
    sys.exit(1)

def parse_shadow(controller_info):
    start = time.perf_counter()

    try:
        with open(controller_info.shadowfile, "r") as f:
            for line in f:
                if line.startswith(controller_info.username + ":"):
                    fields = line.strip().split(":")
                    if len(fields) < 2:
                        continue
                    hash_field = fields[1]
                    parts = hash_field.split("$")

                    if len(parts) < 4:
                        raise ValueError("Unsupported hash format")

                    controller_info.data["algorithm"] = parts[1]

                    if parts[1] == "y":  # yescrypt
                        controller_info.data["options"] = parts[2]
                        controller_info.data["salt"] = parts[3]
                        controller_info.data["password"] = parts[4]
                    elif parts[1] == "2b":  # bcrypt
                        controller_info.data["options"] = parts[2]
                        controller_info.data["salt"] = parts[3][:22]
                        controller_info.data["password"] = parts[3][22:]
                    else:
                        controller_info.data["salt"] = parts[2]
                        controller_info.data["password"] = parts[3]

                    controller_info.parse_time = time.perf_counter() - start        
                    return
                
        usage(f"User '{controller_info.username}' not found in {controller_info.shadowfile}")
    except FileNotFoundError:
        usage(f"Shadow file not found: {controller_info.shadowfile}")
    
    controller_info.parsing_time = time.perf_counter() - start

def init_socket(controller_info):
    addr = validate_address(controller_info.ip, controller_info.port)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(addr)
        sock.listen()
        sock.settimeout(1) 
        print(f"Controller listening on: {sock.getsockname()}")
        controller_info.socket = sock
    except OSError as e:
        usage(f"Failed to bind socket: {e}")

def wait_for_workers(controller_info):
    while True:
        if controller_info.found:
            break

        try:
            conn, addr = controller_info.socket.accept()
            print(f"\nConnected to worker: {addr}")

            thread = threading.Thread(
                target=handle_connection,
                args=(controller_info, conn),
                daemon=True
            )
            thread.start()

        except socket.timeout:
            continue
        except OSError as e:
            print("[WARNING] Accept failed:", e)
            continue
        
def handle_connection(controller_info, conn):
    with controller_info.worker_lock:
        controller_info.workers.append(conn)

    try:
        while True:
            if controller_info.found:
                break

            data = conn.recv(BUFFER_SIZE)
            if not data:
                break

            try:
                msg = json.loads(data.decode())
            except json.decoder.JSONDecodeError:
                continue

            msg_type = msg.get("type")

            if msg_type == "get_work":
                start = time.perf_counter()

                if controller_info.found:
                    send_stop(conn)
                    continue

                chunk = get_chunk(controller_info)

                if chunk:
                    send_job(controller_info, conn, chunk)
                else:
                    send_stop(conn)
                
                elapsed = time.perf_counter() - start
                controller_info.chunk_assign_time += elapsed
                controller_info.total_chunks += 1

            elif msg_type == "found":
                receive_time = time.perf_counter()

                send_time = msg.get("sent_time", receive_time)

                latency = receive_time - send_time

                # print(f"[RESULT LATENCY] {latency:.6f}s")

                controller_info.found = True
                controller_info.result.append(msg)

                controller_info.result.append({
                    "worker": msg["who"],
                    "password": msg["password"],
                    "latency": latency,
                    "cracking_time": msg["timing"]["cracking_time"]
                })

                print(f"[FOUND] {msg['password']}")

                broadcast_stop(controller_info, conn)

            elif msg_type == "hb_response":
                print(f"[HB] {msg.get('tested_since_last')}")
            
            elif msg_type == "checkpoint":
                with controller_info.worker_lock:
                    controller_info.worker_progress[conn] = msg.get("current")
                print(f"[CHECKPOINT] {msg.get('worker')} -> {msg.get('current')}")

    except OSError:
        print("Worker disconnected")

    finally:
        with controller_info.worker_lock:
            if conn in controller_info.worker_chunks:

                chunk_start, chunk_end = controller_info.worker_chunks[conn]
                progress = controller_info.worker_progress.get(conn, chunk_start)

                if progress < chunk_end:
                    print(f"[RECOVERY] Requeue chunk {progress} -> {chunk_end}")
                    controller_info.requeue_chunks.append((progress, chunk_end))

                del controller_info.worker_chunks[conn]
                del controller_info.worker_progress[conn]

            if conn in controller_info.workers:
                controller_info.workers.remove(conn)

        conn.close()

def send_job(controller_info, conn, chunk):
    start = time.perf_counter()

    controller_info.data["chunk_start"] = chunk[0]
    controller_info.data["chunk_end"] = chunk[1]
    controller_info.data["checkpoint"] = controller_info.checkpoint

    # print("Sent job: ", controller_info.data)

    payload = json.dumps(controller_info.data).encode("utf-8")
    conn.sendall(payload)

    with controller_info.worker_lock:
        controller_info.worker_chunks[conn] = chunk
        controller_info.worker_progress[conn] = chunk[0]

    controller_info.dispatch_time = time.perf_counter() - start

def send_stop(conn):
    msg = {"type": "stop"}
    conn.sendall(json.dumps(msg).encode())

def broadcast_stop(controller_info, conn):
    with controller_info.worker_lock:
        workers_copy = list(controller_info.workers)
        del controller_info.worker_chunks[conn]
        del controller_info.worker_progress[conn]

    for w in workers_copy:
        try:
            send_stop(w)
        except:
            pass

def get_chunk(controller_info):

    if controller_info.requeue_chunks:
        return controller_info.requeue_chunks.pop(0)

    chunk_s = controller_info.chunk_start
    chunk_e = controller_info.chunk_start + controller_info.chunk_size

    controller_info.chunk_start = chunk_e + 1
    controller_info.chunk_end = controller_info.chunk_start + controller_info.chunk_size

    return (chunk_s, chunk_e)

def heartbeat_loop(controller_info):
    while not controller_info.found and controller_info.hb_interval > 0:
        time.sleep(controller_info.hb_interval)

        msg = {
            "type": "hb"
        }

        payload = json.dumps(msg).encode()

        with controller_info.worker_lock:
            workers_copy = list(controller_info.workers)

        for w in workers_copy:
            try:
                w.sendall(payload)
            except OSError:
                pass

def print_report(controller_info):
    print("\n===== PERFORMANCE REPORT =====")

    print(f"Parsing Time: {controller_info.parsing_time:.6f}s")
    print(f"Dispatch Time: {controller_info.dispatch_time:.6f}s")

    if controller_info.total_chunks > 0:
        avg_chunk = controller_info.chunk_assign_time / controller_info.total_chunks
    else:
        avg_chunk = 0

    print(f"Chunk Assign Total: {controller_info.chunk_assign_time:.6f}s")
    print(f"Chunk Assign Avg: {avg_chunk:.6f}s")

    r = controller_info.result[1]
    print(f"\nWorker {r['worker']}:")
    print(f"Cracking Time: {r['cracking_time']:.6f}s")
    print(f"Result Latency: {r['latency']:.6f}s")

    total_time = controller_info.end_time - controller_info.start_time
    print(f"\nTotal Runtime: {total_time:.6f}s")


def main():
    controller_info = ControllerInfo()

    controller_info.start_time = time.perf_counter()

    parse_arguments(controller_info)
    parse_shadow(controller_info)
    init_socket(controller_info)

    if controller_info.hb_interval > 0:
        hb_thread = threading.Thread(
            target=heartbeat_loop,
            args=(controller_info,),
            daemon=True
        )
        hb_thread.start()

    print("Waiting for workers...")
    wait_for_workers(controller_info)

    controller_info.end_time = time.perf_counter()

    print_report(controller_info)

if __name__ == "__main__":
    main()