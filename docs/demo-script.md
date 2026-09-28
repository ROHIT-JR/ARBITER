# ARBITER offline demo script

This is the five-minute, no-Wi-Fi walkthrough.  Build the dashboard once
before packaging the repository; the presentation itself needs only Python and
the pre-built `frontend/dist` files.

## Before leaving for the venue

1. On the release checkout, run `cd frontend && npm ci && npm run build`.
2. Disconnect from the network and run `arbiter demo --check`.  Every line
   should be `PASSED`, except the optional cached-hardware preset when no
   hardware capture is bundled.
3. Start the presentation with `arbiter demo --port 8000`.  It opens
   `http://127.0.0.1:8000/`; the server binds only to localhost and creates a
   fresh temporary ledger and SQLite store.
4. If you need the artifacts after stopping, start it with `--keep-data`; it
   reuses `./.arbiter-demo/` on later runs.  Never use demo mode on a
   network-accessible service.

## Timed walkthrough (about 4:30)

| Time | Click / say | Expected on screen |
|---:|---|---|
| 0:00 | Open **Demo presets**. “ARBITER verifies teleportation-based quantum signatures and tells us *which* attack occurred.” | Dashboard is online; seeded menu is visible. |
| 0:20 | **1. Legitimate session**. “A clean session is accepted and written to the post-quantum signed ledger.” | `ACCEPT`, attribution `legitimate`, new valid ledger entry. |
| 0:50 | **2. Forgery alarm**. “A forged signature reaches an alarm in roughly thirteen rounds, not after a fixed waiting period.” | `REJECT: forgery`; sequential evidence crosses its threshold around round 13. |
| 1:25 | **3. Replay (Qiskit backend)**. “This is the circuit-backed path, not a hand-tuned classifier.” | `REJECT: replay`; verdict identifies `qiskit` backend. |
| 1:55 | **4. Resubmit last transcript**. “Even a byte-for-byte resubmission is caught by the nonce registry.” | `REJECT: replay`; nonce freshness is false. |
| 2:25 | **5. Tamper a ledger entry**. “Changing content breaks the hash and signature chain at the exact entry.” | Ledger reports the first bad index and marks it tampered. Use **Restore saved ledger** if you want to continue. |
| 3:00 | **6. Cached accuracy comparison**. “This chart is bundled, so it is instant and stays available without Wi-Fi.” | ARBITER and fixed-threshold matrices plus the seeded strength curves. |
| 3:40 | Optional **7. Cached hardware result**. “When a captured hardware result is shipped, it is shown here. This build skips it honestly when none is bundled.” | Cached hardware result, or a disabled “not bundled” item. |
| 4:05 | Close. “The demo is deterministic, local, and auditable end-to-end.” | Leave the ledger verification visible. |

## Fallback recording (OBS)

Record the same order before travel: 1920×1080 canvas and output, 30 fps,
H.264 at 8–12 Mbps, desktop audio off, microphone on.  Capture only the
browser window, hide notifications, and set the browser zoom to 100%.  Start
recording just before the menu opens, pause briefly after each verdict, and
keep the final file under three minutes if it is used as a fallback rather than
the live walkthrough.  The exact seeds make a re-record visually consistent.
