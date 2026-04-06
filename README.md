# CloudEdge Camera Client

A pure-Python P2P client for CloudEdge / Meari / Arenti IP cameras.  
No native libraries, no Android emulation — runs on any platform with Python 3.8+.

## Features

- Direct P2P connection to camera (LAN or WAN via NAT punch-through)
- CS2 network protocol (reimplements `libPPCS_API.so` natively in Python)
- 1080p H.264 video streaming with frame pacing
- Real-time playback via ffplay or VLC
- RTSP re-publishing via mediamtx + ffmpeg
- Zero dependencies (Python standard library only)

## Requirements

- Python ≥ 3.8
- For live playback: `ffplay` or VLC
- For RTSP streaming: `ffmpeg` + [mediamtx](https://github.com/bluenviron/mediamtx)

## Getting device credentials

You need three things from the CloudEdge cloud API:

| Parameter      | Description                                           | Example                         |
| -------------- | ----------------------------------------------------- | ------------------------------- |
| `--did`        | Device ID (on the camera's label or in the app)       | `UABPAM-000000-XXXXX`          |
| `--password`   | MD5 hash of the device password (32 hex chars)        | `d41d8cd98f00b204e9800998ecf8427e` |
| `--initstring` | PPCS init string from the cloud API `/device/info`    | `EDHNFFBLL...` (long string)   |

### Finding the password hash

The CloudEdge app sends the password as an MD5 hash. You can capture it by:

1. **Proxy the app traffic** — Use mitmproxy or Charles. Look for the
   `devicePassword` field in API responses like `/device/info` or
   `/device/getDeviceList`.

2. **Compute it yourself** — If you know the plaintext password:
   ```bash
   echo -n "YourPassword" | md5sum
   ```

### Finding the initstring

The init string is returned by the CloudEdge cloud API. Capture the
response to `/device/info` — the `deviceP2PInitString` field contains it.
It looks like a long string of uppercase letters followed by a colon and
a key, e.g.:

```
EDHNFFBLL...:WeEye2ppStronGer
```

## Usage

### Configuration file

Instead of passing credentials on every command, create a `camera.json`:

```json
{
    "did": "UABPAM-000000-XXXXX",
    "password": "<md5hash>",
    "initstring": "EDHNFFBLL...:WeEye2ppStronGer"
}
```

Then use `--config camera.json` in place of `--did`, `--password`, and
`--initstring`. A sample file is provided but excluded from version
control via `.gitignore`.

### Save video to a file

```bash
python3 cloudedge.py --config camera.json --duration 60 -o clip.h264
```

This saves 60 seconds of raw H.264 video. Play it with:

```bash
ffplay clip.h264
# or
vlc clip.h264
```

### Live preview with ffplay

```bash
python3 cloudedge.py --config camera.json -o - | \
  ffplay -fflags nobuffer -flags low_delay \
    -framedrop -f h264 -framerate 10 -i pipe:0
```

### Live RTSP stream

This lets any RTSP client (VLC, Blue Iris, Frigate, etc.) connect to
`rtsp://localhost:8554/camera`.

**Step 1 — Start mediamtx:**

Download [mediamtx](https://github.com/bluenviron/mediamtx/releases)
and create a config file `mediamtx.yml`:

```yaml
paths:
  all_others:
```

Then start it:

```bash
./mediamtx mediamtx.yml
```

**Step 2 — Start the stream:**

The simplest way (client manages ffmpeg internally with auto-reconnect):

```bash
python3 cloudedge.py --config camera.json \
    --duration 0 --rtsp rtsp://localhost:8554/camera
```

Or manually via pipe:

```bash
python3 cloudedge.py --config camera.json \
    --duration 0 -o - | \
  ffmpeg -fflags nobuffer+genpts \
    -use_wallclock_as_timestamps 1 \
    -f h264 -i pipe:0 \
    -c:v copy -f rtsp \
    -rtsp_transport tcp \
    rtsp://localhost:8554/camera
```

**Step 3 — Open in VLC:**

```
rtsp://localhost:8554/camera
```

### Convert to MP4

```bash
ffmpeg -i clip.h264 -c:v copy clip.mp4
```

## CLI reference

```
usage: cloudedge.py [-h] [--config FILE] [--did DID] [--password PASSWORD]
                    [--initstring INITSTRING] [--duration DURATION]
                    [-o OUTPUT] [--rtsp URL]

  --config FILE         JSON config file with did, password, initstring
  --did DID             Device ID  (e.g. UABPAM-000000-XXXXX)
  --password PASSWORD   Password MD5 hash (32 hex chars)
  --initstring STRING   PPCS init string from cloud API
  --duration DURATION   Seconds to stream, 0 = indefinite (default: 60)
  -o, --output OUTPUT   Output file, use "-" for stdout (default: live.h264)
  --rtsp URL            Publish to RTSP server via managed ffmpeg subprocess
                        (e.g. rtsp://localhost:8554/camera)
```

## Protocol overview

The client implements a five-layer protocol stack:

```
┌─────────────────────────────────────────────┐
│  Media framing    (32B header + H.264 NALs) │
├─────────────────────────────────────────────┤
│  PPCS protocol    (52B header + MD5 auth)   │
├─────────────────────────────────────────────┤
│  DRW channels     (mux + reliable delivery) │
├─────────────────────────────────────────────┤
│  CS2 session      (P2P discovery + punch)   │
├─────────────────────────────────────────────┤
│  XOR transport    (ciphertext-feedback enc) │
├─────────────────────────────────────────────┤
│  UDP                                        │
└─────────────────────────────────────────────┘
```

1. **UDP** — All communication is over a single UDP socket.
2. **XOR encryption** — Every datagram is encrypted with a 256-byte XOR
   table using ciphertext-feedback (each byte XOR'd with a table entry
   indexed by the previous ciphertext byte).
3. **CS2 session** — Discovery via dispatch servers, NAT punch-through,
   keepalives (PSR/ALIVE). Each message has a 4-byte header:
   `version(1) | type(1) | length(2)`.
4. **DRW channels** — Multiplexes logical channels (ch 0 = control,
   ch 1 = media). Provides sequence numbers and ACK-based reliability.
5. **PPCS protocol** — Application messages with a 52-byte header
   containing a magic number, sequence, type code, MD5 integrity check,
   and payload length. Auth uses HTTP-over-P2P.
6. **Media framing** — A 32-byte little-endian header per media frame
   containing frame number, codec type (0x01 = H.264 video, 0x82 = audio),
   timestamp, and frame size. H.264 NAL units follow immediately.

## Audio

The client **receives audio frames** (codec type `0x82`) but currently
discards them. The audio codec and container format have not been fully
analyzed yet. Adding audio support would require:

1. Identifying the audio codec (likely G.711 or AAC-LC based on similar
   devices)
2. Muxing audio alongside video into a container format (e.g. FLV/MPEG-TS)
3. Adjusting the ffmpeg pipeline to handle both streams

Audio frames are already delivered to the client — they just need a
decoder and output path.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Connection failed" | Camera is offline or behind symmetric NAT. Try from the same LAN. |
| "No auth response" | Wrong password hash. Re-check the MD5 from the API. |
| 0 frames received | Firewall blocking UDP. Allow outbound UDP on all ports. |
| Choppy RTSP | Increase ffmpeg buffer: `-analyzeduration 1M -probesize 1M` |
| ffplay green artifacts | First keyframe was missed; restart the client. |

## License

Research / educational use. This is a clean-room protocol reimplementation
from reverse-engineering the CloudEdge Android APK's native libraries.
