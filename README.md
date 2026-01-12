# MicroRainbow

MicroRainbow is a lightweight, native replacement for the `minirainbow.sh` shell script used on Turris Omnia routers. It manages the RGB LEDs to indicate system status, internet connectivity, and Wi-Fi activity, while providing button-controlled brightness management.

Written in Zig, it runs as a single lightweight process, eliminating the CPU overhead caused by the original shell script constantly spawning subprocesses (`uci`, `grep`, `jsonfilter`, `ping`) polling loops.

## Features

### 1. Global Brightness Control
*   **Rear Button Support:** Monitors the rear reset/brightness button (via `/dev/input/event0`) to cycle global LED brightness.
*   **Levels:** Cycles through **High (100%) → Medium (50%) → Off (0%)**.
*   **Persistence:** Saves the selected brightness level to `/etc/config/rainbow`, preserving settings across reboots.

### 2. WAN Status Indication (WAN LED)
Indicates the current state of internet connectivity by periodically checking DNS resolution and connectivity to public endpoints (Google DNS).

*   🟢 **Green:** IPv4 connectivity + DNS working.
*   🔵 **Cyan:** IPv6 connectivity + DNS working (Priority over IPv4).
*   🟠 **Orange:** IPv4 connectivity established, but DNS resolution failed.
*   🔴 **Red:** No internet connectivity.
*   **Adaptive Polling:** Checks every **5 minutes** when healthy, or every **10 seconds** when connectivity is lost.

### 3. Wi-Fi Status Indication (WLAN LED)
Monitors the status of wireless interfaces via UCI configuration.

*   🔵 **Cyan:** All 3 radios are up (Tri-band operation).
*   🟢 **Green:** Normal operation (most radios up).
*   🟠 **Orange:** Degraded state (some radios down or disabled).
*   🔴 **Red:** All radios down.

### 4. Power & System LEDs
*   Ensures the **Power LED** is green if not managed by system triggers.
*   Initializes the **Indicator LED** to off to prevent undefined states.

## Architecture

*   **Static Linking:** Built as a static binary (`aarch64-linux-musl`), requiring no external system libraries at runtime.
*   **Direct System Access:** Interacts directly with Linux sysfs (`/sys/class/leds`) and input subsystems.
*   **LibUCI Integration:** Links `libuci` statically to read/write system configuration efficiently without spawning shell commands.
*   **Signal Handling:** Listens for `SIGHUP` to instantly reload configuration and brightness settings without restarting the process.

## Build

To build the project efficiently independent of the host system libraries:

```bash
zig build
```

The resulting binary will be located at `zig-out/bin/microrainbow`.

## Installation

1.  Stop the original service:
    ```bash
    /etc/init.d/minirainbow stop
    disable /etc/init.d/minirainbow
    ```
2.  Copy the binary to the router:
    ```bash
    cp zig-out/bin/microrainbow /usr/bin/microrainbow
    ```
3.  Create an init script or systemd service to run `/usr/bin/microrainbow` at startup.

## Development

The project structure is minimal:
*   `src/main.zig`: Application logic.
*   `deps/`: Static libraries (`libuci.a`, `libubox.a`) and headers tailored for the target architecture.
*   `build.zig`: Build configuration ensuring static linking with musl libc.
