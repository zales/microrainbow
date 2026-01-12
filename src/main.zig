const std = @import("std");
const fs = std.fs;
const Thread = std.Thread;
const time = std.time;
const net = std.net;
// const os = std.os;
const c = @cImport({
    @cInclude("uci.h");
    @cInclude("unistd.h");
});

// Access global configuration
pub const log_level: std.log.Level = .info;

// --- Configuration Constants ---
const WAN_LED = "/sys/class/leds/rgb:wan";
const WIFI_LED = "/sys/class/leds/rgb:wlan";
const POWER_LED = "/sys/class/leds/rgb:power";
const INDICATOR_LED = "/sys/class/leds/rgb:indicator";

const COLOR_RED = "255 0 0";
const COLOR_ORANGE = "255 64 0";
const COLOR_GREEN = "0 255 0";
const COLOR_CYAN = "0 255 255";
const COLOR_BLACK = "0 0 0";

// Matches "TRIGGERS=no" in reference script
const TRIGGERS_ENABLED = false;

// Use C allocator since we link libc
const allocator = std.heap.c_allocator;

// --- Global State ---
var reload_mutex: Thread.Mutex = .{};
var reload_cond: Thread.Condition = .{};
var reload_generation: u32 = 0;

var brightness_mutex: Thread.Mutex = .{};
var cached_brightness: u8 = 255;

// --- Helper Functions ---

/// Reads file content into a buffer. Returns slice of buffer.
fn readToBuffer(path: []const u8, buffer: []u8) ![]const u8 {
    const file = try fs.cwd().openFile(path, .{});
    defer file.close();
    const len = try file.readAll(buffer);
    return buffer[0..len];
}

/// Writes content to a file, truncating it.
fn writeFile(path: []const u8, content: []const u8) !void {
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(content);
    if (content.len > 0 and content[content.len - 1] != '\n') {
        try file.writeAll("\n");
    }
}

/// Helper to format strings into stack buffers
fn fmtBuf(buf: []u8, comptime fmt: []const u8, args: anytype) ![]const u8 {
    return std.fmt.bufPrint(buf, fmt, args);
}

/// Helper to format strings naturally (creates a null-terminated string in stack buffer for C interoperability)
fn fmtBufZ(buf: []u8, comptime fmt: []const u8, args: anytype) ![:0]const u8 {
    return std.fmt.bufPrintZ(buf, fmt, args);
}

// --- Hardware Control ---

fn setGenericVal(path: []const u8, new_val: []const u8) !void {
    // Optimization: check existing value to avoid redundant writes
    var read_buf: [256]u8 = undefined;
    if (readToBuffer(path, &read_buf)) |content| {
        const trimmed = std.mem.trimRight(u8, content, "\n\r");
        if (std.mem.eql(u8, trimmed, new_val)) return;
    } else |_| {}

    try writeFile(path, new_val);
}

fn setLedAttribute(led_path: []const u8, attribute: []const u8, value: []const u8) !void {
    var path_buf: [128]u8 = undefined;
    const path = try fmtBuf(&path_buf, "{s}/{s}", .{ led_path, attribute });
    setGenericVal(path, value) catch {};
}

fn setColor(led_path: []const u8, color: []const u8) void {
    setLedAttribute(led_path, "multi_intensity", color) catch |err| {
        std.log.debug("Failed to set color for {s}: {}", .{ led_path, err });
    };
}

fn setTrigger(led_path: []const u8, trigger: []const u8) !void {
    var path_buf: [128]u8 = undefined;
    const path = try fmtBuf(&path_buf, "{s}/trigger", .{led_path});

    var read_buf: [2048]u8 = undefined;
    const content = readToBuffer(path, &read_buf) catch "";

    // Check if trigger is already active: "[trigger] ..."
    var needle_buf: [64]u8 = undefined;
    const needle = try fmtBuf(&needle_buf, "[{s}]", .{trigger});

    if (std.mem.indexOf(u8, content, needle) == null) {
        try writeFile(path, trigger);
    }
}

// --- UCI Wrapper ---
// Provides zig-idiomatic access to libuci
const Uci = struct {
    ctx: *c.uci_context,

    fn init() !Uci {
        const ctx = c.uci_alloc_context() orelse return error.OutOfMemory;
        return Uci{ .ctx = ctx };
    }

    fn deinit(self: Uci) void {
        c.uci_free_context(self.ctx);
    }

    /// Looks up a configuration value string.
    /// Note: The returned slice points to UCI internal memory and is valid only until context changes or deinit.
    fn get(self: Uci, key: []const u8) !?[]const u8 {
        var ptr: c.uci_ptr = std.mem.zeroes(c.uci_ptr);
        var key_buf: [128]u8 = undefined;
        const key_z = try fmtBufZ(&key_buf, "{s}", .{key});

        if (c.uci_lookup_ptr(self.ctx, &ptr, @constCast(key_z), true) != 0) return null;

        if (ptr.o) |opt| {
            if (opt.*.type == c.UCI_TYPE_STRING) {
                return std.mem.span(opt.*.v.string);
            }
        }
        return null;
    }

    fn set(self: Uci, key: []const u8, value: []const u8) !void {
        var ptr: c.uci_ptr = std.mem.zeroes(c.uci_ptr);
        var buf: [128]u8 = undefined;
        // Key and value must be combined for uci_lookup_ptr syntax "package.section.option=value"
        const full = try fmtBufZ(&buf, "{s}={s}", .{ key, value });

        if (c.uci_lookup_ptr(self.ctx, &ptr, @constCast(full), true) != 0) return error.UciLookupFailed;
        if (c.uci_set(self.ctx, &ptr) != 0) return error.UciSetFailed;
    }

    fn commit(self: Uci, package: []const u8) !void {
        var ptr: c.uci_ptr = std.mem.zeroes(c.uci_ptr);
        var buf: [64]u8 = undefined;
        const pkg_z = try fmtBufZ(&buf, "{s}", .{package});

        if (c.uci_lookup_ptr(self.ctx, &ptr, @constCast(pkg_z), true) != 0) return error.UciLookupFailed;
        if (c.uci_commit(self.ctx, &ptr.p, false) != 0) return error.UciCommitFailed;
    }

    /// Checks if a generic system LED configuration exists for a given sysfs target (e.g., "rgb:wan").
    fn hasSystemLedFor(self: Uci, sysfs_target: []const u8) bool {
        var ptr: c.uci_ptr = std.mem.zeroes(c.uci_ptr);
        var kbuf: [16]u8 = undefined;
        const key_z = fmtBufZ(&kbuf, "system", .{}) catch return false;

        if (c.uci_lookup_ptr(self.ctx, &ptr, @constCast(key_z), true) != 0) return false;

        const pkg = ptr.p;
        if (pkg == null) return false;

        const header = &pkg.*.sections;
        var current = header.next;

        while (current != header) {
            const list_ptr: *c.uci_list = @ptrCast(current);
            const elem: *c.uci_element = @fieldParentPtr("list", list_ptr);
            current = current.*.next;

            // Iterate all sections, look for 'sysfs' option matching target
            const section: *c.uci_section = @fieldParentPtr("e", elem);
            if (c.uci_lookup_option(self.ctx, section, "sysfs")) |opt| {
                if (opt.*.type == c.UCI_TYPE_STRING) {
                    const val = std.mem.span(opt.*.v.string);
                    if (std.mem.indexOf(u8, val, sysfs_target) != null) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /// Counts total wifi devices and how many are logically up (not disabled).
    fn countWifiStats(self: Uci, bands_out: *u32, up_out: *u32) !void {
        var ptr: c.uci_ptr = std.mem.zeroes(c.uci_ptr);
        var kbuf: [16]u8 = undefined;
        const key_z = try fmtBufZ(&kbuf, "wireless", .{});

        if (c.uci_lookup_ptr(self.ctx, &ptr, @constCast(key_z), true) != 0) return;

        const pkg = ptr.p;
        if (pkg == null) return;

        const header = &pkg.*.sections;
        var current = header.next;

        var radios_up: u32 = 0;
        var radios_total: u32 = 0;

        while (current != header) {
            const list_ptr: *c.uci_list = @ptrCast(current);
            const elem: *c.uci_element = @fieldParentPtr("list", list_ptr);
            current = current.*.next;
            const section: *c.uci_section = @fieldParentPtr("e", elem);

            // Check if section type is "wifi-device"
            if (std.mem.eql(u8, std.mem.span(section.type), "wifi-device")) {
                radios_total += 1;
                var is_disabled = false;
                if (c.uci_lookup_option(self.ctx, section, "disabled")) |opt| {
                    if (opt.*.type == c.UCI_TYPE_STRING) {
                        const val = std.mem.span(opt.*.v.string);
                        if (std.mem.eql(u8, val, "1")) is_disabled = true;
                    }
                }
                if (!is_disabled) radios_up += 1;
            }
        }

        bands_out.* = radios_total;
        up_out.* = radios_up;
    }

    /// Resolves interface name to device name (e.g. "wan" -> "eth1")
    /// Caller owns returned memory.
    fn getNetDev(self: Uci, interface: []const u8) ![]const u8 {
        var key_buf: [64]u8 = undefined;

        // Try network.<iface>.device
        const key_dev_match = try fmtBuf(&key_buf, "network.{s}.device", .{interface});
        if (try self.get(key_dev_match)) |val| {
            return allocator.dupe(u8, val);
        }

        // Fallback network.<iface>.ifname
        const key_if_match = try fmtBuf(&key_buf, "network.{s}.ifname", .{interface});
        if (try self.get(key_if_match)) |val| {
            return allocator.dupe(u8, val);
        }

        return error.NotFound;
    }
};

// --- Logic Implementation ---

fn updateBrightnessCache() void {
    const uci = Uci.init() catch return;
    defer uci.deinit();

    if (uci.get("rainbow.all.brightness") catch null) |val_str| {
        if (std.fmt.parseInt(u8, val_str, 10)) |val| {
            brightness_mutex.lock();
            cached_brightness = val;
            brightness_mutex.unlock();
        } else |_| {}
    }
}

fn applyBrightnessGlobal(val_str: []const u8) !void {
    var dir = fs.openDirAbsolute("/sys/class/leds", .{ .iterate = true }) catch return;
    defer dir.close();
    var it = dir.iterate();
    while (it.next() catch null) |entry| {
        var path_buf: [128]u8 = undefined;
        const path = try fmtBuf(&path_buf, "/sys/class/leds/{s}/brightness", .{entry.name});
        setGenericVal(path, val_str) catch {};
    }
}

fn setLedToConfiguredBrightness(led: []const u8) void {
    brightness_mutex.lock();
    const bri = cached_brightness;
    brightness_mutex.unlock();

    var buf: [8]u8 = undefined;
    const bri_str = fmtBuf(&buf, "{d}", .{bri}) catch "255";

    setLedAttribute(led, "brightness", bri_str) catch {};
}

const Connectivity = struct {
    dns: bool,
    ipv4: bool,
    ipv6: bool,
};

fn checkConnectivity() Connectivity {
    var conn = Connectivity{ .dns = false, .ipv4 = false, .ipv6 = false };

    // Check IPv4 (Google DNS 8.8.8.8:53)
    if (net.Address.parseIp4("8.8.8.8", 53)) |addr| {
        if (net.tcpConnectToAddress(addr)) |cn| {
            cn.close();
            conn.ipv4 = true;
        } else |_| {}
    } else |_| {}

    // Check IPv6 (Google DNS 2001:4860:4860::8888:53)
    if (net.Address.parseIp6("2001:4860:4860::8888", 53)) |addr| {
        if (net.tcpConnectToAddress(addr)) |cn| {
            cn.close();
            conn.ipv6 = true;
        } else |_| {}
    } else |_| {}

    // Check DNS (resolve nic.cz)
    if (net.getAddressList(allocator, "nic.cz", 80)) |list| {
        defer list.deinit();
        if (list.addrs.len > 0) conn.dns = true;
    } else |_| {
        if (net.getAddressList(allocator, "google.com", 80)) |list| {
            defer list.deinit();
            if (list.addrs.len > 0) conn.dns = true;
        } else |_| {}
    }

    return conn;
}

// --- Loops ---

fn signalLoop() !void {
    // Setup signalfd for SIGHUP
    const sig = std.os.linux.SIG.HUP;
    var set = std.mem.zeroes(std.os.linux.sigset_t);
    std.os.linux.sigaddset(&set, sig);

    const fd_r = std.os.linux.signalfd(-1, &set, 0);
    const fd: i32 = @intCast(fd_r);
    const f = fs.File{ .handle = fd };
    defer f.close();

    while (true) {
        var info: std.os.linux.signalfd_siginfo = undefined;
        const bytes_read = f.read(std.mem.asBytes(&info)) catch |err| {
            std.log.err("Signal read error: {}", .{err});
            continue;
        };
        if (bytes_read != @sizeOf(std.os.linux.signalfd_siginfo)) continue;

        if (info.signo == sig) {
            std.log.info("SIGHUP received, reloading...", .{});

            // Notify other threads
            reload_mutex.lock();
            reload_generation +%= 1; // wrapping add
            reload_cond.broadcast();
            reload_mutex.unlock();

            // Handle main thread responsibilities (brightness reset)
            updateBrightnessCache();
            brightness_mutex.lock();
            const bri = cached_brightness;
            brightness_mutex.unlock();

            var buf: [8]u8 = undefined;
            const bri_str = fmtBuf(&buf, "{d}", .{bri}) catch "255";
            applyBrightnessGlobal(bri_str) catch {};
        }
    }
}

// Waits for notification with timeout. Returns true if woke up by signal, false if timeout.
fn waitForReload(seconds: u64) bool {
    reload_mutex.lock();
    defer reload_mutex.unlock();

    const start_gen = reload_generation;
    // Timeout is in nanoseconds
    reload_cond.timedWait(&reload_mutex, seconds * time.ns_per_s) catch {};

    return reload_generation != start_gen;
}

fn wanStatusLoop() !void {
    while (true) {
        var customized = false;

        // Scope for UCI context
        {
            const uci = Uci.init() catch null;
            if (uci) |u| {
                defer u.deinit();
                if (u.hasSystemLedFor("rgb:wan")) customized = true;
            }
        }

        var sleep_time: u64 = 10;

        if (customized) {
            sleep_time = 300;
        } else {
            const conn = checkConnectivity();
            var status: []const u8 = COLOR_RED;
            var is_green_or_cyan = false;

            if (conn.dns) {
                if (conn.ipv4) {
                    status = COLOR_GREEN;
                    is_green_or_cyan = true;
                }
                if (conn.ipv6) {
                    status = COLOR_CYAN;
                    is_green_or_cyan = true;
                }
            } else {
                if (conn.ipv4) {
                    status = COLOR_ORANGE;
                } else {
                    status = COLOR_RED;
                }
            }

            // Apply state
            setColor(WAN_LED, status);
            setLedToConfiguredBrightness(WAN_LED);

            if (TRIGGERS_ENABLED) {
                setTrigger(WAN_LED, "netdev") catch {};

                const uci = Uci.init() catch null;
                if (uci) |u| {
                    defer u.deinit();
                    if (u.getNetDev("wan")) |dev| {
                        defer allocator.free(dev);
                        setLedAttribute(WAN_LED, "device_name", dev) catch {};
                        setLedAttribute(WAN_LED, "link", "1") catch {};
                        setLedAttribute(WAN_LED, "rx", "1") catch {};
                        setLedAttribute(WAN_LED, "tx", "1") catch {};
                    } else |_| {}
                }
            } else {
                setTrigger(WAN_LED, "default-on") catch {};
            }

            sleep_time = if (is_green_or_cyan) 300 else 10;
        }

        _ = waitForReload(sleep_time);
    }
}

fn wifiStatusLoop() !void {
    while (true) {
        var customized = false;
        var bands: u32 = 0;
        var up_count: u32 = 0;
        var dev_name: ?[]u8 = null;

        // Gather metrics
        {
            const uci = Uci.init() catch null;
            if (uci) |u| {
                defer u.deinit();
                if (u.hasSystemLedFor("rgb:wlan")) {
                    customized = true;
                } else {
                    u.countWifiStats(&bands, &up_count) catch {};
                    if (TRIGGERS_ENABLED) {
                        if (u.getNetDev("lan")) |dev| {
                            // dev is allocated by getNetDev, just move ownership
                            dev_name = dev;
                        } else |_| {}
                    }
                }
            }
        }

        if (customized) {
            _ = waitForReload(10);
            continue;
        }
        defer if (dev_name) |d| allocator.free(d);

        // Calculate Color
        var color: []const u8 = COLOR_BLACK;
        if (bands == up_count and bands == 3) {
            color = COLOR_CYAN;
        } else if (up_count == 0 and bands > 1) {
            color = COLOR_RED;
        } else {
            const diff = if (bands > up_count) bands - up_count else 0;
            if (diff < 2) {
                color = COLOR_GREEN;
            } else {
                color = COLOR_ORANGE;
            }
        }

        // Apply State
        setColor(WIFI_LED, color);
        setLedToConfiguredBrightness(WIFI_LED);

        if (TRIGGERS_ENABLED) {
            setTrigger(WIFI_LED, "netdev") catch {};
            if (dev_name) |dev| {
                setLedAttribute(WIFI_LED, "device_name", dev) catch {};
                setLedAttribute(WIFI_LED, "link", "1") catch {};
                setLedAttribute(WIFI_LED, "rx", "1") catch {};
                setLedAttribute(WIFI_LED, "tx", "1") catch {};
            }
        } else {
            setTrigger(WIFI_LED, "default-on") catch {};
        }

        _ = waitForReload(10);
    }
}

const InputEvent = extern struct {
    time: extern struct {
        sec: c_long,
        usec: c_long,
    },
    type: u16,
    code: u16,
    value: i32,
};

fn brightnessLoop() !void {
    // Initial Setup
    updateBrightnessCache();

    // Copy cached val to local stack
    brightness_mutex.lock();
    const loaded_brightness = cached_brightness;
    brightness_mutex.unlock();

    var buf: [8]u8 = undefined;
    const bri_str = fmtBuf(&buf, "{d}", .{loaded_brightness}) catch "255";

    // One-time power LED setup
    if (Uci.init()) |u| {
        defer u.deinit(); // Using defer with |capture| works in zig

        if (!u.hasSystemLedFor("rgb:power")) {
            setTrigger(POWER_LED, "default-on") catch {};
            setColor(POWER_LED, COLOR_GREEN);
            applyBrightnessGlobal(bri_str) catch {};
        }

        // Ensure config exists
        if (u.get("rainbow.all.brightness") catch null == null) {
            // Create config if missing (naive check via uci get)
            const rainbow_path = "/etc/config/rainbow";
            fs.cwd().access(rainbow_path, .{}) catch |err| {
                if (err == error.FileNotFound) {
                    const f = fs.cwd().createFile(rainbow_path, .{}) catch null;
                    if (f) |h| h.close();
                }
            };
            u.set("rainbow.all", "led") catch {};
            u.set("rainbow.all.brightness", bri_str) catch {};
            u.commit("rainbow") catch {};
        }
    } else |_| {}

    // Event Loop
    const input_path = "/dev/input/event0";

    while (true) {
        // Try to open device
        const file_opt: ?fs.File = fs.cwd().openFile(input_path, .{}) catch null;

        if (file_opt) |file| {
            defer file.close();

            // Connected
            var ev: InputEvent = undefined;
            while (true) {
                const bytes = file.read(std.mem.asBytes(&ev)) catch |err| {
                    std.log.warn("Input read error: {}, reconnecting...", .{err});
                    break;
                };
                if (bytes != @sizeOf(InputEvent)) break;

                // EV_KEY (1), KEY_F1 (59)
                if (ev.type == 1 and ev.code == 59 and ev.value == 1) {
                    // Button Logic
                    brightness_mutex.lock();
                    var current = cached_brightness;
                    brightness_mutex.unlock();

                    if (current < 4) {
                        current = if (current == 0) 255 else 0;
                    } else {
                        current = @divTrunc(current, 2);
                    }

                    // Update Cache
                    brightness_mutex.lock();
                    cached_brightness = current;
                    brightness_mutex.unlock();

                    // Apply and Save
                    const val_str = fmtBuf(&buf, "{d}", .{current}) catch continue;
                    applyBrightnessGlobal(val_str) catch {}; // Apply first for responsiveness

                    if (Uci.init()) |u| {
                        defer u.deinit();
                        u.set("rainbow.all.brightness", val_str) catch {};
                        u.commit("rainbow") catch {};
                    } else |_| {}
                }
            }
        }

        // Wait before retrying
        _ = waitForReload(5);
    }
}

pub fn main() !void {
    // Block SIGHUP in main thread so signalfd can claim it
    var mask = std.mem.zeroes(std.os.linux.sigset_t);
    std.os.linux.sigaddset(&mask, std.os.linux.SIG.HUP);
    _ = std.os.linux.sigprocmask(std.os.linux.SIG.BLOCK, &mask, null);

    // Initial check for indicator LED (one-off)
    if (Uci.init()) |u| {
        defer u.deinit();
        if (!u.hasSystemLedFor("rgb:indicator")) {
            setGenericVal(INDICATOR_LED ++ "/multi_intensity", "0 0 0") catch {};
        }
    } else |_| {}

    // Spawn threads
    const t_sig = try Thread.spawn(.{}, signalLoop, .{});
    const t_bri = try Thread.spawn(.{}, brightnessLoop, .{});
    const t_wan = try Thread.spawn(.{}, wanStatusLoop, .{});
    const t_wif = try Thread.spawn(.{}, wifiStatusLoop, .{});

    // Detach all
    t_sig.detach();
    t_bri.detach();
    t_wan.detach();
    t_wif.detach();

    // Main thread just sleeps forever
    while (true) {
        Thread.sleep(60 * time.ns_per_s);
    }
}
