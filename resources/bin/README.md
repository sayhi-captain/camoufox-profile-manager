# Sing-box Sidecar Binary

Place the `sing-box` (or `sing-box.exe` on Windows) executable in this directory.
When running or packaged, Camoufox Profile Manager uses this binary to bridge
VLESS, VMess, and Trojan proxy nodes to local ephemeral SOCKS5 ports.

If not present here, Camoufox Profile Manager will also check:
1. The `CPM_SINGBOX_PATH` or `SING_BOX_PATH` environment variable.
2. The system `PATH`.
