"""Ephemeral sidecar proxy bridge using sing-box for modern proxy protocols.

Bridges protocols unsupported directly by browser engines (VLESS, VMess, Trojan,
Shadowsocks) to local ephemeral SOCKS5 listeners.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from loguru import logger


def find_singbox_binary() -> str | None:
    """Locate the sing-box binary on the system or in resources/bin."""
    # 1. Explicit environment variables
    for env_key in ("CPM_SINGBOX_PATH", "SING_BOX_PATH", "SINGBOX_PATH"):
        path = os.environ.get(env_key)
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    binary_name = "sing-box.exe" if os.name == "nt" else "sing-box"

    # 2. PyInstaller bundled resources
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        meipass_bin = Path(sys._MEIPASS) / "resources" / "bin" / binary_name
        if meipass_bin.is_file() and os.access(meipass_bin, os.X_OK):
            return str(meipass_bin)

    # 3. Project repository resources/bin
    current_dir = Path(__file__).resolve().parent
    for parent in [current_dir] + list(current_dir.parents):
        candidate = parent / "resources" / "bin" / binary_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    # 4. System PATH
    found = shutil.which(binary_name) or shutil.which("sing-box")
    if found and os.access(found, os.X_OK):
        return found

    return None


def get_random_free_port() -> int:
    """Allocate an available local ephemeral port from the OS."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def parse_node_link(link: str) -> dict[str, Any]:
    """Parse node sharing links (vless://, vmess://, trojan://, ss://).

    Returns a standardized dictionary containing server, credentials, transport,
    and security parameters.
    """
    raw = link.strip()
    if not raw:
        raise ValueError("Empty proxy link")

    if raw.startswith("vmess://") and not re.match(r"^vmess://[^@]+@[^:]+:\d+", raw, re.IGNORECASE):
        # Base64 encoded JSON vmess link
        b64_part = raw[8:].split("#")[0]
        padding = "=" * ((4 - len(b64_part) % 4) % 4)
        try:
            decoded = base64.b64decode(b64_part + padding, altchars=b"-_").decode("utf-8")
        except Exception:
            try:
                decoded = base64.b64decode(b64_part + padding).decode("utf-8")
            except Exception as exc:
                raise ValueError(f"Invalid VMess base64 payload: {exc}") from exc

        try:
            data = json.loads(decoded)
        except Exception as exc:
            raise ValueError(f"Invalid VMess JSON: {exc}") from exc

        host = str(data.get("add") or "").strip()
        port = int(data.get("port") or 443)
        uuid = str(data.get("id") or "").strip()
        name = str(data.get("ps") or "").strip() or None
        transport = str(data.get("net") or "tcp").strip().lower()
        security = str(data.get("tls") or "none").strip().lower()
        cipher = str(data.get("scy") or "auto").strip().lower()
        alter_id = int(data.get("aid") or 0)
        path = str(data.get("path") or "/")
        host_header = str(data.get("host") or "") or None
        sni = str(data.get("sni") or host_header or host)
        fp = str(data.get("fp") or "") or None
        alpn = str(data.get("alpn") or "") or None

        return {
            "protocol": "vmess",
            "server": f"{host}:{port}",
            "host": host,
            "port": port,
            "uuid": uuid,
            "password": None,
            "name": name,
            "security": "tls" if security in {"tls", "reality"} else "none",
            "sni": sni,
            "fp": fp,
            "pbk": None,
            "sid": None,
            "spx": None,
            "flow": None,
            "transport": transport,
            "path": path,
            "host_header": host_header,
            "service_name": None,
            "cipher": cipher,
            "alter_id": alter_id,
            "alpn": alpn,
            "raw_link": raw,
        }

    # URL-based formats: vless://, trojan://, vmess://, ss://
    try:
        parsed = urlsplit(raw)
    except Exception as exc:
        raise ValueError(f"Invalid node URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"vless", "vmess", "trojan", "ss", "shadowsocks"}:
        raise ValueError(f"Unsupported node scheme: {scheme}")

    protocol = "shadowsocks" if scheme in {"ss", "shadowsocks"} else scheme

    # Fragment as alias/name
    name = unquote(parsed.fragment).strip() if parsed.fragment else None

    # Authority: userinfo@host:port
    userinfo = ""
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
    else:
        hostport = netloc

    userinfo = unquote(userinfo)

    # Shadowsocks base64 userinfo or base64 netloc
    ss_method = None
    ss_password = None
    if protocol == "shadowsocks":
        if "@" not in netloc and userinfo == "" and hostport:
            # Whole netloc might be base64
            padding = "=" * ((4 - len(hostport) % 4) % 4)
            try:
                decoded_netloc = base64.b64decode(hostport + padding).decode("utf-8")
                if "@" in decoded_netloc:
                    userinfo, hostport = decoded_netloc.rsplit("@", 1)
            except Exception:
                pass
        if ":" in userinfo:
            ss_method, ss_password = userinfo.split(":", 1)
        else:
            padding = "=" * ((4 - len(userinfo) % 4) % 4)
            try:
                decoded_u = base64.b64decode(userinfo + padding).decode("utf-8")
                if ":" in decoded_u:
                    ss_method, ss_password = decoded_u.split(":", 1)
            except Exception:
                ss_password = userinfo

    # Host and port
    if ":" in hostport:
        host, port_str = hostport.rsplit(":", 1)
        host = host.strip("[]")
        try:
            port = int(port_str)
        except ValueError:
            port = 443
    else:
        host = hostport.strip("[]")
        port = 443

    # Query parameters
    params = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

    transport = (params.get("type") or params.get("net") or "tcp").lower()
    security = (params.get("security") or ("tls" if protocol == "trojan" else "none")).lower()
    sni = params.get("sni") or params.get("serverName") or params.get("peer") or host
    fp = params.get("fp") or None
    pbk = params.get("pbk") or None
    sid = params.get("sid") or None
    spx = params.get("spx") or None
    flow = params.get("flow") or None
    path = params.get("path") or "/"
    host_header = params.get("host") or None
    service_name = params.get("serviceName") or params.get("service_name") or None
    alpn = params.get("alpn") or None

    if pbk:
        security = "reality"

    uuid = userinfo if protocol in {"vless", "vmess"} else None
    password = ss_password if protocol == "shadowsocks" else (userinfo if protocol == "trojan" else None)

    return {
        "protocol": protocol,
        "server": f"{host}:{port}",
        "host": host,
        "port": port,
        "uuid": uuid,
        "password": password,
        "name": name,
        "security": security,
        "sni": sni,
        "fp": fp,
        "pbk": pbk,
        "sid": sid,
        "spx": spx,
        "flow": flow,
        "transport": transport,
        "path": path,
        "host_header": host_header,
        "service_name": service_name,
        "cipher": ss_method or "auto",
        "alter_id": 0,
        "alpn": alpn,
        "raw_link": raw,
    }


def generate_singbox_config(
    inbound_port: int,
    proxy: Any,
    tag: str = "proxy",
) -> dict[str, Any]:
    """Generate a complete sing-box configuration translating SOCKS5 inbound to the node outbound."""
    node_data: dict[str, Any]

    if isinstance(proxy, str):
        node_data = parse_node_link(proxy)
    elif hasattr(proxy, "node_link") and getattr(proxy, "node_link", None):
        node_data = parse_node_link(proxy.node_link)
    elif isinstance(proxy, dict) and proxy.get("node_link"):
        node_data = parse_node_link(proxy["node_link"])
    else:
        # Fallback to structured fields
        proxy_type = getattr(proxy, "type", None) or (proxy.get("type") if isinstance(proxy, dict) else "vless")
        if hasattr(proxy_type, "value"):
            proxy_type = proxy_type.value
        proxy_type = str(proxy_type).lower()

        server = getattr(proxy, "server", None) or (proxy.get("server") if isinstance(proxy, dict) else "")
        username = getattr(proxy, "username", None) or (proxy.get("username") if isinstance(proxy, dict) else None)
        password = getattr(proxy, "password", None) or (proxy.get("password") if isinstance(proxy, dict) else None)

        if ":" in server:
            h, p = server.rsplit(":", 1)
            host = h.strip("[]")
            port = int(p)
        else:
            host = server.strip("[]")
            port = 443

        node_data = {
            "protocol": proxy_type,
            "server": f"{host}:{port}",
            "host": host,
            "port": port,
            "uuid": username or password,
            "password": password or username,
            "name": None,
            "security": "none",
            "sni": host,
            "fp": None,
            "pbk": None,
            "sid": None,
            "spx": None,
            "flow": None,
            "transport": "tcp",
            "path": "/",
            "host_header": None,
            "service_name": None,
            "cipher": "auto",
            "alter_id": 0,
            "alpn": None,
            "raw_link": "",
        }

    protocol = node_data["protocol"]
    outbound: dict[str, Any] = {
        "tag": tag,
        "server": node_data["host"],
        "server_port": int(node_data["port"]),
    }

    if protocol == "vless":
        outbound["type"] = "vless"
        outbound["uuid"] = node_data["uuid"] or ""
        if node_data.get("flow"):
            outbound["flow"] = node_data["flow"]
    elif protocol == "trojan":
        outbound["type"] = "trojan"
        outbound["password"] = node_data["password"] or node_data["uuid"] or ""
    elif protocol == "vmess":
        outbound["type"] = "vmess"
        outbound["uuid"] = node_data["uuid"] or ""
        outbound["security"] = node_data.get("cipher") or "auto"
        outbound["alter_id"] = int(node_data.get("alter_id") or 0)
    elif protocol == "shadowsocks":
        outbound["type"] = "shadowsocks"
        outbound["method"] = node_data.get("cipher") or "aes-256-gcm"
        outbound["password"] = node_data["password"] or ""
    else:
        raise ValueError(f"Unsupported bridge protocol: {protocol}")

    # TLS / Reality configuration
    security = (node_data.get("security") or "none").lower()
    if security in {"tls", "reality"} or node_data.get("pbk") or protocol == "trojan":
        tls_config: dict[str, Any] = {
            "enabled": True,
            "server_name": node_data.get("sni") or node_data["host"],
        }
        if node_data.get("alpn"):
            tls_config["alpn"] = [a.strip() for a in node_data["alpn"].split(",") if a.strip()]

        if security == "reality" or node_data.get("pbk"):
            reality_config: dict[str, Any] = {
                "enabled": True,
                "public_key": node_data.get("pbk") or "",
                "short_id": node_data.get("sid") or "",
            }
            tls_config["reality"] = reality_config
            tls_config["utls"] = {
                "enabled": True,
                "fingerprint": node_data.get("fp") or "chrome",
            }
        elif node_data.get("fp"):
            tls_config["utls"] = {
                "enabled": True,
                "fingerprint": node_data["fp"],
            }

        outbound["tls"] = tls_config

    # Transport configuration
    transport = (node_data.get("transport") or "tcp").lower()
    if transport in {"ws", "websocket"}:
        ws_config: dict[str, Any] = {
            "type": "ws",
            "path": node_data.get("path") or "/",
        }
        host_hdr = node_data.get("host_header") or node_data.get("sni")
        if host_hdr:
            ws_config["headers"] = {"Host": host_hdr}
        outbound["transport"] = ws_config
    elif transport == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": node_data.get("service_name") or "",
        }
    elif transport in {"http", "h2"}:
        outbound["transport"] = {
            "type": "http",
            "path": node_data.get("path") or "/",
        }

    return {
        "log": {
            "level": "warn",
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": inbound_port,
            }
        ],
        "outbounds": [outbound],
        "route": {
            "rules": [
                {
                    "inbound": "socks-in",
                    "outbound": tag,
                }
            ]
        },
    }


class ProxyBridge:
    """One ephemeral sing-box child process bridging a modern node to local SOCKS5."""

    def __init__(self, proxy_config: Any, tag: str = "proxy") -> None:
        self.proxy_config = proxy_config
        self.tag = tag
        self.port: int | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self.config_path: Path | None = None
        self._closed = False

    @property
    def browser_proxy(self) -> dict[str, str]:
        if self.port is None or self._closed:
            raise RuntimeError("Proxy bridge is not running")
        return {"server": f"socks5://127.0.0.1:{self.port}"}

    async def start(self, timeout: float = 5.0) -> int:
        """Start the sing-box bridge process and wait for the SOCKS5 port to open."""
        if self._closed:
            raise RuntimeError("Proxy bridge is closed")
        if self.port is not None and self.proc is not None:
            return self.port

        singbox_bin = find_singbox_binary()
        if not singbox_bin:
            raise RuntimeError(
                "sing-box executable not found. Please install sing-box (e.g. via package manager "
                "or placed in resources/bin/sing-box) to bridge VLESS/VMess/Trojan nodes."
            )

        self.port = get_random_free_port()
        config_data = generate_singbox_config(self.port, self.proxy_config, tag=self.tag)

        temp_file = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        try:
            json.dump(config_data, temp_file, indent=2)
            temp_file.flush()
        finally:
            temp_file.close()

        self.config_path = Path(temp_file.name)

        try:
            self.proc = subprocess.Popen(
                [singbox_bin, "run", "-c", str(self.config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as exc:
            self._cleanup_file()
            raise RuntimeError(f"Failed to launch sing-box: {exc}") from exc

        # Wait for the local SOCKS5 port to accept connections
        start_time = asyncio.get_running_loop().time()
        while asyncio.get_running_loop().time() - start_time < timeout:
            if self.proc.poll() is not None:
                _, stderr = self.proc.communicate()
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                self._cleanup_file()
                raise RuntimeError(f"sing-box exited unexpectedly: {err_msg}")

            try:
                # Test TCP connection to ephemeral socks5 port
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", self.port), timeout=0.1
                )
                writer.close()
                await writer.wait_closed()
                logger.debug(f"sing-box bridge started on 127.0.0.1:{self.port} (tag={self.tag})")
                return self.port
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.05)

        # Timeout reached
        await self.close()
        raise TimeoutError(f"sing-box failed to open port {self.port} within {timeout} seconds")

    async def close(self) -> None:
        """Terminate the sing-box bridge process and clean up temporary files."""
        self._closed = True
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    await asyncio.to_thread(self.proc.wait, timeout=2.0)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    await asyncio.to_thread(self.proc.wait)
            self.proc = None

        self._cleanup_file()
        logger.debug(f"sing-box bridge closed (port={self.port}, tag={self.tag})")

    def _cleanup_file(self) -> None:
        if self.config_path and self.config_path.exists():
            try:
                self.config_path.unlink()
            except OSError:
                pass
            self.config_path = None


class ProxyBridgeManager:
    """Manage lifecycle of sing-box bridges mapped to profile IDs."""

    def __init__(self) -> None:
        self.active_bridges: dict[str, ProxyBridge] = {}

    def get_bridge(self, profile_id: str) -> ProxyBridge | None:
        return self.active_bridges.get(profile_id)

    async def start_bridge(self, profile_id: str, proxy_config: Any) -> int:
        """Allocate a free port and start a sing-box bridge for the profile."""
        if profile_id in self.active_bridges:
            await self.stop_bridge(profile_id)

        bridge = ProxyBridge(proxy_config, tag=f"profile-{profile_id}")
        port = await bridge.start()
        self.active_bridges[profile_id] = bridge
        return port

    async def stop_bridge(self, profile_id: str) -> None:
        """Stop the sing-box bridge and clean up when the profile closes."""
        if profile_id in self.active_bridges:
            bridge = self.active_bridges.pop(profile_id)
            await bridge.close()

    async def stop_all(self) -> None:
        """Stop all running bridges."""
        profile_ids = list(self.active_bridges.keys())
        for pid in profile_ids:
            try:
                await self.stop_bridge(pid)
            except Exception as exc:
                logger.warning(f"Error stopping bridge for profile {pid}: {exc}")


bridge_manager = ProxyBridgeManager()
