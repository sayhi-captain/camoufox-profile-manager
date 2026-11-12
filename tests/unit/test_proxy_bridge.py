import base64
import json
import socket
import pytest

from camoufox_pm.core.models import ProxyConfig, ProxyType
from camoufox_pm.core.proxy_bridge import (
    ProxyBridge,
    ProxyBridgeManager,
    find_singbox_binary,
    generate_singbox_config,
    get_random_free_port,
    parse_node_link,
)


def test_find_singbox_binary():
    bin_path = find_singbox_binary()
    assert bin_path is not None
    assert "sing-box" in bin_path


def test_get_random_free_port():
    port = get_random_free_port()
    assert 1024 <= port <= 65535


def test_parse_node_link_vless_reality():
    link = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com"
        "&fp=chrome&pbk=T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU&sid=1234&spx=%2F&type=tcp#TestVLESS"
    )
    parsed = parse_node_link(link)
    assert parsed["protocol"] == "vless"
    assert parsed["server"] == "1.2.3.4:443"
    assert parsed["host"] == "1.2.3.4"
    assert parsed["port"] == 443
    assert parsed["uuid"] == "a3b68078-d428-48fe-a78b-4b2a33f44534"
    assert parsed["name"] == "TestVLESS"
    assert parsed["security"] == "reality"
    assert parsed["sni"] == "yahoo.com"
    assert parsed["fp"] == "chrome"
    assert parsed["pbk"] == "T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU"
    assert parsed["sid"] == "1234"
    assert parsed["flow"] == "xtls-rprx-vision"
    assert parsed["transport"] == "tcp"


def test_parse_node_link_vless_ws():
    link = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@example.com:8443"
        "?encryption=none&security=tls&sni=example.com&type=ws&path=%2Fws&host=example.com#VlessWS"
    )
    parsed = parse_node_link(link)
    assert parsed["protocol"] == "vless"
    assert parsed["server"] == "example.com:8443"
    assert parsed["host"] == "example.com"
    assert parsed["port"] == 8443
    assert parsed["uuid"] == "a3b68078-d428-48fe-a78b-4b2a33f44534"
    assert parsed["name"] == "VlessWS"
    assert parsed["security"] == "tls"
    assert parsed["transport"] == "ws"
    assert parsed["path"] == "/ws"
    assert parsed["host_header"] == "example.com"


def test_parse_node_link_trojan():
    link = "trojan://password123@example.com:443?security=tls&sni=example.com#MyTrojan"
    parsed = parse_node_link(link)
    assert parsed["protocol"] == "trojan"
    assert parsed["server"] == "example.com:443"
    assert parsed["host"] == "example.com"
    assert parsed["port"] == 443
    assert parsed["password"] == "password123"
    assert parsed["name"] == "MyTrojan"
    assert parsed["security"] == "tls"


def test_parse_node_link_vmess_base64():
    vmess_obj = {
        "v": "2",
        "ps": "MyVMess",
        "add": "9.8.7.6",
        "port": 8443,
        "id": "uuid-1234-5678",
        "aid": 0,
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "ws.example.com",
        "path": "/ws",
        "tls": "tls",
    }
    b64 = base64.b64encode(json.dumps(vmess_obj).encode("utf-8")).decode("utf-8")
    parsed = parse_node_link(f"vmess://{b64}")
    assert parsed["protocol"] == "vmess"
    assert parsed["server"] == "9.8.7.6:8443"
    assert parsed["host"] == "9.8.7.6"
    assert parsed["port"] == 8443
    assert parsed["uuid"] == "uuid-1234-5678"
    assert parsed["name"] == "MyVMess"
    assert parsed["transport"] == "ws"
    assert parsed["security"] == "tls"
    assert parsed["path"] == "/ws"


def test_generate_singbox_config():
    link = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com"
        "&fp=chrome&pbk=T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU&sid=1234&spx=%2F&type=tcp#TestVLESS"
    )
    config = generate_singbox_config(28451, link)
    assert config["inbounds"][0]["type"] == "socks"
    assert config["inbounds"][0]["listen_port"] == 28451
    assert config["outbounds"][0]["type"] == "vless"
    assert config["outbounds"][0]["uuid"] == "a3b68078-d428-48fe-a78b-4b2a33f44534"
    assert config["outbounds"][0]["tls"]["reality"]["public_key"] == "T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU"


@pytest.mark.asyncio
async def test_proxy_bridge_lifecycle():
    link = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com"
        "&fp=chrome&pbk=T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU&sid=1234&spx=%2F&type=tcp#TestVLESS"
    )
    proxy = ProxyConfig(
        type=ProxyType.VLESS,
        server="1.2.3.4:443",
        username="a3b68078-d428-48fe-a78b-4b2a33f44534",
        node_link=link,
    )
    bridge = ProxyBridge(proxy, tag="test-lifecycle")
    try:
        port = await bridge.start(timeout=5.0)
        assert port is not None
        assert 1024 <= port <= 65535
        assert bridge.browser_proxy == {"server": f"socks5://127.0.0.1:{port}"}

        # Check that port is reachable
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as s:
            assert s is not None
    finally:
        await bridge.close()

    assert bridge.proc is None


@pytest.mark.asyncio
async def test_proxy_bridge_manager():
    manager = ProxyBridgeManager()
    link = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com"
        "&fp=chrome&pbk=T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU&sid=1234&spx=%2F&type=tcp#TestVLESS"
    )
    pid = "test-prof-1"
    try:
        port = await manager.start_bridge(pid, link)
        assert port is not None
        assert pid in manager.active_bridges
        assert manager.get_bridge(pid) is not None
    finally:
        await manager.stop_bridge(pid)

    assert pid not in manager.active_bridges
    assert manager.get_bridge(pid) is None


def test_parse_proxy_import_node_links():
    from camoufox_pm.core.proxy_import import parse_proxy_import

    text = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443?security=reality&sni=yahoo.com#Node1\n"
        "trojan://mysecretpass@example.com:443#Node2\n"
        "http://proxy.example:8080\n"
    )
    imported = parse_proxy_import(text)
    assert len(imported) == 3
    line1_num, line1_cfg = imported[0]
    assert line1_num == 1
    assert line1_cfg.type == ProxyType.VLESS
    assert line1_cfg.server == "1.2.3.4:443"
    assert line1_cfg.username == "a3b68078-d428-48fe-a78b-4b2a33f44534"
    assert line1_cfg.node_link.startswith("vless://")

    line2_num, line2_cfg = imported[1]
    assert line2_num == 2
    assert line2_cfg.type == ProxyType.TROJAN
    assert line2_cfg.server == "example.com:443"
    assert line2_cfg.password == "mysecretpass"

    line3_num, line3_cfg = imported[2]
    assert line3_num == 3
    assert line3_cfg.type == ProxyType.HTTP
    assert line3_cfg.server == "proxy.example:8080"


@pytest.mark.asyncio
async def test_proxy_check_preflight_and_resolve_exit_ip(monkeypatch):
    from camoufox_pm.core import proxy_check

    link = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com"
        "&fp=chrome&pbk=T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU&sid=1234&spx=%2F&type=tcp#TestVLESS"
    )
    proxy = ProxyConfig(
        type=ProxyType.VLESS,
        server="1.2.3.4:443",
        username="a3b68078-d428-48fe-a78b-4b2a33f44534",
        node_link=link,
    )
    findings = proxy_check.preflight(proxy)
    assert not any(f.level == "error" for f in findings)


@pytest.mark.asyncio
async def test_proxy_bridge_follows_session_lifetime(monkeypatch):
    import camoufox_pm.core.browser_session as bs
    from camoufox_pm.core.browser_session import BrowserSessionManager

    class FakeCamoufox:
        def __init__(self):
            self.closed = False
            self.browser = self

        async def start(self):
            return self

        async def close(self):
            self.closed = True

        async def __aexit__(self, *args):
            self.closed = True

    options_seen = []
    fake = FakeCamoufox()

    def launch(**options):
        options_seen.append(options)
        return fake

    monkeypatch.setattr(bs, "CAMOUFOX_AVAILABLE", True)
    monkeypatch.setattr(bs, "AsyncCamoufox", launch)

    manager = BrowserSessionManager()
    link = (
        "vless://a3b68078-d428-48fe-a78b-4b2a33f44534@1.2.3.4:443"
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=yahoo.com"
        "&fp=chrome&pbk=T51uECPj_UZg_0Ix9r-XOwL7dlb7UnI5RgGIjc6Y-HU&sid=1234&spx=%2F&type=tcp#Node"
    )
    launch_options = {
        "proxy": {
            "server": "vless://1.2.3.4:443",
            "type": "vless",
            "node_link": link,
        }
    }

    session = await manager.launch("prof-test-bridge", launch_options)
    assert "prof-test-bridge" in manager.active_sessions
    assert session.proxy_bridge is not None
    assert session.proxy_bridge.port is not None
    assert options_seen[0]["proxy"]["server"] == f"socks5://127.0.0.1:{session.proxy_bridge.port}"
    assert options_seen[0]["firefox_user_prefs"]["network.proxy.socks_remote_dns"] is True

    # Terminate session
    await session.terminate()
    assert session.proxy_bridge.proc is None


