import json
import subprocess


def _powershell(script):
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def interface_index_for_ip(local_ip):
    escaped_ip = local_ip.replace("'", "''")
    result = _powershell(
        f"(Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{escaped_ip}' "
        "-ErrorAction Stop | Select-Object -First 1 -ExpandProperty InterfaceIndex)"
    )
    if result.returncode != 0 or not result.stdout.strip().isdigit():
        raise RuntimeError("Không xác định được network interface đang sử dụng.")
    return int(result.stdout.strip())


def read_forwarding_state(interface_index):
    result = _powershell(
        f"Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex {int(interface_index)} "
        "-ErrorAction Stop | Select-Object InterfaceIndex,Forwarding | ConvertTo-Json -Compress"
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Không đọc được trạng thái IP forwarding.")
    data = json.loads(result.stdout)
    return str(data["Forwarding"]).strip().lower() in ("enabled", "1", "true")


def set_forwarding(interface_index, enabled):
    value = "Enabled" if enabled else "Disabled"
    result = _powershell(
        f"Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex {int(interface_index)} "
        f"-Forwarding {value} -ErrorAction Stop"
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Không cập nhật được IP forwarding.")


class ForwardingStateGuard:
    """Change forwarding for one interface and restore its exact prior state."""

    def __init__(self, local_ip):
        self.interface_index = interface_index_for_ip(local_ip)
        self.original_state = read_forwarding_state(self.interface_index)
        self.restored = False

    def set(self, enabled):
        set_forwarding(self.interface_index, enabled)

    def restore(self):
        if not self.restored:
            set_forwarding(self.interface_index, self.original_state)
            self.restored = True
