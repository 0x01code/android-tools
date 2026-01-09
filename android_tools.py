#!/usr/bin/env python3
"""
Android Security Tools - Cross-platform
Combines Burp Certificate installation and Frida Server deployment
Works on: Windows, macOS, Linux

Author: 0x01code
"""

import subprocess
import sys
import shutil
import platform
import urllib.request
import lzma
import time
import argparse
import re
import os
from pathlib import Path
from typing import List, Tuple

# ====== Configuration ======
# These will be set by parse_arguments() in main()
CERT_FILE = None
DEVICE_CERT_DIR = "/system/etc/security/cacerts"

FRIDA_VER = None
FRIDA_ARCH = None
FRIDA_URL = None
AUTO_DETECT_ARCH = False
LOCAL_DIR = Path("../tmp").resolve()
LOCAL_XZ = None
LOCAL_BIN = LOCAL_DIR / "frida-server"
REMOTE_BIN = "/data/local/tmp/frida-server"
# ===========================


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='Android Security Tools - Burp Certificate & Frida Server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python android_tools.py
  python android_tools.py --frida-version 16.0.0
  python android_tools.py --frida-arch android-x86
  python android_tools.py --auto-detect-arch
  python android_tools.py --cert-file ./certs/my-burp.cer
        '''
    )

    parser.add_argument(
        '-v', '--frida-version',
        default='17.5.2',
        help='Frida server version (default: 17.5.2)'
    )

    parser.add_argument(
        '-a', '--frida-arch',
        help='Frida architecture: android-arm64, android-arm, android-x86_64, android-x86 (default: auto-detect or android-arm64)'
    )

    parser.add_argument(
        '-c', '--cert-file',
        default='./burp.cer',
        help='Burp certificate file path (default: ./burp.cer)'
    )

    parser.add_argument(
        '-d', '--auto-detect-arch',
        action='store_true',
        help='Auto-detect device architecture'
    )

    return parser.parse_args()


def map_abi_to_frida_arch(abi: str) -> str:
    """Map device ABI to Frida architecture name"""
    mapping = {
        'arm64-v8a': 'android-arm64',
        'armeabi-v7a': 'android-arm',
        'armeabi': 'android-arm',
        'x86_64': 'android-x86_64',
        'x86': 'android-x86'
    }
    return mapping.get(abi, 'android-arm64')  # Default to arm64


def detect_device_arch(serial: str) -> str:
    """Detect device architecture via ABI"""
    cmd = ['adb', '-s', serial, 'shell', 'getprop', 'ro.product.cpu.abi']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        abi = result.stdout.strip()
        return map_abi_to_frida_arch(abi)
    return 'android-arm64'  # Default fallback


def validate_cert_file(path: str) -> bool:
    """Validate certificate file exists and is readable"""
    if not os.path.exists(path):
        print(f"[!] ไม่พบไฟล์ certificate: {path}")
        return False
    if not os.access(path, os.R_OK):
        print(f"[!] ไม่สามารถอ่านไฟล์ certificate: {path}")
        return False
    return True


def validate_frida_version(version: str) -> bool:
    """Validate Frida version format (x.y.z)"""
    if not re.match(r'^\d+\.\d+\.\d+$', version):
        print(f"[!] รูปแบบ version ไม่ถูกต้อง: {version} (ต้องเป็น x.y.z)")
        return False
    return True


def validate_frida_arch(arch: str) -> bool:
    """Validate Frida architecture name"""
    valid_archs = ['android-arm64', 'android-arm', 'android-x86_64', 'android-x86']
    if arch not in valid_archs:
        print(f"[!] สถาปัตยกรรมไม่ถูกต้อง: {arch}")
        print(f"    เลือกได้: {', '.join(valid_archs)}")
        return False
    return True


def check_tool(tool_name: str) -> bool:
    """Check if a required tool is available in PATH"""
    return shutil.which(tool_name) is not None


def run_command(cmd: List[str], check: bool = True, capture: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the result"""
    try:
        if capture:
            return subprocess.run(cmd, capture_output=True, text=text, check=check)
        else:
            return subprocess.run(cmd, check=check)
    except subprocess.CalledProcessError as e:
        if capture and text:
            print(f"[!] คำสั่งล้มเหลว: {' '.join(cmd)}")
            if e.stdout:
                print(f"    stdout: {e.stdout}")
            if e.stderr:
                print(f"    stderr: {e.stderr}")
        raise


def show_menu() -> str:
    """Display main menu and get user choice"""
    print("\n" + "=" * 50)
    print("=== Android Security Tools ===")
    print("=" * 50)
    print("1. Push Burp Certificate to Device")
    print("2. Run Frida Server")
    print("3. Install Required Tools (adb, openssl)")
    print("4. Exit")
    print("=" * 50)
    choice = input("\nเลือกหมายเลข: ").strip()
    return choice


# ==================== Module 1: Push Burp Certificate ====================

def push_burp_cert():
    """Module 1: Push Burp certificate to Android device"""
    print("\n[*] เริ่มติดตั้ง Burp Certificate")

    # Check for required tools
    if not check_tool("adb"):
        print("[!] ไม่พบ adb - กรุณาติดตั้งก่อน (ใช้ option 3)")
        return

    if not check_tool("openssl"):
        print("[!] ไม่พบ openssl - กรุณาติดตั้งก่อน (ใช้ option 3)")
        return

    # Check for certificate file
    cert_path = Path(CERT_FILE)
    if not cert_path.exists():
        print(f"[!] ไม่พบไฟล์ {CERT_FILE}")
        return

    try:
        # Convert certificate to PEM format
        print("[*] แปลง certificate เป็น PEM")
        temp_pem = Path("temp.pem")

        # Try DER format first
        result = run_command(
            ["openssl", "x509", "-inform", "DER", "-in", str(cert_path), "-out", str(temp_pem)],
            check=False
        )

        # If DER fails, try PEM format
        if result.returncode != 0:
            run_command(
                ["openssl", "x509", "-inform", "PEM", "-in", str(cert_path), "-out", str(temp_pem)]
            )

        # Generate hash-based filename
        result = run_command(
            ["openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(temp_pem)]
        )
        hash_value = result.stdout.strip().split('\n')[0]
        hash_name = f"{hash_value}.0"

        # Rename temp file
        hash_path = Path(hash_name)
        temp_pem.rename(hash_path)

        # Push to device
        print("[*] กำลัง remount /system เป็น writable")
        run_command(["adb", "root"], check=False)
        time.sleep(1)
        run_command(["adb", "remount"], check=False)
        # run_command(["adb", "shell", "mount", "-o", "rw,remount", "/"], check=False)

        print(f"[*] ส่งไฟล์ไปยัง {DEVICE_CERT_DIR}/{hash_name}")
        run_command(["adb", "push", str(hash_path), f"{DEVICE_CERT_DIR}/{hash_name}"])

        print("[*] ตั้ง permission")
        run_command(["adb", "shell", f"chmod 644 {DEVICE_CERT_DIR}/{hash_name}"])

        # Clean up
        if hash_path.exists():
            hash_path.unlink()

        print("[*] รีบูตเครื่องเพื่อใช้ cert ใหม่")
        run_command(["adb", "reboot"])

        print("[✓] เสร็จสิ้น — Burp CA ติดตั้งลง system trust แล้ว")

    except Exception as e:
        print(f"[!] เกิดข้อผิดพลาด: {e}")
        # Clean up on error
        for f in [Path("temp.pem"), Path(hash_name) if 'hash_name' in locals() else None]:
            if f and f.exists():
                f.unlink()


# ==================== Module 2: Run Frida Server ====================

def choose_device() -> List[str]:
    """Get list of connected devices and let user choose"""
    print("[*] ตรวจสอบ emulator/device ที่เชื่อมต่ออยู่...")

    result = run_command(["adb", "devices"])
    lines = result.stdout.strip().split('\n')[1:]  # Skip first line

    devices = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])

    if not devices:
        print("[!] ไม่พบ emulator/device ที่เชื่อมต่อ")
        return []

    print("\nพบอุปกรณ์ทั้งหมด:")
    for i, device in enumerate(devices, 1):
        print(f"  [{i}] {device}")

    print("0) รันกับทุกอุปกรณ์")

    choice = input("เลือกหมายเลขอุปกรณ์: ").strip()

    if choice == "0":
        return devices
    elif choice.isdigit() and 1 <= int(choice) <= len(devices):
        return [devices[int(choice) - 1]]
    else:
        print("[!] เลือกไม่ถูกต้อง")
        return []


def setup_frida_server(serial: str, auto_detect: bool = False):
    """Setup Frida server on a specific device"""
    global FRIDA_ARCH, FRIDA_URL, LOCAL_XZ

    print(f"\n=== จัดการอุปกรณ์: {serial} ===")

    # Check device ABI
    print("[*] ตรวจสอบ ABI...")
    result = run_command(["adb", "-s", serial, "shell", "getprop", "ro.product.cpu.abi"])
    device_abi = result.stdout.strip()
    print(f"    ABI: {device_abi}")

    # Auto-detect architecture if requested
    if auto_detect:
        detected_arch = map_abi_to_frida_arch(device_abi)
        print(f"[*] ตรวจพบ architecture ของอุปกรณ์: {detected_arch}")
        FRIDA_ARCH = detected_arch
        # Update URLs with new architecture
        FRIDA_URL = f"https://github.com/frida/frida/releases/download/{FRIDA_VER}/frida-server-{FRIDA_VER}-{FRIDA_ARCH}.xz"
        LOCAL_XZ = LOCAL_DIR / f"frida-server-{FRIDA_VER}-{FRIDA_ARCH}.xz"
    else:
        # Show warning if architecture might mismatch
        expected_abi_keywords = {
            'android-arm64': 'arm64',
            'android-arm': 'arm',
            'android-x86_64': 'x86_64',
            'android-x86': 'x86'
        }
        expected_keyword = expected_abi_keywords.get(FRIDA_ARCH, '')
        if expected_keyword and expected_keyword not in device_abi:
            print(f"[!] คำเตือน: อุปกรณ์ ABI ({device_abi}) อาจไม่ตรงกับ Frida arch ({FRIDA_ARCH})")

    # Download frida-server
    print(f"[*] ดาวน์โหลด frida-server: {FRIDA_URL}")
    LOCAL_DIR.mkdir(parents=True, exist_ok=True)

    try:
        urllib.request.urlretrieve(FRIDA_URL, LOCAL_XZ)
    except Exception as e:
        print(f"[!] ดาวน์โหลดล้มเหลว: {e}")
        return

    # Extract .xz file
    print("[*] แตกไฟล์ .xz → ไฟล์ปฏิบัติการ")
    try:
        with lzma.open(LOCAL_XZ, 'rb') as f_in:
            with open(LOCAL_BIN, 'wb') as f_out:
                f_out.write(f_in.read())

        # Make executable on Unix-like systems
        if platform.system() != "Windows":
            LOCAL_BIN.chmod(0o755)
    except Exception as e:
        print(f"[!] แตกไฟล์ล้มเหลว: {e}")
        return

    # Push to device
    print(f"[*] กำลัง push ไปยังอุปกรณ์: {REMOTE_BIN}")
    result = run_command(["adb", "-s", serial, "push", str(LOCAL_BIN), REMOTE_BIN], check=False)
    if result.returncode != 0:
        print("[!] Push ล้มเหลว")
        return

    run_command(["adb", "-s", serial, "shell", f"chmod 755 '{REMOTE_BIN}'"], check=False)

    # Kill old frida-server
    print("[*] พยายามหยุด frida-server เดิม (ถ้ามี)")
    run_command(["adb", "-s", serial, "shell", f"su -c 'pkill -f {REMOTE_BIN}'"], check=False)
    run_command(["adb", "-s", serial, "shell", f"pkill -f {REMOTE_BIN}"], check=False)

    # Set SELinux to permissive
    print("[*] ตั้งค่า SELinux เป็น permissive (ถ้าทำได้)")
    run_command(["adb", "-s", serial, "shell", "su -c 'setenforce 0'"], check=False)

    run_command(["adb", "-s", serial, "root"], check=False)

    # Run frida-server
    print("[*] รัน frida-server เป็น background")
    result = run_command(
        ["adb", "-s", serial, "shell", f"su -c 'nohup {REMOTE_BIN} >/dev/null 2>&1 &'"],
        check=False
    )

    if result.returncode != 0:
        print("[!] รันด้วย su ไม่ได้ ลองรันแบบปกติ")
        run_command(["adb", "-s", serial, "shell", f"nohup {REMOTE_BIN} >/dev/null 2>&1 &"], check=False)

    time.sleep(1)

    # Check status
    print(f"[*] ตรวจสอบสถานะ frida-server บนอุปกรณ์ {serial}")
    result = run_command(["adb", "-s", serial, "shell", "ps -A | grep -i frida-server"], check=False)
    if result.returncode != 0 or not result.stdout.strip():
        print("[!] ยังไม่เห็น process frida-server")
    else:
        print(result.stdout.strip())


def run_frida_server():
    """Module 2: Download and run Frida server"""
    print("\n[*] เริ่มติดตั้ง Frida Server")

    # Check for adb
    if not check_tool("adb"):
        print("[!] ไม่พบ adb - กรุณาติดตั้งก่อน (ใช้ option 3)")
        return

    # Choose device
    selected = choose_device()
    if not selected:
        return

    # Setup Frida on selected devices
    for serial in selected:
        setup_frida_server(serial, auto_detect=AUTO_DETECT_ARCH)

        # Try to list processes with frida-ps
        print(f"[*] ทดลองรายการ process ด้วย frida-ps -D {serial}")
        if check_tool("frida-ps"):
            run_command(["frida-ps", "-D", serial], check=False)
        else:
            print("[i] ไม่พบ frida-ps ในเครื่องคุณ ข้ามขั้นตอนตรวจด้วย CLI")

    print("[✓] เสร็จสิ้น")


# ==================== Module 3: Install Tools ====================

def detect_os() -> Tuple[str, str]:
    """Detect operating system and return (os_type, os_name)"""
    os_type = platform.system()
    os_name = ""

    if os_type == "Linux":
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("ID="):
                        os_name = line.split("=")[1].strip().strip('"')
                        break
        except:
            os_name = "unknown"

    return os_type, os_name


def check_package_manager(manager: str) -> bool:
    """Check if a package manager is available"""
    return check_tool(manager)


def install_tools():
    """Module 3: Install required tools (adb, openssl)"""
    print("\n[*] ตรวจสอบและติดตั้ง Tools")

    # Detect OS
    os_type, os_name = detect_os()
    print(f"[*] ระบบปฏิบัติการ: {os_type}", end="")
    if os_name:
        print(f" ({os_name})")
    else:
        print()

    # Check tool status
    print("\n[*] สถานะ Tools:")
    adb_installed = check_tool("adb")
    openssl_installed = check_tool("openssl")

    print(f"  - adb: {'✓ ติดตั้งแล้ว' if adb_installed else '✗ ยังไม่ได้ติดตั้ง'}")
    print(f"  - openssl: {'✓ ติดตั้งแล้ว' if openssl_installed else '✗ ยังไม่ได้ติดตั้ง'}")

    if adb_installed and openssl_installed:
        print("\n[✓] Tools ทั้งหมดติดตั้งแล้ว!")
        return

    print("\n" + "=" * 50)

    # Windows
    if os_type == "Windows":
        print("[*] ตรวจสอบ Package Managers บน Windows...")

        managers = {
            "choco": "Chocolatey",
            "scoop": "Scoop",
            "winget": "winget"
        }

        available_managers = {cmd: name for cmd, name in managers.items() if check_package_manager(cmd)}

        if available_managers:
            print(f"[*] พบ Package Manager: {', '.join(available_managers.values())}")
            print("\nคำสั่งติดตั้ง:")

            for cmd, name in available_managers.items():
                if cmd == "choco":
                    print(f"\n  ใช้ {name}:")
                    if not adb_installed:
                        print("    choco install adb")
                    if not openssl_installed:
                        print("    choco install openssl")
                elif cmd == "scoop":
                    print(f"\n  ใช้ {name}:")
                    if not adb_installed:
                        print("    scoop install adb")
                    if not openssl_installed:
                        print("    scoop install openssl")
                elif cmd == "winget":
                    print(f"\n  ใช้ {name}:")
                    if not adb_installed:
                        print("    winget install Google.AndroidStudio.PlatformTools")
                    if not openssl_installed:
                        print("    winget install OpenSSL.Light")

            # Ask if user wants to auto-install
            print("\n" + "=" * 50)
            choice = input("\nต้องการติดตั้งอัตโนมัติหรือไม่? (y/n): ").strip().lower()

            if choice == 'y':
                # Use first available manager
                cmd = list(available_managers.keys())[0]

                if cmd == "choco":
                    if not adb_installed:
                        print("[*] กำลังติดตั้ง adb...")
                        run_command(["choco", "install", "adb", "-y"], check=False)
                    if not openssl_installed:
                        print("[*] กำลังติดตั้ง openssl...")
                        run_command(["choco", "install", "openssl", "-y"], check=False)
                elif cmd == "scoop":
                    if not adb_installed:
                        print("[*] กำลังติดตั้ง adb...")
                        run_command(["scoop", "install", "adb"], check=False)
                    if not openssl_installed:
                        print("[*] กำลังติดตั้ง openssl...")
                        run_command(["scoop", "install", "openssl"], check=False)
                elif cmd == "winget":
                    if not adb_installed:
                        print("[*] กำลังติดตั้ง adb...")
                        run_command(["winget", "install", "Google.AndroidStudio.PlatformTools"], check=False)
                    if not openssl_installed:
                        print("[*] กำลังติดตั้ง openssl...")
                        run_command(["winget", "install", "OpenSSL.Light"], check=False)

                print("\n[✓] การติดตั้งเสร็จสิ้น - กรุณารีสตาร์ท terminal แล้วลองอีกครั้ง")
        else:
            print("[!] ไม่พบ Package Manager")
            print("\nกรุณาติดตั้งด้วยตนเอง:")
            if not adb_installed:
                print("\n  ADB (Android Platform Tools):")
                print("    https://developer.android.com/tools/releases/platform-tools")
            if not openssl_installed:
                print("\n  OpenSSL:")
                print("    https://slproweb.com/products/Win32OpenSSL.html")

    # macOS
    elif os_type == "Darwin":
        print("[*] ตรวจสอบ Homebrew...")

        if check_package_manager("brew"):
            print("[*] พบ Homebrew")
            print("\nคำสั่งติดตั้ง:")
            if not adb_installed:
                print("  brew install android-platform-tools")
            if not openssl_installed:
                print("  brew install openssl")

            # Ask if user wants to auto-install
            print("\n" + "=" * 50)
            choice = input("\nต้องการติดตั้งอัตโนมัติหรือไม่? (y/n): ").strip().lower()

            if choice == 'y':
                if not adb_installed:
                    print("[*] กำลังติดตั้ง android-platform-tools...")
                    run_command(["brew", "install", "android-platform-tools"], check=False)
                if not openssl_installed:
                    print("[*] กำลังติดตั้ง openssl...")
                    run_command(["brew", "install", "openssl"], check=False)

                print("\n[✓] การติดตั้งเสร็จสิ้น")
        else:
            print("[!] ไม่พบ Homebrew")
            print("\nกรุณาติดตั้ง Homebrew ก่อน:")
            print('  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"')
            print("\nจากนั้นรันคำสั่ง:")
            if not adb_installed:
                print("  brew install android-platform-tools")
            if not openssl_installed:
                print("  brew install openssl")

    # Linux
    elif os_type == "Linux":
        print(f"[*] ตรวจสอบ Package Manager สำหรับ {os_name}...")

        if os_name in ["ubuntu", "debian"]:
            print("[*] พบ APT (Debian/Ubuntu)")
            print("\nคำสั่งติดตั้ง:")
            if not adb_installed:
                print("  sudo apt-get update")
                print("  sudo apt-get install -y adb")
            if not openssl_installed:
                print("  sudo apt-get install -y openssl")

            # Ask if user wants to auto-install
            print("\n" + "=" * 50)
            choice = input("\nต้องการติดตั้งอัตโนมัติหรือไม่? (y/n): ").strip().lower()

            if choice == 'y':
                print("[*] อัพเดท package list...")
                run_command(["sudo", "apt-get", "update"], check=False)

                if not adb_installed:
                    print("[*] กำลังติดตั้ง adb...")
                    run_command(["sudo", "apt-get", "install", "-y", "adb"], check=False)
                if not openssl_installed:
                    print("[*] กำลังติดตั้ง openssl...")
                    run_command(["sudo", "apt-get", "install", "-y", "openssl"], check=False)

                print("\n[✓] การติดตั้งเสร็จสิ้น")

        elif os_name in ["fedora", "rhel", "centos"]:
            print("[*] พบ YUM/DNF (Fedora/RHEL)")
            print("\nคำสั่งติดตั้ง:")
            if not adb_installed:
                print("  sudo yum install -y android-tools")
            if not openssl_installed:
                print("  sudo yum install -y openssl")

            # Ask if user wants to auto-install
            print("\n" + "=" * 50)
            choice = input("\nต้องการติดตั้งอัตโนมัติหรือไม่? (y/n): ").strip().lower()

            if choice == 'y':
                if not adb_installed:
                    print("[*] กำลังติดตั้ง android-tools...")
                    run_command(["sudo", "yum", "install", "-y", "android-tools"], check=False)
                if not openssl_installed:
                    print("[*] กำลังติดตั้ง openssl...")
                    run_command(["sudo", "yum", "install", "-y", "openssl"], check=False)

                print("\n[✓] การติดตั้งเสร็จสิ้น")

        elif os_name in ["arch", "manjaro"]:
            print("[*] พบ Pacman (Arch Linux)")
            print("\nคำสั่งติดตั้ง:")
            if not adb_installed:
                print("  sudo pacman -S --noconfirm android-tools")
            if not openssl_installed:
                print("  sudo pacman -S --noconfirm openssl")

            # Ask if user wants to auto-install
            print("\n" + "=" * 50)
            choice = input("\nต้องการติดตั้งอัตโนมัติหรือไม่? (y/n): ").strip().lower()

            if choice == 'y':
                if not adb_installed:
                    print("[*] กำลังติดตั้ง android-tools...")
                    run_command(["sudo", "pacman", "-S", "--noconfirm", "android-tools"], check=False)
                if not openssl_installed:
                    print("[*] กำลังติดตั้ง openssl...")
                    run_command(["sudo", "pacman", "-S", "--noconfirm", "openssl"], check=False)

                print("\n[✓] การติดตั้งเสร็จสิ้น")

        else:
            print(f"[!] ไม่รู้จัก Linux distribution: {os_name}")
            print("\nกรุณาติดตั้งด้วย package manager ของ distro คุณ:")
            if not adb_installed:
                print("  - adb หรือ android-tools")
            if not openssl_installed:
                print("  - openssl")

    else:
        print(f"[!] ไม่รู้จักระบบปฏิบัติการ: {os_type}")


# ==================== Main ====================

def main():
    """Main menu loop"""
    global CERT_FILE, FRIDA_VER, FRIDA_ARCH, FRIDA_URL, LOCAL_XZ, AUTO_DETECT_ARCH

    # Parse command-line arguments
    args = parse_arguments()

    # Validate inputs
    if not validate_frida_version(args.frida_version):
        sys.exit(1)

    # Set global configuration from arguments
    CERT_FILE = args.cert_file
    FRIDA_VER = args.frida_version
    AUTO_DETECT_ARCH = args.auto_detect_arch

    # Handle architecture (auto-detect or use specified)
    if args.frida_arch:
        if not validate_frida_arch(args.frida_arch):
            sys.exit(1)
        FRIDA_ARCH = args.frida_arch
    else:
        # Will auto-detect per device in setup_frida_server() if AUTO_DETECT_ARCH is True
        FRIDA_ARCH = 'android-arm64'  # Default fallback
        if not args.auto_detect_arch:
            # Only set auto-detect if not explicitly specified
            AUTO_DETECT_ARCH = True  # Auto-detect by default when no arch specified

    # Set URLs with configuration
    FRIDA_URL = f"https://github.com/frida/frida/releases/download/{FRIDA_VER}/frida-server-{FRIDA_VER}-{FRIDA_ARCH}.xz"
    LOCAL_XZ = LOCAL_DIR / f"frida-server-{FRIDA_VER}-{FRIDA_ARCH}.xz"

    # Show configuration
    print("\nAndroid Security Tools - Cross-platform")
    print("=" * 50)
    print("[*] การตั้งค่า:")
    print(f"    - Frida Version: {FRIDA_VER}")
    print(f"    - Frida Architecture: {FRIDA_ARCH}" + (" (auto-detect)" if AUTO_DETECT_ARCH else ""))
    print(f"    - Certificate File: {CERT_FILE}")
    print("=" * 50)

    try:
        choice = show_menu()

        if choice == "1":
            push_burp_cert()
        elif choice == "2":
            run_frida_server()
        elif choice == "3":
            install_tools()
        elif choice == "4":
            print("\n[✓] ออกจากโปรแกรม")
        else:
            print("[!] กรุณาเลือก 1-4")

    except KeyboardInterrupt:
        print("\n[!] ยกเลิกการทำงาน")
    except Exception as e:
        print(f"\n[!] เกิดข้อผิดพลาด: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] ยกเลิกการทำงาน")
        sys.exit(1)
    except Exception as e:
        print(f"[!] ข้อผิดพลาด: {e}")
        sys.exit(1)
