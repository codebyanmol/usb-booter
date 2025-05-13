#!/usr/bin/env python3
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
import subprocess
import requests
import re
from pathlib import Path
import argparse
import shutil
import textwrap

# Configuration
APKTOOL_PATH = "apktool"
JADX_PATH = "jadx"
DANGEROUS_PERMISSIONS = [
    "INTERNET",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO",
    "READ_CALENDAR",
    "WRITE_CALENDAR",
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_PHONE_STATE",
    "CALL_PHONE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_EXTERNAL_STORAGE",
    "CAMERA",
    "BODY_SENSORS",
    "ACCESS_BACKGROUND_LOCATION"
]

TRACKER_SIGNATURES = [
    "google.analytics",
    "flurry",
    "facebook.analytics",
    "adjust",
    "appsflyer",
    "branch.io",
    "mixpanel",
    "amplitude",
    "firebase.analytics",
    "crashlytics",
    "sentry",
    "bugsnag",
    "newrelic",
    "appmetrica",
    "yandex.metrica"
]

MALWARE_INDICATORS = [
    "payload",
    "exploit",
    "root",
    "privilege",
    "escalation",
    "botnet",
    "rat",
    "remote.access",
    "spy",
    "stealer",
    "keylogger"
]

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    print(f"{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}")
    print(f"{Color.BOLD}{Color.CYAN}{text.center(60)}{Color.RESET}")
    print(f"{Color.BOLD}{Color.CYAN}{'='*60}{Color.RESET}\n")

def print_success(text):
    print(f"{Color.GREEN}[+] {text}{Color.RESET}")

def print_warning(text):
    print(f"{Color.YELLOW}[!] {text}{Color.RESET}")

def print_error(text):
    print(f"{Color.RED}[-] {text}{Color.RESET}")

def print_info(text):
    print(f"{Color.BLUE}[*] {text}{Color.RESET}")

def check_dependencies():
    """Check if required tools are installed."""
    required_tools = [APKTOOL_PATH, JADX_PATH]
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run([tool, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_tools.append(tool)
    
    if missing_tools:
        print_error(f"Missing required tools: {', '.join(missing_tools)}")
        print_info("Please install them in Termux with:")
        print("pkg install apktool jadx")
        sys.exit(1)

def download_apk(url, output_path):
    """Download an APK from a URL."""
    try:
        print_info(f"Downloading APK from {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print_success(f"APK downloaded to {output_path}")
        return True
    except Exception as e:
        print_error(f"Failed to download APK: {e}")
        return False

def get_apk_path():
    """Get APK path from user input or download from URL."""
    while True:
        print("\n1. Enter path to APK file")
        print("2. Download APK from URL")
        print("3. Exit")
        choice = input("\nSelect an option (1-3): ").strip()
        
        if choice == "1":
            apk_path = input("Enter path to APK file: ").strip()
            if os.path.isfile(apk_path):
                return apk_path
            print_error("File not found. Please try again.")
        elif choice == "2":
            url = input("Enter APK download URL: ").strip()
            apk_path = "downloaded.apk"
            if download_apk(url, apk_path):
                return apk_path
        elif choice == "3":
            sys.exit(0)
        else:
            print_error("Invalid choice. Please try again.")

def decompile_apk(apk_path, output_dir=None):
    """Decompile APK using apktool."""
    if output_dir is None:
        output_dir = os.path.splitext(os.path.basename(apk_path))[0] + "_decompiled"
    
    if os.path.exists(output_dir):
        print_warning(f"Output directory {output_dir} already exists.")
        choice = input("Delete and recreate? (y/n): ").lower()
        if choice == 'y':
            shutil.rmtree(output_dir)
        else:
            print_info("Using existing decompiled files.")
            return output_dir
    
    print_info(f"Decompiling {apk_path}...")
    try:
        subprocess.run([APKTOOL_PATH, "d", apk_path, "-o", output_dir, "-f"], check=True)
        print_success(f"APK decompiled to {output_dir}")
        return output_dir
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to decompile APK: {e}")
        return None

def extract_manifest(decompiled_dir):
    """Extract AndroidManifest.xml from decompiled APK."""
    manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest_path):
        print_error("AndroidManifest.xml not found in decompiled directory")
        return None
    
    print_success(f"Found AndroidManifest.xml at {manifest_path}")
    return manifest_path

def parse_permissions(manifest_path):
    """Parse permissions from AndroidManifest.xml."""
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        permissions = []
        namespace = "{http://schemas.android.com/apk/res/android}"
        
        for item in root.iter("uses-permission"):
            permission = item.get(f"{namespace}name")
            if permission:
                permissions.append(permission.split(".")[-1])
        
        return permissions
    except Exception as e:
        print_error(f"Failed to parse AndroidManifest.xml: {e}")
        return []

def analyze_permissions(permissions):
    """Analyze permissions and identify dangerous ones."""
    dangerous_found = []
    normal_permissions = []
    
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            dangerous_found.append(perm)
        else:
            normal_permissions.append(perm)
    
    return dangerous_found, normal_permissions

def display_permissions(dangerous_perms, normal_perms):
    """Display permissions in a user-friendly format."""
    print_header("PERMISSIONS ANALYSIS")
    
    if dangerous_perms:
        print(f"{Color.RED}{Color.BOLD}DANGEROUS PERMISSIONS:{Color.RESET}")
        for perm in dangerous_perms:
            print(f"  {Color.RED}✗ {perm}{Color.RESET}")
        print()
    
    if normal_perms:
        print(f"{Color.GREEN}{Color.BOLD}NORMAL PERMISSIONS:{Color.RESET}")
        for perm in normal_perms:
            print(f"  {Color.GREEN}✓ {perm}{Color.RESET}")
        print()

def modify_manifest(manifest_path):
    """Allow user to modify AndroidManifest.xml."""
    print_header("MANIFEST MODIFICATION")
    
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        namespace = "{http://schemas.android.com/apk/res/android}"
        
        # Backup original manifest
        backup_path = manifest_path + ".bak"
        shutil.copy2(manifest_path, backup_path)
        print_info(f"Created backup of manifest at {backup_path}")
        
        # Get all permissions
        permissions = []
        for item in root.iter("uses-permission"):
            permission = item.get(f"{namespace}name")
            if permission:
                permissions.append((item, permission))
        
        if not permissions:
            print_warning("No permissions found in manifest")
            return False
        
        # Display permissions with numbers
        print(f"{Color.BOLD}Select permissions to remove:{Color.RESET}")
        for i, (_, perm) in enumerate(permissions, 1):
            perm_name = perm.split(".")[-1]
            if perm_name in DANGEROUS_PERMISSIONS:
                color = Color.RED
            else:
                color = Color.GREEN
            print(f"  {i}. {color}{perm}{Color.RESET}")
        
        print("\nEnter permission numbers to remove (comma-separated, or 0 to cancel)")
        choices = input("Your choice: ").strip()
        
        if choices == "0":
            print_info("Manifest modification cancelled")
            return False
        
        # Process user choices
        choices = [int(c.strip()) for c in choices.split(",") if c.strip().isdigit()]
        choices = [c for c in choices if 1 <= c <= len(permissions)]
        
        if not choices:
            print_warning("No valid permissions selected")
            return False
        
        # Remove selected permissions
        removed_perms = []
        for choice in sorted(choices, reverse=True):
            if 1 <= choice <= len(permissions):
                item, perm = permissions[choice-1]
                root.remove(item)
                removed_perms.append(perm)
        
        # Save modified manifest
        tree.write(manifest_path, encoding="utf-8", xml_declaration=True)
        
        print_success(f"Removed permissions: {', '.join(removed_perms)}")
        return True
    except Exception as e:
        print_error(f"Failed to modify manifest: {e}")
        return False

def scan_for_trackers(decompiled_dir):
    """Scan decompiled code for known trackers and malware indicators."""
    print_header("MALWARE & TRACKER SCAN")
    
    tracker_matches = []
    malware_matches = []
    suspicious_files = []
    
    # Walk through decompiled directory
    for root, _, files in os.walk(decompiled_dir):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip binary files
            if not (file.endswith(".smali") or file.endswith(".xml") or file.endswith(".java")):
                continue
            
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # Check for tracker signatures
                for sig in TRACKER_SIGNATURES:
                    if sig.lower() in content.lower():
                        tracker_matches.append((file_path, sig))
                
                # Check for malware indicators
                for indicator in MALWARE_INDICATORS:
                    if indicator.lower() in content.lower():
                        malware_matches.append((file_path, indicator))
                
                # Check for suspicious URLs
                urls = re.findall(r"https?://[^\s\"'>]+", content)
                for url in urls:
                    if any(tracker in url.lower() for tracker in TRACKER_SIGNATURES):
                        suspicious_files.append((file_path, f"Suspicious URL: {url}"))
            
            except Exception as e:
                print_warning(f"Could not scan {file_path}: {e}")
    
    # Display results
    if tracker_matches:
        print(f"{Color.YELLOW}{Color.BOLD}TRACKERS DETECTED:{Color.RESET}")
        for file_path, sig in tracker_matches:
            print(f"  {Color.YELLOW}⚠ {sig} in {file_path}{Color.RESET}")
        print()
    
    if malware_matches:
        print(f"{Color.RED}{Color.BOLD}MALWARE INDICATORS DETECTED:{Color.RESET}")
        for file_path, indicator in malware_matches:
            print(f"  {Color.RED}☠ {indicator} in {file_path}{Color.RESET}")
        print()
    
    if suspicious_files:
        print(f"{Color.MAGENTA}{Color.BOLD}SUSPICIOUS FILES:{Color.RESET}")
        for file_path, reason in suspicious_files:
            print(f"  {Color.MAGENTA}? {reason} in {file_path}{Color.RESET}")
        print()
    
    if not tracker_matches and not malware_matches and not suspicious_files:
        print_success("No trackers or malware indicators detected")
    
    return len(tracker_matches) + len(malware_matches)

def repack_apk(decompiled_dir, output_apk=None):
    """Repack decompiled APK into new APK."""
    if output_apk is None:
        original_name = os.path.basename(decompiled_dir).replace("_decompiled", "")
        output_apk = original_name + "_modified.apk"
    
    print_info(f"Repacking APK to {output_apk}")
    try:
        subprocess.run([APKTOOL_PATH, "b", decompiled_dir, "-o", output_apk], check=True)
        print_success(f"Successfully repacked APK to {output_apk}")
        return output_apk
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to repack APK: {e}")
        return None

def sign_apk(apk_path):
    """Sign APK using apksigner (simplified for Termux)."""
    print_info("Signing APK (this may take a moment)...")
    try:
        # In a real implementation, you'd need to set up a keystore
        # This is a simplified version for demonstration
        signed_apk = apk_path.replace(".apk", "_signed.apk")
        subprocess.run(["apksigner", "sign", "--ks", "debug.keystore", "--ks-pass", "pass:android", apk_path], check=True)
        print_success(f"APK signed and saved as {signed_apk}")
        return signed_apk
    except Exception as e:
        print_warning(f"APK signing failed: {e}")
        print_info("You may need to sign the APK manually before installing")
        return apk_path

def install_apk(apk_path):
    """Install APK on device."""
    print_info(f"Attempting to install {apk_path}")
    try:
        subprocess.run(["termux-open", apk_path], check=True)
        print_success("APK installation launched")
    except Exception as e:
        print_error(f"Failed to install APK: {e}")
        print_info("You can install it manually with: termux-open path/to/apk")

def main():
    # Check dependencies first
    check_dependencies()
    
    print_header("APK INSPECTOR & MODIFIER")
    print("A tool for analyzing and modifying APK files in Termux\n")
    
    # Get APK file
    apk_path = get_apk_path()
    
    # Decompile APK
    decompiled_dir = decompile_apk(apk_path)
    if not decompiled_dir:
        sys.exit(1)
    
    # Extract and analyze manifest
    manifest_path = extract_manifest(decompiled_dir)
    if not manifest_path:
        sys.exit(1)
    
    permissions = parse_permissions(manifest_path)
    dangerous_perms, normal_perms = analyze_permissions(permissions)
    display_permissions(dangerous_perms, normal_perms)
    
    # Scan for trackers and malware
    scan_for_trackers(decompiled_dir)
    
    # Offer modification options
    modify = input("\nDo you want to modify the APK? (y/n): ").lower() == 'y'
    if modify:
        if modify_manifest(manifest_path):
            # Repack APK after modification
            modified_apk = repack_apk(decompiled_dir)
            if modified_apk:
                # Offer to sign and install
                install = input("\nDo you want to install the modified APK? (y/n): ").lower() == 'y'
                if install:
                    signed_apk = sign_apk(modified_apk)
                    install_apk(signed_apk)
    
    print("\n" + "="*60)
    print_header("ANALYSIS COMPLETE")
    print("You can find the decompiled files in:", decompiled_dir)
    if modify and 'modified_apk' in locals():
        print("Modified APK saved as:", modified_apk)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(0)
