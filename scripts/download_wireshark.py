import requests
import os

def download_wireshark():
    """Download Wireshark installer."""
    # Latest version URL for Windows 64-bit
    url = "https://2.na.dl.wireshark.org/win64/Wireshark-win64-4.2.3.exe"
    installer_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wireshark-installer.exe")
    
    print(f"Downloading Wireshark installer to {installer_path}")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    
    with open(installer_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    
    print("Download complete. Please run the installer manually.")
    print(f"Installer location: {installer_path}")
    print("\nIMPORTANT: During installation:")
    print("1. Install Npcap if prompted (if not already installed)")
    print("2. Install USBPcap if you want to capture USB traffic")
    print("3. Add Wireshark to the system PATH")

if __name__ == "__main__":
    download_wireshark()
