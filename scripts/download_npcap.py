import requests
import os

def download_npcap():
    """Download Npcap installer."""
    url = "https://npcap.com/dist/npcap-1.80.exe"
    installer_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "npcap-installer.exe")
    
    print(f"Downloading Npcap installer to {installer_path}")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    
    with open(installer_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    
    print("Download complete. Please run the installer manually.")
    print(f"Installer location: {installer_path}")

if __name__ == "__main__":
    download_npcap()
