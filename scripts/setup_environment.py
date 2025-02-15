import os
import sys
import requests
import subprocess
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def download_npcap():
    """Download Npcap installer"""
    npcap_url = "https://npcap.com/dist/npcap-1.75.exe"
    installer_path = Path(__file__).parent.parent / "tools" / "npcap-installer.exe"
    
    # Create tools directory if it doesn't exist
    installer_path.parent.mkdir(exist_ok=True)
    
    logger.info("Downloading Npcap installer...")
    response = requests.get(npcap_url, stream=True)
    response.raise_for_status()
    
    with open(installer_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    
    return installer_path

def install_npcap(installer_path):
    """Install Npcap with required options"""
    logger.info("Installing Npcap...")
    try:
        # Run installer with WinPcap compatibility mode
        subprocess.run([
            str(installer_path),
            "/winpcap_mode=yes",
            "/loopback_support=yes",
            "/dot11_support=yes",
            "/silent"
        ], check=True)
        logger.info("Npcap installation completed successfully!")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error installing Npcap: {e}")
        sys.exit(1)

def configure_tensorflow():
    """Configure TensorFlow environment variables"""
    logger.info("Configuring TensorFlow environment...")
    
    # Suppress TensorFlow warnings
    os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    
    # Create or update .env file
    env_path = Path(__file__).parent.parent / ".env"
    with open(env_path, 'w') as f:
        f.write("TF_ENABLE_ONEDNN_OPTS=0\n")
        f.write("TF_CPP_MIN_LOG_LEVEL=2\n")
    
    logger.info("TensorFlow environment configured!")

def main():
    """Main setup function"""
    logger.info("Starting environment setup...")
    
    # Download and install Npcap
    try:
        installer_path = download_npcap()
        install_npcap(installer_path)
    except Exception as e:
        logger.error(f"Error setting up Npcap: {e}")
        sys.exit(1)
    
    # Configure TensorFlow
    configure_tensorflow()
    
    logger.info("Environment setup completed successfully!")
    logger.info("\nYou may need to restart your system for all changes to take effect.")

if __name__ == "__main__":
    main()
