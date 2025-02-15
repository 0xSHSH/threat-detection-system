import os
import sys
from pathlib import Path
import logging
from scapy.all import sniff
import time

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def process_packet(packet):
    """Process captured packet and print summary"""
    logger.info(packet.summary())
    return packet

def test_packet_capture():
    """Test packet capture functionality"""
    logger.info("Starting packet capture test...")
    logger.info("Will capture 5 packets. Please ensure there is some network activity.")
    
    try:
        # Attempt to capture 5 packets
        packets = sniff(prn=process_packet, count=5, timeout=10)
        
        if packets:
            logger.info(f"\nSuccessfully captured {len(packets)} packets!")
            logger.info("Packet capture is working correctly.")
        else:
            logger.warning("No packets captured. This might indicate an issue with the capture setup.")
            
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")
        logger.error("Please ensure Npcap is installed and you have the necessary permissions.")
        sys.exit(1)

if __name__ == "__main__":
    # Load environment variables
    if os.path.exists(project_root / ".env"):
        from dotenv import load_dotenv
        load_dotenv(project_root / ".env")
    
    test_packet_capture()
