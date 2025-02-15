import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import pandas as pd
import numpy as np
from typing import Dict, Any
import logging
from datetime import datetime
import threading
from queue import Queue

class NetworkDataCollector:
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the NetworkDataCollector.
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.packet_queue = Queue()
        self.stop_capture = threading.Event()
        
        # Initialize statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': {},
            'start_time': None,
            'end_time': None
        }

    def start_capture(self, interface: str, duration: int = None) -> pd.DataFrame:
        """
        Start capturing network packets.
        
        Args:
            interface: Network interface to capture from
            duration: Capture duration in seconds
            
        Returns:
            DataFrame containing network data
        """
        try:
            self.logger.info(f"Starting packet capture on interface {interface}")
            self.stop_capture.clear()
            self.stats['start_time'] = datetime.now()
            
            # Start packet processing thread
            processing_thread = threading.Thread(target=self._process_packets)
            processing_thread.start()
            
            # Start packet capture
            scapy.sniff(
                iface=interface,
                prn=self._packet_callback,
                stop_filter=lambda _: self.stop_capture.is_set(),
                timeout=duration
            )
            
            self.stats['end_time'] = datetime.now()
            self.packet_queue.put(None)  # Signal processing thread to stop
            processing_thread.join()
            
            return self._create_dataframe()
            
        except Exception as e:
            self.logger.error(f"Error during packet capture: {str(e)}")
            raise

    def _packet_callback(self, packet: scapy.Packet) -> None:
        """Process captured packet and add to queue."""
        try:
            if IP in packet:
                self.packet_queue.put(packet)
                self.stats['total_packets'] += 1
                
        except Exception as e:
            self.logger.error(f"Error in packet callback: {str(e)}")

    def _process_packets(self) -> None:
        """Process packets from queue and extract features."""
        packets_data = []
        
        while True:
            packet = self.packet_queue.get()
            if packet is None:
                break
                
            try:
                # Extract basic packet info
                ip_packet = packet[IP]
                protocol = self._get_protocol(packet)
                length = len(packet)
                
                # Update statistics
                self.stats['total_bytes'] += length
                self.stats['protocols'][protocol] = self.stats['protocols'].get(protocol, 0) + 1
                
                # Extract packet features
                packet_data = {
                    'timestamp': datetime.now(),
                    'src_ip': ip_packet.src,
                    'dst_ip': ip_packet.dst,
                    'protocol': protocol,
                    'length': length,
                    'src_port': self._get_port(packet, 'src'),
                    'dst_port': self._get_port(packet, 'dst')
                }
                
                packets_data.append(packet_data)
                
            except Exception as e:
                self.logger.error(f"Error processing packet: {str(e)}")
                
            finally:
                self.packet_queue.task_done()
                
        # Store processed packets
        self.processed_packets = packets_data

    def _get_protocol(self, packet: scapy.Packet) -> str:
        """Get packet protocol."""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        return 'OTHER'

    def _get_port(self, packet: scapy.Packet, direction: str) -> int:
        """Get source or destination port."""
        try:
            if TCP in packet:
                return packet[TCP].sport if direction == 'src' else packet[TCP].dport
            elif UDP in packet:
                return packet[UDP].sport if direction == 'src' else packet[UDP].dport
            return 0
        except:
            return 0

    def _create_dataframe(self) -> pd.DataFrame:
        """Convert processed packets to DataFrame."""
        try:
            if not hasattr(self, 'processed_packets') or not self.processed_packets:
                return pd.DataFrame()
            
            df = pd.DataFrame(self.processed_packets)
            
            # Add some basic derived features
            df['packets_per_second'] = len(df) / (self.stats['end_time'] - self.stats['start_time']).total_seconds()
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error creating DataFrame: {str(e)}")
            raise

    def generate_demo_data(self, n_samples: int = 100) -> pd.DataFrame:
        """
        Generate synthetic network traffic data for demonstration.
        
        Args:
            n_samples: Number of samples to generate
            
        Returns:
            DataFrame containing synthetic network data
        """
        try:
            self.logger.info(f"Generating {n_samples} synthetic traffic records")
            
            # Generate timestamps
            timestamps = pd.date_range(
                start=datetime.now(),
                periods=n_samples,
                freq='1s'
            )
            
            # Generate data
            data = {
                'timestamp': timestamps,
                'src_ip': [f"192.168.1.{np.random.randint(1, 255)}" for _ in range(n_samples)],
                'dst_ip': [f"10.0.0.{np.random.randint(1, 255)}" for _ in range(n_samples)],
                'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
                'length': np.random.normal(500, 200, n_samples).astype(int),
                'src_port': np.random.randint(1024, 65535, n_samples),
                'dst_port': np.random.randint(1024, 65535, n_samples)
            }
            
            df = pd.DataFrame(data)
            
            # Add some anomalous patterns
            if n_samples > 10:
                # Add some DDoS-like traffic
                df.loc[:n_samples//10, 'length'] *= 5
                
                # Add some port scan-like traffic
                df.loc[n_samples//10:n_samples//5, 'dst_port'] = np.random.choice(
                    range(1, 1000),
                    n_samples//10
                )
            
            # Calculate packets per second
            df['packets_per_second'] = 1  # Since we generate 1 packet per second
            
            return df
            
        except Exception as e:
            self.logger.error(f"Error generating demo data: {str(e)}")
            raise

if __name__ == "__main__":
    # Example usage
    collector = NetworkDataCollector({})
    
    # Generate demo data
    demo_data = collector.generate_demo_data(100)
    print("Demo Data Sample:")
    print(demo_data.head())
    
    # Collect real network traffic
    print("\nCollecting real network traffic...")
    real_data = collector.start_capture(duration=10)
    print("\nReal Traffic Sample:")
    print(real_data.head())
