import asyncio
import pandas as pd
import numpy as np
from typing import Dict, Any, List, Callable
import logging
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import threading

class RealtimeProcessor:
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.processing_queue = asyncio.Queue()
        self.result_queue = asyncio.Queue()
        self.buffer_size = config.get('buffer_size', 1000)
        self.packet_buffer = deque(maxlen=self.buffer_size)
        self.thread_pool = ThreadPoolExecutor(max_workers=config.get('max_workers', 4))
        self.running = False
        self.callbacks = []
        
    async def start_processing(self):
        """
        Start the real-time processing pipeline
        """
        self.running = True
        await asyncio.gather(
            self.process_packets(),
            self.handle_results()
        )
        
    def stop_processing(self):
        """
        Stop the processing pipeline
        """
        self.running = False
        self.thread_pool.shutdown(wait=True)
        
    async def process_packets(self):
        """
        Process packets from the queue
        """
        while self.running:
            try:
                batch = []
                while len(batch) < self.buffer_size:
                    try:
                        packet = await asyncio.wait_for(self.processing_queue.get(), timeout=0.1)
                        batch.append(packet)
                    except asyncio.TimeoutError:
                        break
                    
                if batch:
                    # Process batch in thread pool
                    await self.process_batch(batch)
                    
            except Exception as e:
                self.logger.error(f"Error processing packets: {str(e)}")
                
    async def process_batch(self, batch: List[Dict[str, Any]]):
        """
        Process a batch of packets
        """
        try:
            # Convert batch to DataFrame
            df = pd.DataFrame(batch)
            
            # Basic feature extraction
            features = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool,
                self.extract_features,
                df
            )
            
            # Anomaly detection
            anomalies = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool,
                self.detect_anomalies,
                features
            )
            
            # Put results in queue
            await self.result_queue.put({
                'timestamp': datetime.now(),
                'features': features,
                'anomalies': anomalies
            })
            
        except Exception as e:
            self.logger.error(f"Error processing batch: {str(e)}")
            
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract features from packet batch
        """
        features = pd.DataFrame()
        
        # Basic statistical features
        features['bytes_mean'] = df['bytes'].mean()
        features['bytes_std'] = df['bytes'].std()
        features['packet_count'] = len(df)
        
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts(normalize=True)
        for protocol in protocol_counts.index:
            features[f'protocol_{protocol}'] = protocol_counts[protocol]
            
        # Time-based features
        features['time_span'] = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        features['packets_per_second'] = features['packet_count'] / features['time_span']
        
        return features
        
    def detect_anomalies(self, features: pd.DataFrame) -> Dict[str, Any]:
        """
        Detect anomalies in the feature set
        """
        anomalies = {
            'high_traffic': features['packets_per_second'].iloc[0] > self.config.get('traffic_threshold', 1000),
            'unusual_protocols': features.filter(like='protocol_').max().iloc[0] > 0.8,
            'timestamp': datetime.now()
        }
        return anomalies
        
    async def handle_results(self):
        """
        Handle processing results
        """
        while self.running:
            try:
                result = await self.result_queue.get()
                
                # Call registered callbacks with results
                for callback in self.callbacks:
                    try:
                        await callback(result)
                    except Exception as e:
                        self.logger.error(f"Error in result callback: {str(e)}")
                        
            except Exception as e:
                self.logger.error(f"Error handling results: {str(e)}")
                
    def register_callback(self, callback: Callable):
        """
        Register a callback for processing results
        """
        self.callbacks.append(callback)
        
    async def add_packet(self, packet: Dict[str, Any]):
        """
        Add a packet to the processing queue
        """
        await self.processing_queue.put(packet)
        
    def get_stats(self) -> Dict[str, Any]:
        """
        Get current processing statistics
        """
        return {
            'queue_size': self.processing_queue.qsize(),
            'processed_packets': len(self.packet_buffer),
            'is_running': self.running,
            'timestamp': datetime.now()
        }
