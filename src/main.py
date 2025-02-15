import logging
from datetime import datetime
import time
import yaml
from data_collection import DataCollector
from preprocessing import DataPreprocessor
from threat_detection import ThreatDetector
from alerting import AlertManager

def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f"../logs/main_{datetime.now().strftime('%Y%m%d')}.log"),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def load_config(config_path: str = "../config/config.yml"):
    """Load configuration from YAML file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def main():
    """Main function to run the threat detection system."""
    logger = setup_logging()
    logger.info("Starting Threat Detection System")
    
    try:
        # Load configuration
        config = load_config()
        
        # Initialize components
        collector = DataCollector()
        preprocessor = DataPreprocessor()
        detector = ThreatDetector()
        alert_manager = AlertManager()
        
        # Main processing loop
        while True:
            try:
                # 1. Collect data
                logger.info("Starting data collection")
                network_data = collector.collect_network_traffic(
                    interface=config['network']['interface'],
                    duration=config['network']['capture_duration']
                )
                system_logs = collector.collect_system_logs(config['logging']['file_path'])
                user_activity = collector.collect_user_activity()
                
                # Save raw data
                collector.save_data(network_data, "network_traffic")
                collector.save_data(system_logs, "system_logs")
                collector.save_data(user_activity, "user_activity")
                
                # 2. Preprocess data
                logger.info("Preprocessing data")
                processed_network = preprocessor.preprocess_network_traffic(network_data)
                processed_system = preprocessor.preprocess_system_logs(system_logs)
                processed_user = preprocessor.preprocess_user_activity(user_activity)
                
                # 3. Detect threats
                logger.info("Detecting threats")
                network_threats = detector.detect_threats(processed_network)
                system_threats = detector.detect_threats(processed_system)
                user_threats = detector.detect_threats(processed_user)
                
                # 4. Generate and send alerts
                if any([network_threats, system_threats, user_threats]):
                    logger.info("Generating alerts")
                    for threats in [network_threats, system_threats, user_threats]:
                        if threats:
                            alert = alert_manager.generate_alert(threats)
                            alert_manager.send_email_alert(alert)
                            alert_manager.send_webhook_alert(alert)
                
                # Wait for next iteration
                logger.info("Waiting for next iteration")
                time.sleep(config['network']['capture_duration'])
                
            except Exception as e:
                logger.error(f"Error in processing loop: {str(e)}")
                time.sleep(60)  # Wait a minute before retrying
                
    except Exception as e:
        logger.error(f"Fatal error in main function: {str(e)}")
        raise

if __name__ == "__main__":
    main()
