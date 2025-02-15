import os
import sys
import time
from datetime import datetime
import pandas as pd
import numpy as np
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich import print as rprint
import warnings
import logging

# Suppress tensorflow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_collection import DataCollector
from src.preprocessing import DataPreprocessor
from src.threat_detection import ThreatDetector
from src.alerting import AlertManager

# Suppress warnings
warnings.filterwarnings('ignore')

class ThreatDetectionDemo:
    def __init__(self):
        """Initialize the demo system."""
        try:
            self.console = Console()
            self.setup_logging()
            
            self.console.print("[yellow]Initializing components...[/yellow]")
            
            # Initialize components with proper error handling
            try:
                self.collector = DataCollector()
                self.console.print("[green]✓[/green] Data collector initialized")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Failed to initialize data collector: {str(e)}")
                raise
                
            try:
                self.preprocessor = DataPreprocessor()
                self.console.print("[green]✓[/green] Data preprocessor initialized")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Failed to initialize preprocessor: {str(e)}")
                raise
                
            try:
                self.detector = ThreatDetector()
                self.console.print("[green]✓[/green] Threat detector initialized")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Failed to initialize threat detector: {str(e)}")
                raise
                
            try:
                self.alert_manager = AlertManager()
                self.console.print("[green]✓[/green] Alert manager initialized")
            except Exception as e:
                self.console.print(f"[red]✗[/red] Failed to initialize alert manager: {str(e)}")
                raise
            
            self.console.print("[yellow]Training models with demo data...[/yellow]")
            self.initialize_demo_data()
            self.console.print("[green]✓[/green] Models trained successfully")
            
        except Exception as e:
            self.console.print(f"[red]Error during initialization:[/red] {str(e)}")
            raise
    
    def setup_logging(self):
        """Set up logging configuration."""
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'demo.log')),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
    def initialize_demo_data(self):
        """Initialize and train models with demo data."""
        try:
            # Create synthetic training data
            n_samples = 1000
            np.random.seed(42)
            
            # Normal traffic patterns
            normal_data = pd.DataFrame({
                'length': np.random.normal(500, 100, n_samples),
                'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_samples),
                'src_port': np.random.randint(1024, 65535, n_samples),
                'dst_port': np.random.randint(1024, 65535, n_samples),
                'timestamp': pd.date_range(start='2025-01-01', periods=n_samples, freq='1min')
            })
            
            # Add some known attack patterns
            attack_data = pd.DataFrame({
                'length': np.random.normal(2000, 200, n_samples // 10),
                'protocol': np.random.choice(['TCP'], n_samples // 10),
                'src_port': np.random.randint(1024, 65535, n_samples // 10),
                'dst_port': np.random.choice([80, 443, 8080], n_samples // 10),
                'timestamp': pd.date_range(start='2025-01-01', periods=n_samples // 10, freq='1min')
            })
            
            # Combine and preprocess data
            training_data = pd.concat([normal_data, attack_data])
            processed_data = self.preprocessor.preprocess_network_traffic(training_data)
            
            # Create labels (0 for normal, 1 for attack)
            labels = np.zeros(len(training_data))
            labels[len(normal_data):] = 1
            
            # Train models with progress indication
            self.console.print("[yellow]Training supervised model...[/yellow]")
            self.detector.train_supervised_model(processed_data, labels)
            self.console.print("[green]✓[/green] Supervised model trained")
            
            self.console.print("[yellow]Training unsupervised model...[/yellow]")
            self.detector.train_unsupervised_model(processed_data)
            self.console.print("[green]✓[/green] Unsupervised model trained")
            
            self.console.print("[yellow]Training behavioral model...[/yellow]")
            self.detector.train_behavioral_model(processed_data)
            self.console.print("[green]✓[/green] Behavioral model trained")
            
        except Exception as e:
            self.console.print(f"[red]Error during model training:[/red] {str(e)}")
            raise
    
    def create_status_table(self, stats):
        """Create a rich table with current statistics."""
        table = Table(title="Network Traffic Analysis")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")
        
        for key, value in stats.items():
            if isinstance(value, dict):
                value = ", ".join(f"{k}: {v}" for k, v in value.items())
            table.add_row(str(key), str(value))
            
        return table
    
    def run_demo(self, duration=300):
        """Run the demo system for specified duration."""
        try:
            self.console.print("\n[bold green]Starting Network Threat Detection Demo[/bold green]")
            self.console.print(f"[yellow]Duration: {duration} seconds[/yellow]\n")
            
            start_time = time.time()
            packet_count = 0
            alerts_generated = 0
            threats_detected = 0
            
            with Live(Panel("Initializing..."), refresh_per_second=4) as live:
                while time.time() - start_time < duration:
                    try:
                        # Generate demo network traffic instead of capturing
                        network_data = self.collector.generate_demo_data(100)  # Generate 100 packets per iteration
                        
                        if not network_data.empty:
                            packet_count += len(network_data)
                            
                            # Preprocess data
                            processed_data = self.preprocessor.preprocess_network_traffic(network_data)
                            
                            # Detect threats
                            results = self.detector.detect_threats(processed_data)
                            
                            # Update statistics
                            new_threats = len(results.get('threats_detected', []))
                            threats_detected += new_threats
                            
                            # Generate alerts if threats detected
                            if new_threats > 0:
                                alert = self.alert_manager.generate_alert(results)
                                alerts_generated += 1
                                
                                # Display alert in a panel
                                alert_panel = Panel(
                                    f"[red]ALERT![/red]\n" +
                                    f"Severity: {alert['severity']}\n" +
                                    f"Type: {alert['type']}\n" +
                                    f"Recommended Actions:\n" +
                                    "\n".join(f"- {action}" for action in alert['recommended_actions']),
                                    title="Threat Alert",
                                    border_style="red"
                                )
                                live.update(alert_panel)
                                time.sleep(2)  # Show alert for 2 seconds
                            
                            # Update statistics display
                            stats = {
                                "Duration": f"{int(time.time() - start_time)}s",
                                "Packets Analyzed": packet_count,
                                "Threats Detected": threats_detected,
                                "Alerts Generated": alerts_generated,
                                "Current Protocol Distribution": network_data['protocol'].value_counts().to_dict(),
                                "Average Packet Length": f"{network_data['length'].mean():.2f} bytes"
                            }
                            
                            live.update(self.create_status_table(stats))
                        
                        time.sleep(1)  # Short sleep to prevent CPU overuse
                        
                    except KeyboardInterrupt:
                        self.console.print("\n[yellow]Demo stopped by user[/yellow]")
                        break
                    except Exception as e:
                        error_panel = Panel(
                            f"[red]Error:[/red] {str(e)}",
                            title="Error",
                            border_style="red"
                        )
                        live.update(error_panel)
                        time.sleep(2)
            
            # Final summary
            self.console.print("\n[bold green]Demo Complete![/bold green]")
            self.console.print(f"Total Duration: {duration} seconds")
            self.console.print(f"Packets Analyzed: {packet_count}")
            self.console.print(f"Threats Detected: {threats_detected}")
            self.console.print(f"Alerts Generated: {alerts_generated}")
            
        except Exception as e:
            self.console.print(f"\n[red]Fatal error during demo:[/red] {str(e)}")
            raise

if __name__ == "__main__":
    try:
        demo = ThreatDetectionDemo()
        demo.run_demo(duration=300)  # Run for 5 minutes
    except KeyboardInterrupt:
        print("\nDemo stopped by user")
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        sys.exit(1)
