"""
baseline.py — Rolling Baseline Learning
Maintains moving averages of normal network behavior.
"""

import time
import threading
from collections import deque
import backend.analysis.logger as logger
from backend.models.models import db, BaselineStat

class BaselineLearner:
    """
    Learns and maintains baseline statistics for network traffic.
    """
    
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.lock = threading.Lock()
        
        # Rolling windows for metrics
        self.packet_rates = deque(maxlen=window_size)
        self.byte_rates = deque(maxlen=window_size)
        self.unique_ips = deque(maxlen=window_size)
        self.unique_ports = deque(maxlen=window_size)
        
        # Current baseline values
        self.baseline = {
            'packet_rate': 100,
            'byte_rate': 1000,
            'unique_ips': 5,
            'unique_ports': 10
        }
        
        self.last_update = time.time()
    
    def update(self, traffic_data):
        """
        Update baseline with new traffic window data.
        
        traffic_data: dict with packet_rate, byte_rate, etc.
        """
        with self.lock:
            packet_rate = traffic_data.get('packet_rate', 0)
            byte_rate = traffic_data.get('byte_rate', 0)
            unique_ips = traffic_data.get('unique_ips', 0)
            unique_ports = traffic_data.get('unique_ports', 0)
            
            self.packet_rates.append(packet_rate)
            self.byte_rates.append(byte_rate)
            self.unique_ips.append(unique_ips)
            self.unique_ports.append(unique_ports)
            
            # Recalculate baselines
            if len(self.packet_rates) > 10:  # Need some data
                self.baseline['packet_rate'] = sum(self.packet_rates) / len(self.packet_rates)
                self.baseline['byte_rate'] = sum(self.byte_rates) / len(self.byte_rates)
                self.baseline['unique_ips'] = sum(self.unique_ips) / len(self.unique_ips)
                self.baseline['unique_ports'] = sum(self.unique_ports) / len(self.unique_ports)
                
                self.last_update = time.time()
                
                # Save to database
                self._save_baseline_to_db()
    
    def _save_baseline_to_db(self):
        """Save current baseline stats to database."""
        try:
            for metric, value in self.baseline.items():
                stat = BaselineStat(
                    metric_name=metric,
                    value=value,
                    window_size=self.window_size
                )
                db.session.add(stat)
            db.session.commit()
        except Exception as e:
            logger.log_system(f"Failed to save baseline to DB: {e}")
    
    def get_baseline(self):
        """Return current baseline statistics."""
        with self.lock:
            return self.baseline.copy()
    
    def is_normal_traffic(self, traffic_data):
        """
        Check if traffic data is within normal bounds.
        
        Returns: (is_normal, deviations)
        """
        baseline = self.get_baseline()
        deviations = {}
        
        packet_rate = traffic_data.get('packet_rate', 0)
        if packet_rate > baseline['packet_rate'] * 3:
            deviations['packet_rate'] = packet_rate / baseline['packet_rate']
        
        byte_rate = traffic_data.get('byte_rate', 0)
        if byte_rate > baseline['byte_rate'] * 3:
            deviations['byte_rate'] = byte_rate / baseline['byte_rate']
        
        unique_ips = traffic_data.get('unique_ips', 0)
        if unique_ips > baseline['unique_ips'] * 2:
            deviations['unique_ips'] = unique_ips / baseline['unique_ips']
        
        unique_ports = traffic_data.get('unique_ports', 0)
        if unique_ports > baseline['unique_ports'] * 2:
            deviations['unique_ports'] = unique_ports / baseline['unique_ports']
        
        is_normal = len(deviations) == 0
        return is_normal, deviations

# Global instance
baseline_learner = BaselineLearner()