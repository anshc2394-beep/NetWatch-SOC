"""
rules.py — Rule-Based Detection Engine
Implements signature-based detection for common attacks.
"""

import time
from collections import defaultdict
import backend.analysis.logger as logger

class RuleDetector:
    """
    Rule-based detector for network attacks.
    
    Rules:
    - Port Scan: Same IP hitting many unique ports in short time
    - DDoS: High packet rate from one/many IPs
    - ARP Spoof: Duplicate IP with different MAC
    """
    
    def __init__(self):
        self.port_scan_threshold = 10  # unique ports
        self.port_scan_window = 60     # seconds
        self.ddos_threshold = 1000     # packets per minute
        self.arp_cache = {}            # IP -> MAC mapping
        
        # Tracking structures
        self.ip_ports = defaultdict(set)  # IP -> set of ports seen
        self.ip_timestamps = defaultdict(list)  # IP -> list of timestamps
        self.ip_packet_counts = defaultdict(int)  # IP -> packet count in window
        
        self.alerts = []
    
    def process_packet(self, packet_data):
        """
        Process a packet for rule-based detection.
        
        packet_data: dict with keys like src_ip, dst_ip, src_port, dst_port, proto, etc.
        """
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        src_port = packet_data.get('src_port', 0)
        dst_port = packet_data.get('dst_port', 0)
        proto = packet_data.get('proto')
        timestamp = packet_data.get('timestamp', time.time())
        
        # Clean old data
        self._cleanup_old_data(timestamp)
        
        # Check rules
        alerts = []
        
        # Port scan detection
        if self._check_port_scan(src_ip, dst_port, timestamp):
            alerts.append({
                'type': 'Port Scan',
                'severity': 'high',
                'src_ip': src_ip,
                'description': f'Port scan detected from {src_ip}',
                'timestamp': timestamp
            })
        
        # DDoS detection (simplified)
        if self._check_ddos(src_ip, timestamp):
            alerts.append({
                'type': 'DDoS',
                'severity': 'critical',
                'src_ip': src_ip,
                'description': f'High packet rate from {src_ip}',
                'timestamp': timestamp
            })
        
        # ARP spoof detection (placeholder - would need ARP packets)
        # if self._check_arp_spoof(src_ip, mac):
        #     alerts.append(...)
        
        self.alerts.extend(alerts)
        return alerts
    
    def _check_port_scan(self, src_ip, dst_port, timestamp):
        """Check if src_ip is scanning ports."""
        self.ip_ports[src_ip].add(dst_port)
        self.ip_timestamps[src_ip].append(timestamp)
        
        # Check if exceeded threshold in time window
        recent_timestamps = [t for t in self.ip_timestamps[src_ip] 
                           if timestamp - t <= self.port_scan_window]
        self.ip_timestamps[src_ip] = recent_timestamps
        
        if len(self.ip_ports[src_ip]) >= self.port_scan_threshold and len(recent_timestamps) >= self.port_scan_threshold:
            logger.log_system(f"Port scan alert: {src_ip} scanned {len(self.ip_ports[src_ip])} ports")
            return True
        return False
    
    def _check_ddos(self, src_ip, timestamp):
        """Check for high packet rate from src_ip."""
        self.ip_packet_counts[src_ip] += 1
        
        # Simple rate check (packets per minute)
        # In real implementation, use sliding window
        rate = self.ip_packet_counts[src_ip] / 60  # assuming 1 min window
        if rate > self.ddos_threshold:
            logger.log_system(f"DDoS alert: {src_ip} rate {rate} pkt/min")
            return True
        return False
    
    def _check_arp_spoof(self, ip, mac):
        """Check for ARP spoofing."""
        if ip in self.arp_cache:
            if self.arp_cache[ip] != mac:
                logger.log_system(f"ARP spoof alert: IP {ip} has multiple MACs")
                return True
        else:
            self.arp_cache[ip] = mac
        return False
    
    def _cleanup_old_data(self, current_time):
        """Remove old tracking data."""
        cutoff = current_time - self.port_scan_window
        for ip in list(self.ip_timestamps.keys()):
            self.ip_timestamps[ip] = [t for t in self.ip_timestamps[ip] if t > cutoff]
            if not self.ip_timestamps[ip]:
                del self.ip_timestamps[ip]
                self.ip_ports[ip].clear()
    
    def get_alerts(self):
        """Return current alerts."""
        return self.alerts
    
    def clear_alerts(self):
        """Clear old alerts."""
        self.alerts = []

# Global instance
rule_detector = RuleDetector()