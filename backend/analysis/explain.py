"""
explain.py — Explainable AI for Anomaly Detection
Generates human-readable explanations for detected anomalies.
"""

import backend.analysis.logger as logger
from backend.analysis import baseline

class AnomalyExplainer:
    """
    Provides explanations for anomalies based on feature importance and heuristics.
    """
    
    def __init__(self):
        pass  # Use dynamic baseline from baseline_learner
    
    def explain_anomaly(self, anomaly_data):
        """
        Generate explanation for an anomaly.
        
        anomaly_data: dict with features and anomaly info
        Returns: explanation dict
        """
        baseline_stats = baseline.baseline_learner.get_baseline()
        reasons = []
        top_features = []
        
        # Extract features
        pkt_count = anomaly_data.get('pkt_count', 0)
        byte_count = anomaly_data.get('byte_count', 0)
        duration = anomaly_data.get('duration_s', 1)
        avg_pkt_size = anomaly_data.get('avg_pkt_size', 0)
        avg_iat = anomaly_data.get('avg_iat_ms', 0)
        
        # Calculate rates
        packet_rate = pkt_count / duration if duration > 0 else 0
        byte_rate = byte_count / duration if duration > 0 else 0
        
        # Compare to baseline
        if packet_rate > baseline_stats['packet_rate'] * 2:
            ratio = packet_rate / baseline_stats['packet_rate']
            reasons.append(f"Packet rate is {ratio:.1f}x baseline")
            top_features.append({'feature': 'packet_rate', 'impact': min(ratio / 10, 1.0)})
        
        if byte_rate > baseline_stats['byte_rate'] * 2:
            ratio = byte_rate / baseline_stats['byte_rate']
            reasons.append(f"Byte rate is {ratio:.1f}x baseline")
            top_features.append({'feature': 'byte_rate', 'impact': min(ratio / 10, 1.0)})
        
        if avg_pkt_size > 1500:  # Large packets
            reasons.append("Unusually large packet sizes")
            top_features.append({'feature': 'avg_pkt_size', 'impact': 0.6})
        
        if avg_iat < 1:  # Very fast packets
            reasons.append("Very high packet frequency")
            top_features.append({'feature': 'avg_iat_ms', 'impact': 0.8})
        
        # Sort top features by impact
        top_features.sort(key=lambda x: x['impact'], reverse=True)
        top_features = top_features[:3]  # Top 3
        
        if not reasons:
            reasons.append("Anomaly detected by ML model")
            top_features.append({'feature': 'ml_score', 'impact': 0.5})
        
        return {
            'reason': reasons,
            'top_features': top_features
        }

# Global instance
explainer = AnomalyExplainer()