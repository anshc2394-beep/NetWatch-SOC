"""
classify.py — Attack Classification Model
Trains and uses a classifier to categorize detected anomalies.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
import backend.analysis.logger as logger

class AttackClassifier:
    """
    ML classifier for attack types.
    
    Input: feature vector
    Output: attack type with confidence
    """
    
    ATTACK_TYPES = ["Normal", "DDoS", "Port Scan", "Spoofing", "Data Exfiltration"]
    
    def __init__(self, model_path="backend/models/classifier.pkl"):
        self.model_path = model_path
        self.model = None
        self.is_trained = False
        
        # Load existing model if available
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                self.is_trained = True
                logger.log_system("Loaded existing attack classifier model")
            except Exception as e:
                logger.log_system(f"Failed to load classifier: {e}")
    
    def train(self, X, y):
        """
        Train the classifier.
        
        X: feature matrix
        y: labels (0=Normal, 1=DDoS, etc.)
        """
        if len(X) == 0:
            logger.log_system("No training data provided")
            return
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        report = classification_report(y_test, y_pred, target_names=self.ATTACK_TYPES)
        logger.log_system(f"Classifier trained:\n{report}")
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        self.is_trained = True
    
    def predict(self, features):
        """
        Predict attack type for given features.
        
        features: numpy array or list
        Returns: (attack_type, confidence)
        """
        if not self.is_trained or self.model is None:
            return "Unknown", 0.0
        
        features = np.array(features).reshape(1, -1)
        probabilities = self.model.predict_proba(features)[0]
        predicted_class = np.argmax(probabilities)
        confidence = probabilities[predicted_class]
        
        attack_type = self.ATTACK_TYPES[predicted_class] if predicted_class < len(self.ATTACK_TYPES) else "Unknown"
        
        return attack_type, float(confidence)
    
    def generate_synthetic_data(self, n_samples=1000):
        """
        Generate synthetic training data for demonstration.
        
        Returns: (X, y) where y is attack type index
        """
        np.random.seed(42)
        X = []
        y = []
        
        for _ in range(n_samples):
            attack_type = np.random.choice(len(self.ATTACK_TYPES), p=[0.7, 0.1, 0.1, 0.05, 0.05])
            
            # Generate features based on attack type
            if attack_type == 0:  # Normal
                features = [
                    np.random.normal(100, 20),    # packet_rate
                    np.random.normal(1000, 200),  # byte_rate
                    np.random.normal(10, 3),      # unique_ips
                    np.random.normal(5, 2),       # unique_ports
                    np.random.normal(0.5, 0.1),   # entropy
                ]
            elif attack_type == 1:  # DDoS
                features = [
                    np.random.normal(5000, 1000), # high packet_rate
                    np.random.normal(50000, 10000), # high byte_rate
                    np.random.normal(1, 0.5),     # few unique_ips
                    np.random.normal(2, 1),       # few ports
                    np.random.normal(0.1, 0.05),  # low entropy
                ]
            elif attack_type == 2:  # Port Scan
                features = [
                    np.random.normal(200, 50),    # moderate packet_rate
                    np.random.normal(2000, 500),  # moderate byte_rate
                    np.random.normal(1, 0.5),     # single ip
                    np.random.normal(50, 10),     # many ports
                    np.random.normal(0.8, 0.1),   # high entropy
                ]
            elif attack_type == 3:  # Spoofing
                features = [
                    np.random.normal(150, 30),    # normal packet_rate
                    np.random.normal(1500, 300),  # normal byte_rate
                    np.random.normal(20, 5),      # many ips
                    np.random.normal(10, 3),      # normal ports
                    np.random.normal(0.9, 0.05),  # high entropy
                ]
            else:  # Data Exfiltration
                features = [
                    np.random.normal(50, 10),     # low packet_rate
                    np.random.normal(10000, 2000), # high byte_rate
                    np.random.normal(2, 1),       # few ips
                    np.random.normal(3, 1),       # few ports
                    np.random.normal(0.3, 0.1),   # moderate entropy
                ]
            
            X.append(features)
            y.append(attack_type)
        
        return np.array(X), np.array(y)

# Global instance
attack_classifier = AttackClassifier()

# Train with synthetic data if no model exists
if not attack_classifier.is_trained:
    logger.log_system("Training attack classifier with synthetic data")
    X_synth, y_synth = attack_classifier.generate_synthetic_data()
    attack_classifier.train(X_synth, y_synth)