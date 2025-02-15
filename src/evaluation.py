import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve, auc, precision_recall_curve, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, Any, Tuple
import logging

class ModelEvaluator:
    def __init__(self, config: Dict[str, Any]):
        self.logger = logging.getLogger(__name__)
        self.config = config
        
    def calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> Dict[str, float]:
        """Calculate comprehensive performance metrics"""
        metrics = {}
        
        # Basic metrics
        metrics['accuracy'] = np.mean(y_true == y_pred)
        metrics['precision'] = np.sum((y_true == 1) & (y_pred == 1)) / np.sum(y_pred == 1)
        metrics['recall'] = np.sum((y_true == 1) & (y_pred == 1)) / np.sum(y_true == 1)
        metrics['f1'] = 2 * (metrics['precision'] * metrics['recall']) / (metrics['precision'] + metrics['recall'])
        
        # ROC and AUC
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        metrics['auc'] = auc(fpr, tpr)
        
        return metrics
    
    def plot_roc_curve(self, y_true: np.ndarray, y_prob: np.ndarray, save_path: str = None):
        """Plot ROC curve"""
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(10, 8))
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        
        if save_path:
            plt.savefig(save_path)
        plt.close()
    
    def plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray, save_path: str = None):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.title('Confusion Matrix')
        
        if save_path:
            plt.savefig(save_path)
        plt.close()
    
    def generate_evaluation_report(self, metrics: Dict[str, float], output_path: str):
        """Generate comprehensive evaluation report"""
        report = f"""
# Model Evaluation Report

## Performance Metrics
- Accuracy: {metrics['accuracy']:.3f}
- Precision: {metrics['precision']:.3f}
- Recall: {metrics['recall']:.3f}
- F1 Score: {metrics['f1']:.3f}
- AUC-ROC: {metrics['auc']:.3f}

## Analysis
The model shows {'strong' if metrics['f1'] > 0.9 else 'moderate' if metrics['f1'] > 0.7 else 'weak'} 
performance with an F1 score of {metrics['f1']:.3f}. 
The AUC-ROC score of {metrics['auc']:.3f} indicates {'excellent' if metrics['auc'] > 0.9 
else 'good' if metrics['auc'] > 0.8 else 'fair' if metrics['auc'] > 0.7 else 'poor'} 
discriminative ability.
"""
        
        with open(output_path, 'w') as f:
            f.write(report)
            
    def evaluate_model_performance(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                 y_prob: np.ndarray, output_dir: str):
        """Comprehensive model evaluation"""
        # Calculate metrics
        metrics = self.calculate_metrics(y_true, y_pred, y_prob)
        
        # Generate visualizations
        self.plot_roc_curve(y_true, y_prob, f"{output_dir}/roc_curve.png")
        self.plot_confusion_matrix(y_true, y_pred, f"{output_dir}/confusion_matrix.png")
        
        # Generate report
        self.generate_evaluation_report(metrics, f"{output_dir}/evaluation_report.md")
        
        return metrics
