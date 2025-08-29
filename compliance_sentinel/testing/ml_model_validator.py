"""ML model validation framework with accuracy and bias testing."""

import logging
import numpy as np
import time
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, classification_report
)
from sklearn.model_selection import cross_val_score, StratifiedKFold
import matplotlib.pyplot as plt
import seaborn as sns


logger = logging.getLogger(__name__)


class ValidationMetric(Enum):
    """ML validation metrics."""
    ACCURACY = "accuracy"
    PRECISION = "precision"
    RECALL = "recall"
    F1_SCORE = "f1_score"
    ROC_AUC = "roc_auc"
    CONFUSION_MATRIX = "confusion_matrix"
    CROSS_VALIDATION = "cross_validation"


class BiasType(Enum):
    """Types of bias to detect."""
    DEMOGRAPHIC_PARITY = "demographic_parity"
    EQUALIZED_ODDS = "equalized_odds"
    CALIBRATION = "calibration"
    INDIVIDUAL_FAIRNESS = "individual_fairness"


@dataclass
class ValidationMetrics:
    """Container for validation metrics."""
    
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    roc_auc: Optional[float] = None
    
    # Cross-validation results
    cv_scores: List[float] = field(default_factory=list)
    cv_mean: float = 0.0
    cv_std: float = 0.0
    
    # Confusion matrix
    confusion_matrix: Optional[np.ndarray] = None
    
    # Per-class metrics
    per_class_precision: Dict[str, float] = field(default_factory=dict)
    per_class_recall: Dict[str, float] = field(default_factory=dict)
    per_class_f1: Dict[str, float] = field(default_factory=dict)
    
    # Bias metrics
    bias_metrics: Dict[str, float] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'roc_auc': self.roc_auc,
            'cv_mean': self.cv_mean,
            'cv_std': self.cv_std,
            'per_class_precision': self.per_class_precision,
            'per_class_recall': self.per_class_recall,
            'per_class_f1': self.per_class_f1,
            'bias_metrics': self.bias_metrics,
            'confusion_matrix': self.confusion_matrix.tolist() if self.confusion_matrix is not None else None
        }


@dataclass
class ModelValidationResult:
    """Result of ML model validation."""
    
    model_name: str
    model_version: str
    validation_type: str
    
    # Metrics
    metrics: ValidationMetrics = field(default_factory=ValidationMetrics)
    
    # Performance
    training_time: float = 0.0
    inference_time: float = 0.0
    model_size_mb: float = 0.0
    
    # Validation details
    dataset_size: int = 0
    test_size: int = 0
    validation_date: datetime = field(default_factory=datetime.now)
    
    # Issues found
    performance_issues: List[str] = field(default_factory=list)
    bias_issues: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'model_name': self.model_name,
            'model_version': self.model_version,
            'validation_type': self.validation_type,
            'metrics': self.metrics.to_dict(),
            'training_time': self.training_time,
            'inference_time': self.inference_time,
            'model_size_mb': self.model_size_mb,
            'dataset_size': self.dataset_size,
            'test_size': self.test_size,
            'validation_date': self.validation_date.isoformat(),
            'performance_issues': self.performance_issues,
            'bias_issues': self.bias_issues,
            'recommendations': self.recommendations
        }


class BiasDetector:
    """Detects bias in ML models."""
    
    def __init__(self):
        """Initialize bias detector."""
        self.logger = logging.getLogger(__name__)
    
    def detect_demographic_parity(self, 
                                 y_pred: np.ndarray,
                                 sensitive_attributes: np.ndarray,
                                 threshold: float = 0.1) -> Dict[str, Any]:
        """Detect demographic parity bias."""
        unique_groups = np.unique(sensitive_attributes)
        group_rates = {}
        
        for group in unique_groups:
            group_mask = sensitive_attributes == group
            group_positive_rate = np.mean(y_pred[group_mask])
            group_rates[str(group)] = group_positive_rate
        
        # Calculate parity difference
        rates = list(group_rates.values())
        max_diff = max(rates) - min(rates)
        
        return {
            'bias_type': 'demographic_parity',
            'group_rates': group_rates,
            'max_difference': max_diff,
            'threshold': threshold,
            'bias_detected': max_diff > threshold,
            'severity': 'high' if max_diff > 0.2 else 'medium' if max_diff > 0.1 else 'low'
        }
    
    def detect_equalized_odds(self,
                             y_true: np.ndarray,
                             y_pred: np.ndarray,
                             sensitive_attributes: np.ndarray,
                             threshold: float = 0.1) -> Dict[str, Any]:
        """Detect equalized odds bias."""
        unique_groups = np.unique(sensitive_attributes)
        group_metrics = {}
        
        for group in unique_groups:
            group_mask = sensitive_attributes == group
            group_y_true = y_true[group_mask]
            group_y_pred = y_pred[group_mask]
            
            # True positive rate
            tpr = np.sum((group_y_true == 1) & (group_y_pred == 1)) / np.sum(group_y_true == 1)
            # False positive rate
            fpr = np.sum((group_y_true == 0) & (group_y_pred == 1)) / np.sum(group_y_true == 0)
            
            group_metrics[str(group)] = {'tpr': tpr, 'fpr': fpr}
        
        # Calculate equalized odds difference
        tprs = [metrics['tpr'] for metrics in group_metrics.values()]
        fprs = [metrics['fpr'] for metrics in group_metrics.values()]
        
        tpr_diff = max(tprs) - min(tprs)
        fpr_diff = max(fprs) - min(fprs)
        max_diff = max(tpr_diff, fpr_diff)
        
        return {
            'bias_type': 'equalized_odds',
            'group_metrics': group_metrics,
            'tpr_difference': tpr_diff,
            'fpr_difference': fpr_diff,
            'max_difference': max_diff,
            'threshold': threshold,
            'bias_detected': max_diff > threshold,
            'severity': 'high' if max_diff > 0.2 else 'medium' if max_diff > 0.1 else 'low'
        }
    
    def detect_calibration_bias(self,
                               y_true: np.ndarray,
                               y_prob: np.ndarray,
                               sensitive_attributes: np.ndarray,
                               n_bins: int = 10) -> Dict[str, Any]:
        """Detect calibration bias across groups."""
        unique_groups = np.unique(sensitive_attributes)
        group_calibration = {}
        
        for group in unique_groups:
            group_mask = sensitive_attributes == group
            group_y_true = y_true[group_mask]
            group_y_prob = y_prob[group_mask]
            
            # Calculate calibration curve
            bin_boundaries = np.linspace(0, 1, n_bins + 1)
            bin_lowers = bin_boundaries[:-1]
            bin_uppers = bin_boundaries[1:]
            
            calibration_error = 0
            for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
                in_bin = (group_y_prob > bin_lower) & (group_y_prob <= bin_upper)
                prop_in_bin = in_bin.mean()
                
                if prop_in_bin > 0:
                    accuracy_in_bin = group_y_true[in_bin].mean()
                    avg_confidence_in_bin = group_y_prob[in_bin].mean()
                    calibration_error += np.abs(avg_confidence_in_bin - accuracy_in_bin) * prop_in_bin
            
            group_calibration[str(group)] = calibration_error
        
        # Calculate calibration difference
        calibration_errors = list(group_calibration.values())
        max_diff = max(calibration_errors) - min(calibration_errors)
        
        return {
            'bias_type': 'calibration',
            'group_calibration_errors': group_calibration,
            'max_difference': max_diff,
            'bias_detected': max_diff > 0.1,
            'severity': 'high' if max_diff > 0.2 else 'medium' if max_diff > 0.1 else 'low'
        }


class AccuracyValidator:
    """Validates model accuracy and performance."""
    
    def __init__(self):
        """Initialize accuracy validator."""
        self.logger = logging.getLogger(__name__)
    
    def validate_classification_model(self,
                                    model: Any,
                                    X_test: np.ndarray,
                                    y_test: np.ndarray,
                                    class_names: Optional[List[str]] = None) -> ValidationMetrics:
        """Validate classification model performance."""
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Get prediction probabilities if available
        y_prob = None
        if hasattr(model, 'predict_proba'):
            y_prob = model.predict_proba(X_test)
        elif hasattr(model, 'decision_function'):
            y_prob = model.decision_function(X_test)
        
        # Calculate basic metrics
        metrics = ValidationMetrics()
        metrics.accuracy = accuracy_score(y_test, y_pred)
        metrics.precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        metrics.recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        metrics.f1_score = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # ROC AUC for binary classification
        if len(np.unique(y_test)) == 2 and y_prob is not None:
            if y_prob.ndim > 1:
                y_prob_binary = y_prob[:, 1]
            else:
                y_prob_binary = y_prob
            metrics.roc_auc = roc_auc_score(y_test, y_prob_binary)
        
        # Confusion matrix
        metrics.confusion_matrix = confusion_matrix(y_test, y_pred)
        
        # Per-class metrics
        if class_names is None:
            class_names = [str(i) for i in np.unique(y_test)]
        
        per_class_precision = precision_score(y_test, y_pred, average=None, zero_division=0)
        per_class_recall = recall_score(y_test, y_pred, average=None, zero_division=0)
        per_class_f1 = f1_score(y_test, y_pred, average=None, zero_division=0)
        
        for i, class_name in enumerate(class_names):
            if i < len(per_class_precision):
                metrics.per_class_precision[class_name] = per_class_precision[i]
                metrics.per_class_recall[class_name] = per_class_recall[i]
                metrics.per_class_f1[class_name] = per_class_f1[i]
        
        return metrics
    
    def cross_validate_model(self,
                           model: Any,
                           X: np.ndarray,
                           y: np.ndarray,
                           cv_folds: int = 5,
                           scoring: str = 'accuracy') -> Tuple[List[float], float, float]:
        """Perform cross-validation on model."""
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        cv_scores = cross_val_score(model, X, y, cv=cv, scoring=scoring)
        
        return cv_scores.tolist(), cv_scores.mean(), cv_scores.std()
    
    def measure_inference_time(self,
                             model: Any,
                             X_sample: np.ndarray,
                             n_iterations: int = 100) -> float:
        """Measure model inference time."""
        start_time = time.time()
        
        for _ in range(n_iterations):
            _ = model.predict(X_sample)
        
        total_time = time.time() - start_time
        return total_time / n_iterations


class PerformanceValidator:
    """Validates model performance characteristics."""
    
    def __init__(self):
        """Initialize performance validator."""
        self.logger = logging.getLogger(__name__)
    
    def validate_model_size(self, model: Any) -> float:
        """Estimate model size in MB."""
        try:
            import pickle
            model_bytes = pickle.dumps(model)
            return len(model_bytes) / (1024 * 1024)
        except Exception as e:
            self.logger.warning(f"Could not estimate model size: {e}")
            return 0.0
    
    def validate_memory_usage(self, model: Any, X_sample: np.ndarray) -> Dict[str, float]:
        """Validate memory usage during inference."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        # Measure memory before inference
        memory_before = process.memory_info().rss / (1024 * 1024)  # MB
        
        # Perform inference
        _ = model.predict(X_sample)
        
        # Measure memory after inference
        memory_after = process.memory_info().rss / (1024 * 1024)  # MB
        
        return {
            'memory_before_mb': memory_before,
            'memory_after_mb': memory_after,
            'memory_increase_mb': memory_after - memory_before
        }
    
    def validate_scalability(self,
                           model: Any,
                           X_base: np.ndarray,
                           scale_factors: List[int] = [1, 2, 5, 10]) -> Dict[str, List[float]]:
        """Test model scalability with different input sizes."""
        inference_times = []
        memory_usage = []
        
        for factor in scale_factors:
            # Create scaled dataset
            n_samples = len(X_base) * factor
            if n_samples > len(X_base):
                # Repeat samples to reach desired size
                indices = np.random.choice(len(X_base), n_samples, replace=True)
                X_scaled = X_base[indices]
            else:
                X_scaled = X_base[:n_samples]
            
            # Measure inference time
            start_time = time.time()
            _ = model.predict(X_scaled)
            inference_time = time.time() - start_time
            inference_times.append(inference_time)
            
            # Measure memory usage
            memory_info = self.validate_memory_usage(model, X_scaled)
            memory_usage.append(memory_info['memory_increase_mb'])
        
        return {
            'scale_factors': scale_factors,
            'inference_times': inference_times,
            'memory_usage': memory_usage
        }


class MLModelValidator:
    """Comprehensive ML model validation framework."""
    
    def __init__(self):
        """Initialize ML model validator."""
        self.logger = logging.getLogger(__name__)
        
        # Initialize validators
        self.bias_detector = BiasDetector()
        self.accuracy_validator = AccuracyValidator()
        self.performance_validator = PerformanceValidator()
        
        # Validation thresholds
        self.thresholds = {
            'min_accuracy': 0.8,
            'min_precision': 0.7,
            'min_recall': 0.7,
            'min_f1': 0.7,
            'max_bias_difference': 0.1,
            'max_inference_time_ms': 100,
            'max_model_size_mb': 100
        }
    
    def validate_model(self,
                      model: Any,
                      X_test: np.ndarray,
                      y_test: np.ndarray,
                      model_name: str,
                      model_version: str = "1.0",
                      sensitive_attributes: Optional[np.ndarray] = None,
                      class_names: Optional[List[str]] = None) -> ModelValidationResult:
        """Perform comprehensive model validation."""
        
        result = ModelValidationResult(
            model_name=model_name,
            model_version=model_version,
            validation_type="comprehensive",
            dataset_size=len(X_test),
            test_size=len(X_test)
        )
        
        try:
            # Validate accuracy and performance
            result.metrics = self.accuracy_validator.validate_classification_model(
                model, X_test, y_test, class_names
            )
            
            # Cross-validation
            cv_scores, cv_mean, cv_std = self.accuracy_validator.cross_validate_model(
                model, X_test, y_test
            )
            result.metrics.cv_scores = cv_scores
            result.metrics.cv_mean = cv_mean
            result.metrics.cv_std = cv_std
            
            # Performance metrics
            result.model_size_mb = self.performance_validator.validate_model_size(model)
            
            # Inference time
            sample_size = min(100, len(X_test))
            X_sample = X_test[:sample_size]
            result.inference_time = self.accuracy_validator.measure_inference_time(
                model, X_sample
            )
            
            # Bias detection
            if sensitive_attributes is not None:
                y_pred = model.predict(X_test)
                
                # Demographic parity
                demo_parity = self.bias_detector.detect_demographic_parity(
                    y_pred, sensitive_attributes
                )
                result.metrics.bias_metrics['demographic_parity'] = demo_parity['max_difference']
                
                if demo_parity['bias_detected']:
                    result.bias_issues.append(f"Demographic parity bias detected: {demo_parity['max_difference']:.3f}")
                
                # Equalized odds
                eq_odds = self.bias_detector.detect_equalized_odds(
                    y_test, y_pred, sensitive_attributes
                )
                result.metrics.bias_metrics['equalized_odds'] = eq_odds['max_difference']
                
                if eq_odds['bias_detected']:
                    result.bias_issues.append(f"Equalized odds bias detected: {eq_odds['max_difference']:.3f}")
                
                # Calibration bias (if probabilities available)
                if hasattr(model, 'predict_proba'):
                    y_prob = model.predict_proba(X_test)
                    if y_prob.shape[1] == 2:  # Binary classification
                        calib_bias = self.bias_detector.detect_calibration_bias(
                            y_test, y_prob[:, 1], sensitive_attributes
                        )
                        result.metrics.bias_metrics['calibration'] = calib_bias['max_difference']
                        
                        if calib_bias['bias_detected']:
                            result.bias_issues.append(f"Calibration bias detected: {calib_bias['max_difference']:.3f}")
            
            # Check performance thresholds
            self._check_performance_thresholds(result)
            
            # Generate recommendations
            self._generate_recommendations(result)
            
        except Exception as e:
            self.logger.error(f"Error during model validation: {e}")
            result.performance_issues.append(f"Validation error: {str(e)}")
        
        return result
    
    def _check_performance_thresholds(self, result: ModelValidationResult):
        """Check if model meets performance thresholds."""
        metrics = result.metrics
        
        if metrics.accuracy < self.thresholds['min_accuracy']:
            result.performance_issues.append(
                f"Low accuracy: {metrics.accuracy:.3f} < {self.thresholds['min_accuracy']}"
            )
        
        if metrics.precision < self.thresholds['min_precision']:
            result.performance_issues.append(
                f"Low precision: {metrics.precision:.3f} < {self.thresholds['min_precision']}"
            )
        
        if metrics.recall < self.thresholds['min_recall']:
            result.performance_issues.append(
                f"Low recall: {metrics.recall:.3f} < {self.thresholds['min_recall']}"
            )
        
        if metrics.f1_score < self.thresholds['min_f1']:
            result.performance_issues.append(
                f"Low F1 score: {metrics.f1_score:.3f} < {self.thresholds['min_f1']}"
            )
        
        if result.inference_time * 1000 > self.thresholds['max_inference_time_ms']:
            result.performance_issues.append(
                f"Slow inference: {result.inference_time * 1000:.1f}ms > {self.thresholds['max_inference_time_ms']}ms"
            )
        
        if result.model_size_mb > self.thresholds['max_model_size_mb']:
            result.performance_issues.append(
                f"Large model size: {result.model_size_mb:.1f}MB > {self.thresholds['max_model_size_mb']}MB"
            )
    
    def _generate_recommendations(self, result: ModelValidationResult):
        """Generate recommendations based on validation results."""
        metrics = result.metrics
        
        # Performance recommendations
        if metrics.accuracy < 0.9:
            result.recommendations.append("Consider collecting more training data or feature engineering")
        
        if metrics.precision < metrics.recall:
            result.recommendations.append("Model has high false positive rate - consider adjusting decision threshold")
        elif metrics.recall < metrics.precision:
            result.recommendations.append("Model has high false negative rate - consider class balancing techniques")
        
        if result.inference_time > 0.05:  # 50ms
            result.recommendations.append("Consider model optimization or quantization for faster inference")
        
        if result.model_size_mb > 50:
            result.recommendations.append("Consider model compression or pruning to reduce size")
        
        # Bias recommendations
        if result.bias_issues:
            result.recommendations.append("Implement bias mitigation techniques such as fairness constraints")
            result.recommendations.append("Consider collecting more balanced training data")
        
        # Cross-validation recommendations
        if metrics.cv_std > 0.1:
            result.recommendations.append("High variance in cross-validation - consider regularization")
    
    def generate_validation_report(self, result: ModelValidationResult) -> str:
        """Generate a comprehensive validation report."""
        report = f"""
# ML Model Validation Report

## Model Information
- **Model Name**: {result.model_name}
- **Model Version**: {result.model_version}
- **Validation Date**: {result.validation_date.strftime('%Y-%m-%d %H:%M:%S')}
- **Dataset Size**: {result.dataset_size:,} samples
- **Test Size**: {result.test_size:,} samples

## Performance Metrics
- **Accuracy**: {result.metrics.accuracy:.4f}
- **Precision**: {result.metrics.precision:.4f}
- **Recall**: {result.metrics.recall:.4f}
- **F1 Score**: {result.metrics.f1_score:.4f}
- **ROC AUC**: {result.metrics.roc_auc:.4f if result.metrics.roc_auc else 'N/A'}

## Cross-Validation Results
- **CV Mean**: {result.metrics.cv_mean:.4f}
- **CV Std**: {result.metrics.cv_std:.4f}
- **CV Scores**: {[f'{score:.4f}' for score in result.metrics.cv_scores]}

## Performance Characteristics
- **Model Size**: {result.model_size_mb:.2f} MB
- **Inference Time**: {result.inference_time * 1000:.2f} ms
- **Training Time**: {result.training_time:.2f} seconds

## Bias Analysis
"""
        
        if result.metrics.bias_metrics:
            for bias_type, value in result.metrics.bias_metrics.items():
                report += f"- **{bias_type.replace('_', ' ').title()}**: {value:.4f}\n"
        else:
            report += "- No bias analysis performed\n"
        
        report += "\n## Issues Identified\n"
        
        if result.performance_issues:
            report += "### Performance Issues\n"
            for issue in result.performance_issues:
                report += f"- {issue}\n"
        
        if result.bias_issues:
            report += "### Bias Issues\n"
            for issue in result.bias_issues:
                report += f"- {issue}\n"
        
        if not result.performance_issues and not result.bias_issues:
            report += "- No significant issues identified\n"
        
        report += "\n## Recommendations\n"
        if result.recommendations:
            for rec in result.recommendations:
                report += f"- {rec}\n"
        else:
            report += "- No specific recommendations\n"
        
        return report
    
    def set_thresholds(self, **kwargs):
        """Update validation thresholds."""
        for key, value in kwargs.items():
            if key in self.thresholds:
                self.thresholds[key] = value
            else:
                self.logger.warning(f"Unknown threshold: {key}")


# Utility functions for model validation

def create_synthetic_bias_dataset(n_samples: int = 1000, 
                                bias_strength: float = 0.3) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Create synthetic dataset with bias for testing."""
    np.random.seed(42)
    
    # Features
    X = np.random.randn(n_samples, 10)
    
    # Sensitive attribute (0 or 1)
    sensitive_attr = np.random.binomial(1, 0.5, n_samples)
    
    # Target with bias
    # Base prediction based on features
    y_base = (X[:, 0] + X[:, 1] > 0).astype(int)
    
    # Add bias based on sensitive attribute
    bias_mask = sensitive_attr == 1
    y_biased = y_base.copy()
    
    # Introduce bias: group 1 has lower positive rate
    flip_indices = np.where(bias_mask & (y_base == 1))[0]
    n_flip = int(len(flip_indices) * bias_strength)
    if n_flip > 0:
        flip_selected = np.random.choice(flip_indices, n_flip, replace=False)
        y_biased[flip_selected] = 0
    
    return X, y_biased, sensitive_attr


def validate_security_ml_model(model: Any,
                             X_test: np.ndarray,
                             y_test: np.ndarray,
                             model_name: str) -> ModelValidationResult:
    """Validate ML model specifically for security applications."""
    validator = MLModelValidator()
    
    # Set stricter thresholds for security models
    validator.set_thresholds(
        min_accuracy=0.95,
        min_precision=0.9,
        min_recall=0.85,
        min_f1=0.9,
        max_inference_time_ms=50
    )
    
    return validator.validate_model(model, X_test, y_test, model_name)