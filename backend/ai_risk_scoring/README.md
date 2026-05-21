# AI Risk Scoring Module

This module provides AI-based risk scoring using Random Forest machine learning models trained on CVE (Common Vulnerabilities and Exposures) data.

## Features

- **Random Forest Model**: Trained on severity, exploitability, and impact features
- **CVE Data Integration**: Uses CVE data including CVSS scores, exploit availability, and patch status
- **Risk Score Prediction**: Returns risk scores between 0-100
- **Confidence Intervals**: Provides confidence scores and prediction ranges
- **Model Versioning**: Track and manage multiple model versions
- **Automatic Training**: Management command for easy model training

## Model Features

The Random Forest model uses the following features:

1. **Severity** - Encoded severity level (critical, high, medium, low, info)
2. **Base CVSS Score** - Maximum CVSS v2/v3/v3.1 score
3. **Exploitability Score** - Extracted from CVSS vector (0-100)
4. **Impact Score** - Extracted from CVSS vector (0-100)
5. **Exploit Available** - Binary flag for exploit availability
6. **Patch Available** - Binary flag for patch availability
7. **CVE Age** - Age of CVE in years (normalized)
8. **Detection Count** - How many times vulnerability was detected
9. **Not False Positive** - Inverse of false positive flag

## Usage

### Training the Model

#### Using Management Command

```bash
python manage.py train_risk_model --model-name "Risk Scoring Model" --model-version "1.0"
```

#### Using API

```bash
POST /api/ai-risk/models/train/
{
    "model_name": "Risk Scoring Model",
    "model_version": "1.0"
}
```

**Note**: Requires SOC Manager role.

### Calculating Risk Scores

#### Using API

```bash
POST /api/ai-risk/scores/calculate/
{
    "vulnerability_id": 123
}
```

#### Using Python

```python
from ai_risk_scoring.ml_service import MLRiskScoringService
from scanning.models import Vulnerability

ml_service = MLRiskScoringService()
vulnerability = Vulnerability.objects.get(id=123)
risk_score = ml_service.calculate_risk_score(vulnerability)

print(f"Risk Score: {risk_score.overall_score}")
print(f"Confidence: {risk_score.confidence}")
print(f"Exploitability: {risk_score.exploitability_score}")
print(f"Impact: {risk_score.impact_score}")
```

## Model Training Requirements

- Minimum 10 samples with CVE data
- Vulnerabilities must have linked CVE data
- CVE data should include CVSS scores for best results

## Model Performance

The model provides the following metrics:

- **R² Score**: Coefficient of determination (closer to 1.0 is better)
- **MAE**: Mean Absolute Error (lower is better)
- **MSE**: Mean Squared Error (lower is better)

## Model Storage

Trained models are stored in:
- `backend/ai_risk_scoring/models/`
- Model files are saved as `.pkl` files using joblib
- Model metadata is stored in the `AIModel` database table

## Model Versioning

- Each trained model has a unique name and version
- Only one model per type can be active at a time
- Model activation can be done via API or admin interface

## API Endpoints

- `POST /api/ai-risk/scores/calculate/` - Calculate risk score for vulnerability
- `POST /api/ai-risk/models/train/` - Train new model (SOC Manager only)
- `GET /api/ai-risk/models/` - List all models
- `POST /api/ai-risk/models/{id}/activate/` - Activate a model (SOC Manager only)

## Fallback Calculation

If the ML model is not available, the system uses a fallback calculation:
- Based on CVSS score (0-10 scaled to 0-100)
- Adjusted for exploit availability (+20% if exploit available)
- Lower confidence score (0.5)

## Example Response

```json
{
    "id": 1,
    "vulnerability": 123,
    "overall_score": 85.5,
    "exploitability_score": 77.2,
    "impact_score": 92.1,
    "confidence": 0.89,
    "factors": {
        "prediction_std_dev": 3.2,
        "min_score": 82.3,
        "max_score": 88.7,
        "feature_importance": {
            "severity": 0.25,
            "base_cvss_score": 0.20,
            "exploitability_score": 0.18,
            "impact_score": 0.15,
            ...
        }
    },
    "ai_analysis": {
        "model_version": "Risk Scoring Model v1.0",
        "prediction_method": "random_forest"
    },
    "predicted_exploit_likelihood": 0.855,
    "remediation_priority": 86
}
```

