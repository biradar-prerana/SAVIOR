# Anomaly Detection Module

This module provides anomaly detection using Isolation Forest to identify unusual system behavior, configuration drift, unknown threats, and potential zero-day vulnerabilities.

## Features

- **Isolation Forest Algorithm**: Unsupervised anomaly detection using scikit-learn
- **Multiple Detection Types**:
  - Unusual System Behavior
  - Configuration Drift
  - Unknown Threats
  - Potential Zero-Day Vulnerabilities
  - Scan Anomalies
  - Unusual Vulnerability Patterns
- **Automatic Detection**: Integrated with vulnerability and scan signals
- **Zero-Day Detection**: Flags vulnerabilities without CVE assignments
- **Configuration Drift**: Monitors changes from baseline configurations

## Detection Types

### 1. Zero-Day Vulnerabilities
Detects vulnerabilities that:
- Have no CVE ID assigned
- Show unusual patterns compared to known vulnerabilities
- Have high severity but no known CVE

### 2. System Behavior Anomalies
Detects unusual patterns in:
- Scan duration
- Vulnerability counts
- Severity distributions
- Scan frequency

### 3. Configuration Drift
Monitors changes in:
- System configurations
- Missing configurations
- New configurations
- Changed values

### 4. Unknown Threats
Identifies vulnerabilities with:
- Unusual severity/CVSS combinations
- Uncommon vulnerability types
- Pattern deviations from baseline

## Model Features

The Isolation Forest model uses the following features for vulnerability anomaly detection:

1. **CVE Presence** - Whether vulnerability has CVE ID
2. **Severity** - Encoded severity level
3. **CVSS Score** - Normalized CVSS score (0-1)
4. **Detection Count** - How many times detected
5. **Vulnerability Age** - Days since first detected
6. **False Positive Flag** - Inverse of false positive status
7. **Vulnerability Type** - Encoded vulnerability type
8. **Evidence Complexity** - Complexity of evidence data
9. **CVE Age** - Age of associated CVE
10. **Exploit Availability** - Binary flag
11. **Patch Availability** - Binary flag

## Usage

### Training the Model

#### Using Management Command

```bash
python manage.py train_anomaly_model \
    --model-name "Anomaly Detection Model" \
    --model-version "1.0" \
    --model-type vulnerability \
    --contamination 0.1
```

#### Using API

```bash
POST /api/anomaly/models/train/
{
    "model_name": "Anomaly Detection Model",
    "model_version": "1.0",
    "model_type": "vulnerability",
    "contamination": 0.1
}
```

**Note**: Requires SOC Manager role.

### Detecting Anomalies

#### Detect Vulnerability Anomalies

```bash
POST /api/anomaly/anomalies/detect_vulnerability/
{
    "vulnerability_id": 123
}
```

#### Detect Scan Anomalies

```bash
POST /api/anomaly/anomalies/detect_scan/
{
    "scan_id": 456
}
```

#### Detect Configuration Drift

```bash
POST /api/anomaly/baselines/detect_drift/
{
    "target_id": 789,
    "current_config": {
        "key1": "value1",
        "key2": "value2"
    },
    "baseline_name": "baseline_v1"
}
```

### Querying Anomalies

#### Get All Anomalies

```bash
GET /api/anomaly/anomalies/
```

#### Filter by Type

```bash
GET /api/anomaly/anomalies/?anomaly_type=zero_day
```

#### Get Zero-Day Vulnerabilities

```bash
GET /api/anomaly/anomalies/zero_days/
```

#### Filter by Severity

```bash
GET /api/anomaly/anomalies/?severity=critical
```

### Managing Anomalies

#### Investigate Anomaly

```bash
POST /api/anomaly/anomalies/{id}/investigate/
{
    "notes": "Investigating potential zero-day"
}
```

#### Confirm Anomaly

```bash
POST /api/anomaly/anomalies/{id}/confirm/
{
    "notes": "Confirmed as zero-day vulnerability"
}
```

#### Mark as False Positive

```bash
POST /api/anomaly/anomalies/{id}/mark_false_positive/
{
    "notes": "False positive - known CVE"
}
```

#### Resolve Anomaly

```bash
POST /api/anomaly/anomalies/{id}/resolve/
{
    "notes": "Vulnerability patched"
}
```

## Automatic Detection

The module automatically detects anomalies when:

1. **New Vulnerability Created**: Automatically checks for anomalies
2. **Scan Completed**: Automatically checks for scan anomalies

This is handled by Django signals in `signals.py`.

## Model Configuration

### Contamination Parameter

The `contamination` parameter controls the expected proportion of anomalies:
- **0.05** (5%): Very strict, only most anomalous
- **0.1** (10%): Default, balanced detection
- **0.2** (20%): More lenient, catches more potential issues

### Model Types

- **vulnerability**: Detects anomalies in vulnerabilities
- **system_behavior**: Detects anomalies in scan behavior
- **configuration**: Detects configuration drift
- **zero_day**: Specialized zero-day detection

## Anomaly Score

The anomaly score ranges from approximately -0.5 to 0.5:
- **Negative values**: Indicate anomalies (more negative = more anomalous)
- **Positive values**: Indicate normal behavior
- **Threshold**: Typically -0.1 to -0.3 depending on contamination

## API Endpoints

- `GET /api/anomaly/anomalies/` - List all anomalies
- `POST /api/anomaly/anomalies/detect_vulnerability/` - Detect vulnerability anomalies
- `POST /api/anomaly/anomalies/detect_scan/` - Detect scan anomalies
- `GET /api/anomaly/anomalies/zero_days/` - Get zero-day vulnerabilities
- `POST /api/anomaly/anomalies/{id}/investigate/` - Mark as investigating
- `POST /api/anomaly/anomalies/{id}/confirm/` - Confirm anomaly
- `POST /api/anomaly/anomalies/{id}/mark_false_positive/` - Mark false positive
- `POST /api/anomaly/anomalies/{id}/resolve/` - Resolve anomaly
- `GET /api/anomaly/models/` - List anomaly models
- `POST /api/anomaly/models/train/` - Train new model (SOC Manager)
- `POST /api/anomaly/models/{id}/activate/` - Activate model (SOC Manager)
- `GET /api/anomaly/baselines/` - List baselines
- `POST /api/anomaly/baselines/detect_drift/` - Detect configuration drift

## Example Response

```json
{
    "id": 1,
    "anomaly_type": "zero_day",
    "severity": "critical",
    "status": "new",
    "vulnerability": 123,
    "title": "Anomaly detected: SQL Injection in Login",
    "description": "Unusual vulnerability pattern detected. Anomaly score: -0.452",
    "anomaly_score": -0.452,
    "confidence": 0.452,
    "is_potential_zero_day": true,
    "has_no_cve": true,
    "unusual_pattern": "CVSS: 9.8, Severity: critical, Type: SQL Injection",
    "detected_at": "2024-01-15T10:30:00Z"
}
```

## Best Practices

1. **Train Regularly**: Retrain models as new data becomes available
2. **Review Anomalies**: Manually review detected anomalies to reduce false positives
3. **Update Baselines**: Keep configuration baselines up to date
4. **Monitor Zero-Days**: Pay special attention to zero-day detections
5. **Adjust Contamination**: Fine-tune contamination based on your environment

## Troubleshooting

### Too Many False Positives
- Increase contamination parameter
- Review and mark false positives to improve model
- Retrain with more data

### Missing Anomalies
- Decrease contamination parameter
- Check model is active
- Verify features are being extracted correctly

### Model Not Loading
- Check model file path exists
- Verify model was trained successfully
- Check file permissions

