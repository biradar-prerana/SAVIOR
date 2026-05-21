"""
Management command to train the anomaly detection model
"""
from django.core.management.base import BaseCommand
from anomaly_detection.anomaly_service import AnomalyDetectionService
from scanning.models import Vulnerability


class Command(BaseCommand):
    help = 'Train the Isolation Forest anomaly detection model'

    def add_arguments(self, parser):
        parser.add_argument(
            '--model-name',
            type=str,
            default='Anomaly Detection Model',
            help='Name for the trained model'
        )
        parser.add_argument(
            '--model-version',
            type=str,
            default='1.0',
            help='Version string for the model'
        )
        parser.add_argument(
            '--model-type',
            type=str,
            default='vulnerability',
            choices=['vulnerability', 'system_behavior', 'configuration', 'zero_day'],
            help='Type of anomaly detection model'
        )
        parser.add_argument(
            '--contamination',
            type=float,
            default=0.1,
            help='Expected proportion of anomalies (0.0 to 0.5)'
        )
        parser.add_argument(
            '--min-samples',
            type=int,
            default=10,
            help='Minimum number of samples required for training'
        )

    def handle(self, *args, **options):
        model_name = options['model_name']
        model_version = options['model_version']
        model_type = options['model_type']
        contamination = options['contamination']
        min_samples = options['min_samples']
        
        self.stdout.write('Training anomaly detection model...')
        self.stdout.write(f'Model: {model_name} v{model_version}')
        self.stdout.write(f'Type: {model_type}')
        self.stdout.write(f'Contamination: {contamination}')
        
        # Get vulnerabilities
        vulnerabilities = Vulnerability.objects.select_related('cve_data')
        
        count = vulnerabilities.count()
        self.stdout.write(f'Found {count} vulnerabilities')
        
        if count < min_samples:
            self.stdout.write(
                self.style.ERROR(
                    f'Insufficient data. Need at least {min_samples} samples, found {count}.'
                )
            )
            return
        
        try:
            service = AnomalyDetectionService()
            anomaly_model = service.train_model(
                vulnerabilities=vulnerabilities,
                model_name=model_name,
                model_version=model_version,
                model_type=model_type,
                contamination=contamination
            )
            
            self.stdout.write(self.style.SUCCESS('\n✓ Model trained successfully!'))
            self.stdout.write(f'\nModel ID: {anomaly_model.id}')
            self.stdout.write(f'Model: {anomaly_model.name} v{anomaly_model.version}')
            self.stdout.write(f'Active: {anomaly_model.is_active}')
            
            # Display metrics
            metrics = anomaly_model.performance_metrics
            self.stdout.write('\nPerformance Metrics:')
            self.stdout.write(f'  Training samples: {metrics.get("training_samples", 0)}')
            self.stdout.write(f'  Detected anomalies: {metrics.get("detected_anomalies", 0)}')
            self.stdout.write(f'  Anomaly rate: {metrics.get("anomaly_rate", 0):.2%}')
            self.stdout.write(f'  Mean anomaly score: {metrics.get("mean_anomaly_score", 0):.4f}')
            self.stdout.write(f'  Std anomaly score: {metrics.get("std_anomaly_score", 0):.4f}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'\n✗ Error training model: {str(e)}')
            )
            raise

