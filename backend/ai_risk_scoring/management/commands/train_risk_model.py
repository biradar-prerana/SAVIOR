"""
Management command to train the risk scoring ML model
"""
from django.core.management.base import BaseCommand
from ai_risk_scoring.ml_service import MLRiskScoringService
from scanning.models import Vulnerability


class Command(BaseCommand):
    help = 'Train the Random Forest risk scoring model using CVE data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--model-name',
            type=str,
            default='Risk Scoring Model',
            help='Name for the trained model'
        )
        parser.add_argument(
            '--model-version',
            type=str,
            default='1.0',
            help='Version string for the model'
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
        min_samples = options['min_samples']
        
        self.stdout.write('Training risk scoring model...')
        self.stdout.write(f'Model: {model_name} v{model_version}')
        
        # Get vulnerabilities with CVE data
        vulnerabilities = Vulnerability.objects.filter(
            cve_data__isnull=False
        ).select_related('cve_data', 'risk_score')
        
        count = vulnerabilities.count()
        self.stdout.write(f'Found {count} vulnerabilities with CVE data')
        
        if count < min_samples:
            self.stdout.write(
                self.style.ERROR(
                    f'Insufficient data. Need at least {min_samples} samples, found {count}.'
                )
            )
            return
        
        try:
            ml_service = MLRiskScoringService()
            ai_model = ml_service.train_model(
                vulnerabilities=vulnerabilities,
                model_name=model_name,
                model_version=model_version
            )
            
            self.stdout.write(self.style.SUCCESS('\n✓ Model trained successfully!'))
            self.stdout.write(f'\nModel ID: {ai_model.id}')
            self.stdout.write(f'Model: {ai_model.name} v{ai_model.version}')
            self.stdout.write(f'Active: {ai_model.is_active}')
            
            # Display metrics
            metrics = ai_model.performance_metrics
            self.stdout.write('\nPerformance Metrics:')
            self.stdout.write(f'  Training R²: {metrics.get("train_r2", 0):.4f}')
            self.stdout.write(f'  Test R²: {metrics.get("test_r2", 0):.4f}')
            self.stdout.write(f'  Test MAE: {metrics.get("test_mae", 0):.2f}')
            self.stdout.write(f'  Test MSE: {metrics.get("test_mse", 0):.2f}')
            self.stdout.write(f'  Training samples: {metrics.get("train_samples", 0)}')
            self.stdout.write(f'  Test samples: {metrics.get("test_samples", 0)}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'\n✗ Error training model: {str(e)}')
            )
            raise

