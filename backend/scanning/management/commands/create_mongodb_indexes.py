"""
Management command to create MongoDB indexes
"""
from django.core.management.base import BaseCommand
from scanning.mongodb_indexes import create_all_indexes


class Command(BaseCommand):
    help = 'Create MongoDB indexes for optimal performance'

    def handle(self, *args, **options):
        self.stdout.write('Creating MongoDB indexes...')
        
        results = create_all_indexes()
        
        for collection, success in results.items():
            if success:
                self.stdout.write(
                    self.style.SUCCESS(f'✓ Successfully created indexes for {collection} collection')
                )
            else:
                self.stdout.write(
                    self.style.ERROR(f'✗ Failed to create indexes for {collection} collection')
                )
        
        if all(results.values()):
            self.stdout.write(self.style.SUCCESS('\nAll indexes created successfully!'))
        else:
            self.stdout.write(self.style.WARNING('\nSome indexes failed to create. Check logs for details.'))

