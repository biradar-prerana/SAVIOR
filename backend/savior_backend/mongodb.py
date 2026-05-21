"""
Secure MongoDB connection utility
"""
import ssl
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ConfigurationError
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class MongoDBConnection:
    """Singleton MongoDB connection manager with secure connection handling"""
    
    _instance = None
    _client = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MongoDBConnection, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._client is None:
            self._client = self._create_connection()
    
    def _create_connection(self):
        """Create secure MongoDB connection"""
        try:
            mongodb_settings = settings.MONGODB_SETTINGS
            
            # Build connection parameters
            connection_params = {
                'host': mongodb_settings['host'],
                'serverSelectionTimeoutMS': 5000,
                'connectTimeoutMS': 20000,
                'maxPoolSize': 50,
                'minPoolSize': 10,
                'retryWrites': True,
                'retryReads': True,
            }
            
            # Add authentication if provided
            if mongodb_settings.get('username') and mongodb_settings.get('password'):
                connection_params['username'] = mongodb_settings['username']
                connection_params['password'] = mongodb_settings['password']
                connection_params['authSource'] = mongodb_settings.get('authSource', 'admin')
                connection_params['authMechanism'] = mongodb_settings.get('authMechanism', 'SCRAM-SHA-1')
            
            # Add SSL/TLS configuration if enabled
            if mongodb_settings.get('ssl', False):
                ssl_context = ssl.create_default_context()
                
                # SSL certificate requirements
                ssl_cert_reqs = mongodb_settings.get('ssl_cert_reqs', 'CERT_NONE')
                if ssl_cert_reqs == 'CERT_REQUIRED':
                    ssl_context.check_hostname = True
                    ssl_context.verify_mode = ssl.CERT_REQUIRED
                elif ssl_cert_reqs == 'CERT_OPTIONAL':
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_OPTIONAL
                else:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                
                # CA certificates
                if mongodb_settings.get('ssl_ca_certs'):
                    ssl_context.load_verify_locations(mongodb_settings['ssl_ca_certs'])
                
                # Client certificate
                if mongodb_settings.get('ssl_certfile') and mongodb_settings.get('ssl_keyfile'):
                    ssl_context.load_cert_chain(
                        mongodb_settings['ssl_certfile'],
                        mongodb_settings['ssl_keyfile']
                    )
                
                connection_params['ssl'] = True
                connection_params['ssl_context'] = ssl_context
            
            # Create connection
            client = MongoClient(**connection_params)
            
            # Test connection
            client.admin.command('ping')
            logger.info(f"Successfully connected to MongoDB: {mongodb_settings['database']}")
            
            return client
            
        except ConnectionFailure as e:
            logger.error(f"MongoDB connection failed: {str(e)}")
            raise
        except ConfigurationError as e:
            logger.error(f"MongoDB configuration error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error connecting to MongoDB: {str(e)}")
            raise
    
    def get_client(self):
        """Get MongoDB client instance"""
        if self._client is None:
            self._client = self._create_connection()
        return self._client
    
    def get_database(self, database_name=None):
        """Get database instance"""
        if database_name is None:
            database_name = settings.MONGODB_SETTINGS['database']
        return self.get_client()[database_name]
    
    def get_collection(self, collection_name, database_name=None):
        """Get collection instance"""
        db = self.get_database(database_name)
        return db[collection_name]
    
    def close(self):
        """Close MongoDB connection"""
        if self._client:
            self._client.close()
            self._client = None
            logger.info("MongoDB connection closed")
    
    def reconnect(self):
        """Reconnect to MongoDB"""
        self.close()
        self._client = self._create_connection()


# Global MongoDB connection instance
mongodb_connection = MongoDBConnection()

class MongoDBLogHandler(logging.Handler):
    """Logging handler that writes logs to a MongoDB collection"""
    def __init__(self, collection_name='app_logs', level=logging.INFO):
        super().__init__(level)
        self.collection_name = collection_name
    
    def emit(self, record: logging.LogRecord):
        try:
            doc = {
                'level': record.levelname,
                'logger': record.name,
                'module': record.module,
                'pathname': record.pathname,
                'funcName': record.funcName,
                'lineno': record.lineno,
                'message': self.format(record),
                'created': record.created,
            }
            collection = mongodb_connection.get_collection(self.collection_name)
            collection.insert_one(doc)
        except Exception as e:
            try:
                logger.debug(f"MongoDBLogHandler emit failed: {str(e)}")
            except Exception:
                pass

