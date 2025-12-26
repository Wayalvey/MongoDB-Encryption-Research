# Configuration for Database Benchmarking

# Toggle this to TRUE to run without installing MongoDB
# (It will simulate database latency using time.sleep)
SIMULATION_MODE = True 

# Database Settings
DB_URI = "mongodb://localhost:27017/"
DB_NAME = "encryption_benchmark_db"
COLLECTION_NAME = "user_profiles"

# Experiment Settings
NUM_RECORDS = 1000        # Number of records to insert per batch
NUM_ITERATIONS = 5        # How many times to repeat the test
ENCRYPTION_KEY = b'SixteenByteKey!!' # AES-128 or change length for 256
SENSITIVE_FIELDS = ['ssn', 'credit_card', 'email']