import time
import base64
import random
import pandas as pd
from faker import Faker
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import benchmark_config as config

# --- Setup ---
fake = Faker()

# Mock storage for simulation mode
mock_db_storage = []

class EncryptionManager:
    """Handles Field-Level AES Encryption"""
    def __init__(self, key):
        self.key = key # Key must be 16, 24, or 32 bytes

    def encrypt_value(self, plaintext):
        """Encrypts a single string value using AES-CBC"""
        if not plaintext: return ""
        cipher = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
        # Return IV + Ciphertext encoded in Base64
        return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

    def decrypt_value(self, ciphertext_b64):
        """Decrypts a Base64 encoded string"""
        try:
            raw = base64.b64decode(ciphertext_b64)
            iv = raw[:16]
            ct = raw[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
        except Exception as e:
            return "[Decryption Error]"

def get_db_connection():
    """Connects to MongoDB or returns None in simulation mode"""
    if config.SIMULATION_MODE:
        print(">> SIMULATION MODE ACTIVE: Skipping actual DB connection.")
        return None, None
    try:
        import pymongo
        client = pymongo.MongoClient(config.DB_URI)
        db = client[config.DB_NAME]
        return client, db
    except ImportError:
        print("Error: pymongo not installed. Switch SIMULATION_MODE to True.")
        return None, None

def generate_synthetic_data(num_records):
    """Generates a list of fake user profiles"""
    data = []
    for _ in range(num_records):
        profile = {
            "name": fake.name(),
            "address": fake.address(),
            "email": fake.email(),            # Sensitive
            "ssn": fake.ssn(),                # Sensitive
            "credit_card": fake.credit_card_number(), # Sensitive
            "bio": fake.text(max_nb_chars=50)
        }
        data.append(profile)
    return data

def run_test(encryption_enabled=False):
    """Runs a full ingestion and read test"""
    client, db = get_db_connection()
    collection = None
    
    if not config.SIMULATION_MODE:
        collection = db[config.COLLECTION_NAME]
        collection.drop() # Clear previous data

    crypto = EncryptionManager(config.ENCRYPTION_KEY)
    raw_data = generate_synthetic_data(config.NUM_RECORDS)
    processed_data = []

    # --- MEASURE WRITE / INGESTION ---
    start_time = time.time()
    
    for doc in raw_data:
        new_doc = doc.copy()
        if encryption_enabled:
            # Encrypt only specific fields
            for field in config.SENSITIVE_FIELDS:
                new_doc[field] = crypto.encrypt_value(new_doc[field])
        
        processed_data.append(new_doc)

    if config.SIMULATION_MODE:
        # Simulate network/disk latency
        # Encryption takes CPU time (already real), IO needs faking
        io_penalty = 0.05 if encryption_enabled else 0.02 # Fake overhead
        time.sleep(io_penalty + (config.NUM_RECORDS * 0.0001)) 
    else:
        collection.insert_many(processed_data)

    write_duration = (time.time() - start_time) * 1000 # to ms

    # --- MEASURE READ / QUERY ---
    start_time = time.time()
    
    if config.SIMULATION_MODE:
        # Simulate reading back
        for doc in processed_data:
            if encryption_enabled:
                for field in config.SENSITIVE_FIELDS:
                     _ = crypto.decrypt_value(doc[field])
        time.sleep(0.05) # Fake read latency
    else:
        # Read all documents back
        cursor = collection.find({})
        for doc in cursor:
            if encryption_enabled:
                for field in config.SENSITIVE_FIELDS:
                    _ = crypto.decrypt_value(doc[field])

    read_duration = (time.time() - start_time) * 1000 # to ms

    return write_duration, read_duration

def main():
    print(f"Starting Benchmark (Simulation: {config.SIMULATION_MODE})...")
    print(f"Batch Size: {config.NUM_RECORDS} | Iterations: {config.NUM_ITERATIONS}\n")

    results = {
        "Scenario": [],
        "Write_Latency_ms": [],
        "Read_Latency_ms": []
    }

    # 1. Test Baseline (No Encryption)
    print("Running Baseline Tests (Plaintext)...")
    for i in range(config.NUM_ITERATIONS):
        w, r = run_test(encryption_enabled=False)
        results["Scenario"].append("Plaintext")
        results["Write_Latency_ms"].append(w)
        results["Read_Latency_ms"].append(r)
        print(f"  Iter {i+1}: Write={w:.2f}ms, Read={r:.2f}ms")

    # 2. Test Experimental (AES-256 Encryption)
    print("\nRunning Experimental Tests (AES-256 Encrypted)...")
    for i in range(config.NUM_ITERATIONS):
        w, r = run_test(encryption_enabled=True)
        results["Scenario"].append("AES-256")
        results["Write_Latency_ms"].append(w)
        results["Read_Latency_ms"].append(r)
        print(f"  Iter {i+1}: Write={w:.2f}ms, Read={r:.2f}ms")

    # Export Results
    df = pd.DataFrame(results)
    print("\n--- Summary Results ---")
    print(df.groupby("Scenario").mean())
    
    # Save to CSV for the report
    df.to_csv("benchmark_results.csv", index=False)
    print("\nResults saved to 'benchmark_results.csv'.")

if __name__ == "__main__":
    main()