"""
ml/jsonl_loader.py  —  RX-MORTEM v2 JSONL Dataset Loader

Loads JSONL files from Win64_train and Win64_test directories.
Extracts features needed for model training:
  - file_size: from general.size
  - entropy: from general.entropy
  - num_sections: from header.coff.number_of_sections
  - imports_count: count of imports from header.imports
  - suspicious_strings_count: from strings.string_counts
  - label: 0=benign, 1=malware
"""

import json
import os
import glob
import numpy as np
from typing import Tuple, List


def extract_features_from_jsonl_record(record: dict) -> dict:
    """
    Extract required features from a single JSONL record.
    Returns a dict with keys: file_size, entropy, num_sections, 
                              imports_count, suspicious_strings_count, label
    Returns None if extraction fails.
    """
    try:
        # Extract file_size
        file_size = float(record.get("general", {}).get("size", 0))
        
        # Extract entropy
        entropy = float(record.get("general", {}).get("entropy", 0.0))
        
        # Extract num_sections
        num_sections = float(record.get("header", {}).get("coff", {}).get("number_of_sections", 0))
        
        # Extract imports_count (sum across all imported DLLs)
        imports_dict = record.get("imports", {})
        imports_count = 0
        if isinstance(imports_dict, dict):
            for dll_imports in imports_dict.values():
                if isinstance(dll_imports, list):
                    imports_count += len(dll_imports)
        imports_count = float(imports_count)
        
        # Extract suspicious_strings_count
        strings_info = record.get("strings", {})
        string_counts = strings_info.get("string_counts", {})
        suspicious_strings_count = float(len(string_counts))
        
        # Extract label
        label = int(record.get("label", 0))
        
        return {
            "file_size": file_size,
            "entropy": entropy,
            "num_sections": num_sections,
            "imports_count": imports_count,
            "suspicious_strings_count": suspicious_strings_count,
            "label": label,
        }
    except (KeyError, ValueError, TypeError):
        return None


def load_jsonl_files(directory: str) -> Tuple[np.ndarray, np.ndarray, int]:
    """
    Load all JSONL files from a directory.
    
    Args:
        directory: Path to directory containing JSONL files
        
    Returns:
        Tuple of (features_array, labels_array, total_records_processed)
        - features_array: Shape (N, 5) with columns [file_size, entropy, num_sections, imports_count, suspicious_strings_count]
        - labels_array: Shape (N,) with binary labels
        - total_records: Count of records successfully extracted
    """
    if not os.path.exists(directory):
        return np.array([]), np.array([]), 0
    
    features_list = []
    labels_list = []
    total_records = 0
    
    # Find all JSONL files in the directory
    jsonl_files = glob.glob(os.path.join(directory, "*.jsonl"))
    
    if not jsonl_files:
        print(f"[WARNING] No JSONL files found in {directory}")
        return np.array([]), np.array([]), 0
    
    print(f"[*] Found {len(jsonl_files)} JSONL files in {directory}")
    
    for jsonl_file in sorted(jsonl_files):
        file_size = os.path.getsize(jsonl_file) / (1024 * 1024)  # Size in MB
        print(f"  [*] Loading {os.path.basename(jsonl_file)} ({file_size:.1f} MB)")
        
        try:
            with open(jsonl_file, 'r', encoding='utf-8') as fh:
                for line_num, line in enumerate(fh, 1):
                    if not line.strip():
                        continue
                    
                    try:
                        record = json.loads(line)
                        total_records += 1
                        
                        features = extract_features_from_jsonl_record(record)
                        if features is not None:
                            features_list.append([
                                features["file_size"],
                                features["entropy"],
                                features["num_sections"],
                                features["imports_count"],
                                features["suspicious_strings_count"],
                            ])
                            labels_list.append(features["label"])
                        
                        if line_num % 1000 == 0:
                            print(f"      Processed {line_num} records...")
                    
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            print(f"  [!] Error reading {os.path.basename(jsonl_file)}: {e}")
            continue
    
    if not features_list:
        print(f"[WARNING] No valid records extracted from {directory}")
        return np.array([]), np.array([]), total_records
    
    features_array = np.array(features_list, dtype=np.float32)
    labels_array = np.array(labels_list, dtype=np.int32)
    
    print(f"  [*] Loaded {len(features_list)} records (skipped {total_records - len(features_list)} invalid)")
    
    return features_array, labels_array, total_records


def load_combined_jsonl_datasets(train_dir: str, test_dir: str) -> Tuple:
    """
    Load both training and test JSONL datasets.
    
    Returns:
        Tuple of (X_train, y_train, X_test, y_test)
    """
    print("\n[*] Loading JSONL Training Dataset:")
    X_train, y_train, _ = load_jsonl_files(train_dir)
    
    print("\n[*] Loading JSONL Test Dataset:")
    X_test, y_test, _ = load_jsonl_files(test_dir)
    
    if len(X_train) == 0:
        raise ValueError(f"No valid training data found in {train_dir}")
    
    if len(X_test) == 0:
        raise ValueError(f"No valid test data found in {test_dir}")
    
    return X_train, y_train, X_test, y_test
