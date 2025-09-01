import os
import hashlib
import time
import mimetypes
import csv

def get_file_hash(filepath, hash_algo="sha256"):
    """Generate file hash using given algorithm (sha256 default)."""
    hash_func = getattr(hashlib, hash_algo)()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def analyze_file(filepath):
    """Extract metadata and forensic details of a file."""
    try:
        file_stats = os.stat(filepath)
        metadata = {
            "File Name": os.path.basename(filepath),
            "Absolute Path": os.path.abspath(filepath),
            "Size (Bytes)": file_stats.st_size,
            "Created Time": time.ctime(file_stats.st_ctime),
            "Modified Time": time.ctime(file_stats.st_mtime),
            "Accessed Time": time.ctime(file_stats.st_atime),
            "File Type": mimetypes.guess_type(filepath)[0] or "Unknown",
            "MD5 Hash": get_file_hash(filepath, "md5"),
            "SHA1 Hash": get_file_hash(filepath, "sha1"),
            "SHA256 Hash": get_file_hash(filepath, "sha256")
        }
        return metadata
    except Exception as e:
        return {"error": str(e), "File Name": filepath}

def scan_directory(folder_path, output_csv="forensics_report.csv"):
    """Scan all files in a folder and save results to CSV."""
    results = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            metadata = analyze_file(filepath)
            results.append(metadata)

    # Save results to CSV
    keys = results[0].keys() if results else []
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

    return results, output_csv


if __name__ == "__main__":
    print("=== Digital Forensics File Analyzer ===")
    choice = input("Analyze single file (F) or scan folder (D)? [F/D]: ").strip().upper()

    if choice == "F":
        filepath = input("Enter the file path: ").strip()
        report = analyze_file(filepath)
        print("\n--- Forensic Report ---")
        for key, value in report.items():
            print(f"{key}: {value}")

    elif choice == "D":
        folder = input("Enter folder path to scan: ").strip()
        reports, csv_file = scan_directory(folder)
        print(f"\nScanned {len(reports)} files. Report saved to {csv_file}")

    else:
        print("Invalid option! Please choose F or D.")
