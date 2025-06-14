import subprocess
import os
import sys

def run_script(script_path):
    """Run a script and handle errors with UTF-8 encoding"""
    try:
        print(f"Running {script_path}...")
        result = subprocess.run(
            [sys.executable, script_path], 
            check=True, 
            capture_output=True, 
            text=True, 
            encoding="utf-8"  # Force UTF-8 encoding
        )
        print(f"Output of {script_path}: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error in {script_path}: {e.stderr}")
        sys.exit(1)

if __name__ == "__main__":
    # Get the absolute path of the scripts directory
    scripts_dir = os.path.abspath(os.path.dirname(__file__))  # Current directory

    # Step 1: Run feature extraction script
    run_script(os.path.join(scripts_dir, 'feature_extraction.py'))

    # Step 2: Run DDoS detection script
    run_script(os.path.join(scripts_dir, 'detect_ddos.py'))

    # Step 3: Run dynamic blocking script
    run_script(os.path.join(scripts_dir, 'dynamic_blocking.py'))

    # Step 4: Send email notification (after all scripts are completed)
    run_script(os.path.join(scripts_dir, 'send_email.py'))

    print("All scripts executed successfully!")
