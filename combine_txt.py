import os
from tqdm import tqdm

def is_ascii(s):
    """Check if all characters in the string are ASCII."""
    return all(ord(c) < 128 for c in s)

def combine_txt_files(start_dir, output_file):
    # First, collect all txt files to determine the total progress.
    txt_files = []
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.endswith('.txt'):
                txt_files.append(os.path.join(root, file))
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        # Iterate over the list of txt files with a progress bar.
        for file_path in tqdm(txt_files, desc="Combining files"):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as infile:
                    contents = infile.read()
                    # Filter out non-ASCII characters
                    ascii_contents = ''.join(filter(is_ascii, contents))
                    outfile.write(ascii_contents + '\n')
            except Exception as e:
                print(f"Error reading {file_path}: {e}")

# Usage
start_directory = '/Users/dianziji/Downloads/SecLists-master'  # Your specified starting directory
output_file_path = '/Users/dianziji/Downloads/combined_output.txt'  # Desired output file path
combine_txt_files(start_directory, output_file_path)