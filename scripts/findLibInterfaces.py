import subprocess
import sys
import os

def get_symbols(file_path, symbol_type, mode):
    if mode == "bc":
        command = f"llvm-nm-12 --{symbol_type}-only {file_path}"
    elif mode == "obj":
        command = f"nm --{symbol_type}-only {file_path}"
    else:
        print(f"Error: Invalid mode '{mode}'. Supported modes are 'bc' and 'obj'.")
        sys.exit(1)

    output = subprocess.check_output(command, shell=True, universal_newlines=True)
    symbols = set(line.split()[-1] for line in output.splitlines())
    return symbols

def main(core_app_file, lib_file, mode):
    # Check if the provided paths exist
    if not os.path.exists(core_app_file):
        print(f"Error: {core_app_file} does not exist.")
        sys.exit(1)
    if not os.path.exists(lib_file):
        print(f"Error: {lib_file} does not exist.")
        sys.exit(1)

    # Get the external symbols from the core application
    extern_symbols = get_symbols(core_app_file, "extern", mode)

    # Get the defined symbols from the target library
    defined_symbols = get_symbols(lib_file, "defined", mode)

    # Find the intersection of the two sets of symbols
    intersection = extern_symbols.intersection(defined_symbols)

    # Output the intersection
    print("Intersection of symbols:")
    for symbol in intersection:
        print(symbol)

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[3] not in ["bc", "obj"]:
        print("Usage: python script.py <core_app_file_path> <lib_file_path> <mode>")
        print("Supported modes: 'bc' (bitcode files) or 'obj' (object files)")
        sys.exit(1)

    core_app_file = sys.argv[1]
    lib_file = sys.argv[2]
    mode = sys.argv[3]
    main(core_app_file, lib_file, mode)
