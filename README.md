# Nitrokey TOTP Importer

This script will import an Aegis TOTP vault into Nitrokey.

## Requirements

- Nitrokey 3
- Python 3.8 or higher
- pip

## Install the required packages

### Create a virtual environment (optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### Install the required packages

```bash
pip install -r requirements.txt
```

## Usage

### Run the script

Note: Insert the Nitrokey before running the script

```bash
# Run the script without removing old entries
python import_aegis.py <path_to_aegis_vault_file>

# Reset the existing Nitrokey and run the script (WARNING: this will remove everything from the Nitrokey)
python import_aegis.py <path_to_aegis_vault_file> --reset
```

## Limitations

- The script currently only supports Nitrokey 3.
- As of writing this, the Nitrokey 3 only supports a maximum of 50 entries.
