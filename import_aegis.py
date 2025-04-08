import argparse
import csv
import getpass
import os
import random
import subprocess
from decrypt_aegis import decrypt_aegis_vault

INPUT_LIST_FILE = "input_list.txt"
MAX_ENTRIES = 50


def fix_base32_padding(base32_str):
    # Check if padding is needed
    if len(base32_str) % 8 != 0:
        # Add necessary padding
        base32_str = base32_str.rstrip("=") + "=" * ((8 - len(base32_str) % 8) % 8)
    return base32_str


def main():
    parser = argparse.ArgumentParser(description="Decrypt Aegis vault file")
    parser.add_argument("input_file", type=str, help="Path to the input file")

    args = parser.parse_args()

    if args.input_file is None:
        print("ERROR: Input file required")
        return

    # ask the user for a password
    password = getpass.getpass().encode("utf-8")

    # decrypt the Aegis vault file
    try:
        db = decrypt_aegis_vault(args.input_file, password)
    except Exception as e:
        print(f"ERROR: {e}")
        return

    failed_entries = []
    added_entries = []

    entries = db.get("entries", [])

    while True:
        if os.path.exists(INPUT_LIST_FILE):
            with open(INPUT_LIST_FILE, "r", encoding="utf-8") as f:
                csv_reader = csv.reader(f)
                # Get indexes of entries to include
                indexes = []
                for row in csv_reader:
                    if row[0].isdigit():
                        indexes.append(int(row[0]))
                entries = [entries[i] for i in indexes]
                print(f"Selected {len(entries)} entries from {INPUT_LIST_FILE}.")

        if len(entries) > MAX_ENTRIES:
            print(
                f"WARNING: More than {MAX_ENTRIES} entries found. Please choose which ones to include."
            )
            with open(INPUT_LIST_FILE, "w", encoding="utf-8") as f:
                csv_writer = csv.writer(f)
                csv_writer.writerow(["Index", "Issuer", "Name"])
                for i, entry in enumerate(entries):
                    name = entry.get("name")
                    issuer = entry.get("issuer")
                    csv_writer.writerow([i, issuer, name])

            print(f"Entries written to {INPUT_LIST_FILE}.")
            print(
                f"Please edit the file to include only rows with desired entries. (max {MAX_ENTRIES})"
            )
            input("Press Enter to continue after editing the file...")
        else:
            break

    print(f"Removing temporary file {INPUT_LIST_FILE}...")
    if os.path.exists(INPUT_LIST_FILE):
        os.remove(INPUT_LIST_FILE)

    for entry in entries:
        name = entry.get("name")
        issuer = entry.get("issuer")
        totp_info = entry.get("info")
        secret = totp_info.get("secret")
        algorithm = totp_info.get("algo")
        digits = totp_info.get("digits")

        try:
            entry_name = f"{issuer}_{name}"
            if entry_name in added_entries:
                entry_name = f"{issuer}_{name}_{hex(random.getrandbits(32))}"
            subprocess.run(
                [
                    "nitropy",
                    "nk3",
                    "secrets",
                    "add-otp",
                    entry_name,
                    fix_base32_padding(secret),  # nitropy requires correct padding
                    "--digits-str",
                    str(digits),
                    "--hash",
                    algorithm,
                    "--kind",
                    "TOTP",
                ],
                check=True,
            )
            added_entries.append(entry_name)
        except Exception as e:
            print(f"ERROR: Failed to add OTP entry: {e}")
            failed_entries.append((issuer, name))
            continue
        print(f"Added OTP entry: {issuer}_{name}")

    if failed_entries:
        print("Failed to add the following entries:")
        for issuer, name in failed_entries:
            print(f"  - {issuer}_{name}")
    if len(added_entries) > 0:
        print(f"Successfully added {len(added_entries)} entries to Nitrokey.")
        print("Successfully added the following entries:")
        for entry in added_entries:
            print(f"  - {entry}")


if __name__ == "__main__":
    main()
