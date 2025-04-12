import argparse
import csv
import getpass
import os
import random
import subprocess
import pyotp
from decrypt_aegis import decrypt_aegis_vault


INPUT_LIST_FILE = "input_list.csv"
MAX_ENTRIES = 50


def fix_base32_padding(base32_str: str) -> str:
    # Check if padding is needed
    if len(base32_str) % 8 != 0:
        # Add necessary padding
        base32_str = base32_str.rstrip("=") + "=" * ((8 - len(base32_str) % 8) % 8)
    return base32_str


def read_entries_from_file(file_path: str, old_entries: list) -> list:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            csv_reader = csv.DictReader(f, delimiter=",")
            # Get entries to include
            new_entries = []
            for row in csv_reader:
                # Search from old entries with issuer and name
                for entry in old_entries:
                    if (
                        entry.get("issuer") == row["issuer"]
                        and entry.get("name") == row["name"]
                    ):
                        new_entries.append(entry)
            print(f"Selected {len(new_entries)} entries from {file_path}.")
    except FileNotFoundError:
        print(f"ERROR: File {file_path} not found.")
    return new_entries


def write_entries_to_file(file_path: str, entries: list) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        csv_writer = csv.writer(f, delimiter=",")
        csv_writer.writerow(["issuer", "name"])
        for entry in entries:
            issuer = entry.get("issuer")
            name = entry.get("name")
            csv_writer.writerow([issuer, name])
    print(f"Entries written to {file_path}.")


def verify_entries(entries: list) -> list:
    failed_entries = []
    for entry in entries:
        try:
            entry_name = entry.get("entry_name")
            output = subprocess.run(
                ["nitropy", "nk3", "secrets", "get-otp", entry_name],
                check=True,
                stdout=subprocess.PIPE,
            )
            # Read output and get the last row and compare to generated OTP
            output_lines = output.stdout.decode("utf-8").strip().split("\n")
            if len(output_lines) > 0:
                nitrokey_code = output_lines[-1].strip()
                totp = pyotp.TOTP(entry.get("info").get("secret"))
                if totp.verify(nitrokey_code):
                    print(f"SUCCESS: OTP entry {entry_name} verified successfully.")
                else:
                    print(f"ERROR: OTP entry {entry_name} verification failed.")
                    failed_entries.append(entry)
            else:
                print(f"ERROR: No output for OTP entry {entry_name}.")
                failed_entries.append(entry)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Failed to verify OTP entry {entry_name}: {e}")
            failed_entries.append(entry)
    return failed_entries


def get_existing_entries_amount() -> int:
    print("Checking existing entries...")
    try:
        output = subprocess.run(
            ["nitropy", "nk3", "secrets", "list"],
            check=True,
            stdout=subprocess.PIPE,
        )
        output_lines = output.stdout.decode("utf-8").strip().split("\n")
        print(f"Found {len(output_lines)} existing entries.")
        return len(output_lines)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to list existing entries: {e}")
        return 0


def main():
    parser = argparse.ArgumentParser(description="Decrypt Aegis vault file")
    parser.add_argument("input_file", type=str, help="Path to the input file")
    parser.add_argument(
        "--reset",
        action=argparse.BooleanOptionalAction,
        help="Reset the nitrokey before adding entries. Use with caution!",
    )

    args = parser.parse_args()

    if args.input_file is None:
        print("ERROR: Input file required")
        return

    if args.reset:
        user_verification = input(
            "NOTICE: This will RESET ALL THE CONTENT in the Nitrokey. Type 'yes' to continue: "
        )
        if user_verification.lower() != "yes":
            print("Aborting...")
            return
        else:
            print("Resetting Nitrokey...")
            subprocess.run(["nitropy", "nk3", "secrets", "reset"], check=True)
            print("Nitrokey reset complete.")
            print()

    existing_amount = get_existing_entries_amount()
    max_amount = MAX_ENTRIES - existing_amount
    if max_amount <= 0:
        print("ERROR: No space left for new entries.")
        return

    # ask the user for a password
    password = getpass.getpass("Aegis vault password: ").encode("utf-8")

    # decrypt the Aegis vault file
    try:
        db = decrypt_aegis_vault(args.input_file, password)
    except Exception as e:
        print(f"ERROR: {e}")
        return

    if db is None:
        print("ERROR: Unable to decrypt the vault.")
        return

    failed_entries = []
    added_entries = []

    entries = db.get("entries", [])

    while True:
        if os.path.exists(INPUT_LIST_FILE):
            entries = read_entries_from_file(INPUT_LIST_FILE, entries)

        if len(entries) > max_amount:
            print(
                f"WARNING: More than {max_amount} entries found. Please choose which ones to include."
            )
            write_entries_to_file(INPUT_LIST_FILE, entries)
            print(
                f"Please edit the file to include only rows with desired entries. (max {max_amount}). DO NOT EDIT THE HEADER ROW!"
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
            entry["entry_name"] = entry_name
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
            added_entries.append(entry)
        except Exception as e:
            print(f"ERROR: Failed to add OTP entry: {e}")
            failed_entries.append(entry)
            continue
        print(f"Added OTP entry: {issuer}_{name}")

    print("Verifying added entries...")
    failed_to_verify_entries = verify_entries(added_entries)

    if failed_entries:
        print("Failed to add the following entries:")
        for entry in failed_entries:
            print(f"  - {entry.get("entry_name")}")
    if failed_to_verify_entries:
        print("Failed to verify the following entries:")
        for entry in failed_to_verify_entries:
            print(f"  - {entry.get("entry_name")}")
    if len(added_entries) > 0:
        print(f"Added {len(added_entries)} entries to Nitrokey.")
        print("Added the following entries:")
        for entry in added_entries:
            verification_failed = entry in failed_to_verify_entries
            output = (
                f"  - {entry.get("entry_name")} (verification failed)"
                if verification_failed
                else f"  - {entry.get("entry_name")}"
            )
            print(output)


if __name__ == "__main__":
    main()
