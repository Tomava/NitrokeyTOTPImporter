import argparse
import getpass
import random
import subprocess

from decrypt_aegis import decrypt_aegis_vault


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

    for entry in db.get("entries", []):
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
                    secret,
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


if __name__ == "__main__":
    main()
