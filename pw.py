#! python3
# pw.py - An insecure password locker program.

import sys, pyperclip, os, json

# JSON file with passwords
DATA_FILE = r'...\Password_Locker\pw_data.json'

# Check for json file if exist and load stored passwords
with open(DATA_FILE,'r') as f:
    #load JSON into a Python dictionary.
    passwords=json.load(f)

# This is a helper function to save the passwords dictionary back into pw_data.json.
def save_passwords():
    with open(DATA_FILE, "w") as f:
        json.dump(passwords, f, indent=4)


if len(sys.argv) < 2:
    print("Usage:")
    print("  pw [account]           -> copy password to clipboard")
    print("  pw add [account] [pwd] -> add new account password")
    print("  pw del [account]       -> delete an account")
    print("\nAccounts Available:")
    for account in sorted(passwords.keys()):
        print(f" - {account}")
    sys.exit()


command = sys.argv[1].lower()

if command=='show':
    if len(sys.argv) !=2:
        print(f'Usage: pw show')
    else:
        print("\nAccounts Available:")
        for account in sorted(passwords.keys()):
            print(f"- {account}")
        sys.exit()

elif command=='add':
    if len(sys.argv) !=4:
        print("Usage: pw add [account] [password]")
        sys.exit()
    account, pwd = sys.argv[2].lower(), sys.argv[3].lower()
    passwords[account]=pwd
    save_passwords()
    print(f'Password Added/Updated for: {account}')

elif command=='del':
    if len(sys.argv) !=3:
        print(f'Usage: pw delete [account]')
        sys.exit()
    account=sys.argv[2].lower()
    if account in passwords:
        del passwords[account]
        save_passwords()
        print(f'Deleted: {account}')
    else:
        print(f'No data for {account}')

else:
    account=command
    if account in passwords:
        pyperclip.copy(passwords[account])
        print(f'Password for {account} is copied to clipboard')
    else:
        print(f'There is no data for {account} in data')
