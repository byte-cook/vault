# Vault.py

Vault.py is an application to store secret data like passwords transparently in an encrypted file. It uses salted AES encryption in GCM mode to protect the data. Vault.py can therefore be used as a command line password manager.

The application intentionally does not offer any options about the encryption used. Strong encryption is used by default. However, the user should take care to choose a strong password. 

If no argument is specified, the interactive mode is started, which allows to edit the encrypted file. 

The editor is line-based, so it is recommended to save only one record per line. For example, user names and passwords should be stored in different lines.

## Install
1. Install Python3 and pip as follows in Ubuntu/Debian Linux:
```
sudo apt install python3.6 python3-pip
```

2. Use pip to install dependencies:

```bash
pip3 install pyperclip
pip3 install pycryptodome
pip3 install gnureadline
```

3. If copy/paste does not work on your system, try to install one of the copy/paste mechansims, e.g.:
```bash
sudo apt-get install xclip
```
See: https://pyperclip.readthedocs.io/en/latest/

## Example usage

### Application parameters
See all options:
```
vault.py -h
```

Import plaintext file to vault:
```
cat <plaintextfile> | vault.py --import <file>
```

Edit encrypted file in interactive mode:
```
vault.py <file>
Enter master password:
Enter your command. Use "-h" to get help.
  > 
```
If the file parameter is missing, the default file is used. If the given file does not exist, a new file will be created.

### Interactive editor mode to edit the file

Unlike other text editors, the entire content of the file is not output. The secret data should remain secret. Instead, the interactive mode can be used to query for the data that is currently needed.

In interactive mode use "-h" to get help:
```
  > -h
  > <command> -h
```

Insert new line at the end:
```
  > i
Type text to insert. Use empty line to exit.
 77 | <input here>
```

Edit line 10 (use option "-c" to get line text in clipboard):
```
  > e -c 10
Type text to edit line. Use RETURN to exit.
 10 | <input here>
```

Output the contents of the entire file ("line" or "l" without parameter print the whole file):
```
  > l
```

Remove first line:
```
  > d 1
```

Search for search term in file and output found line incl. following lines:
```
  > f google
```

Search for search term in file and output found line incl. previous lines:
```
  > f -B 1 -A 0 google
```

Write changes to the file and exit:
```
  > w
  > q
```
```
  > wq
```

Revert changes (read file again):
```
  > r -f
```

Change password of the file and write the file:
```
  > w -p
```

