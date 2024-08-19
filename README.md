# Password-Manager
This is a local encrypted password manager that I created to be extremely efficient and fast with autocorrect based on the account you want.

This is a two script package for efficiency.
The adder script allows you to add and remove passwords from the encrypted text file.
The crimson script allows you to view and retrieve passwords to your clipboard from the encrypted text file.

The reason two scripts are used and they are not merged into one is due to efficiency as one more button press to select the option you want takes extra time.

To configure the text file and file path edit the FILE_PATH in the files.

To turn these into applications, install `pyinstaller` and run the `pyinstaller --onefile \path\to\script.py`
