# Binary-Translator by Jimmy Luong  

This product is designed to securely store your files and passwords.  

---

## Terms of Use  

Date: 27.04.2024  

1. You are not allowed to open the program with other software.  
2. The Python script must not be converted into other formats.  
3. Modifying the file is prohibited.  
4. No warranty is provided for your data. You use this program at your own risk.  
5. If you close the program before it finishes running, files in the locker folder may become corrupted and irrecoverable.  
6. For your data's safety, encryption will not occur if the `priv.key` is missing.  

---

## How to Check Your Version  

Run `locker.py` and use the command:  
--version


---

## How to Create the Keys  

1. Run `gen_key.py`.  
2. Enter the desired length for the keys.  
3. Two keys and a key length value will be generated. Save these securely (e.g., on a drive or email account).  
4. After generating each key, press `Windows + R`, type `taskmgr.exe`, and terminate any high CPU processes for `locker.py` if it doesn't stop automatically.  

---

## Recommended Key Length  

- Choose any positive whole number.  
- For high security, opt for a larger number.  
- Be cautious: lengths over 20,000 may result in long wait times for key generation and encryption processes.  

---

## Product Description  

**Product 1**: Securely lock your files or passwords in a folder named `locker`.  

### How to Lock Your Data  

1. Run `locker.py`. A folder named `locker` will be created.  
2. Place your files in the folder.  
3. Run `locker.py` again to lock the folder (do not close the program prematurely).  
4. Once locked, the folder becomes invisible.  
5. Locate the generated `priv.key` file and store it securely.  
6. Save your key number in a safe location and remove it from the Terms of Use.  

### How to Unlock Your Data  

1. Place the `priv.key` file in the same directory as `locker.py`.  
2. Run `locker.py`. Wait for the program to finish. Your folder will reappear with your files.  

### How It Works  

- The program uses an RSA key to loosely encrypt the `locker` folder.  
- The folder is then hidden as an added security measure.  
- You can access the hidden folder by navigating to its directory (e.g., `\locker`).  
- During decryption, the `priv.key` is used to unlock the folder.  

---

## Troubleshooting  

**Corrupted Files After Decryption**  
1. Place the corrupted file (e.g., `filename.filetype+enc`) in the same directory as `locker.py`.  
2. Run `locker.py` to encrypt the files again.  
3. Example: If your folder is in this directory:  C:\Users(Your username)\OneDrive\Desktop\locker
4. Then place the corrupted file in: C:\Users(Your username)\OneDrive\Desktop\locker\locker

 Run `locker.py` to decrypt the files.  

---

## Warnings  

1. Once you delete the key, your data is almost impossible to recover.  
2. If you execute the program in `C:\`, your Windows system may get encrypted, resulting in irrecoverable data loss.  

---

## How Safe Is This Method?  

This method is very safe, comparable to BitLocker.  
- While BitLocker uses 128-bit encryption, this program uses custom x-bit encryption.  
- However, if you lose `locker.py` or `priv.key`, recovery becomes impossible.  
- Save both the script and your key securely.  

---

## Contact  

For more information or questions, please contact:  
**nguyenhungjimmy.luong@yahoo.com**  


