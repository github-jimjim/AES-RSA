This are a product from Jimmy Luong. You must accept the Terms of Use: 27.04.2024
	1. You aren´t allowed to open the program with other programs.
	2. The executable file must not be converted to other files.
	3. You aren´t allowed to modify the file.
	4. We have no warranty on your datas. You are using this on your own risk.
	5. If you close the file before the window closes automatically, your files in the locker folder may get damaged and unrescueable.
	6. for the safety of your datas the datas won't get encrypted if the priv.key is missing. 

To check your version, open locker.exe and write --version

How to create the keys?
	1. Open gen_key.exe
	2. Enter the lenght of the keys
	2. You will get two keys and a key_lenght
	3. Save them in a drive or email account or somewhere else.
	5. After each key - creation press Windows + R and type taskmgr.exe
	6. Look at the highest CPU and turn the locker.exe out because the programm sometimes doesn't stop from alone.

Which lenght should I choose?
You can choose between each positive full number
If your files should be very safe you should choose a high number but as long as the numbers are, the longer you have to wait till the progress finish.
If you choose 65536 you have to dividide your number with 8. So 85536/8 is 8192. So you have a 8192 - bit encryption.
Numbers over 20000 aren't recommended if the datas aren't too important, because it can take hours to generate the key and hours to encrypt and decrypt the locker. If you really need fully security, there is a faster package on https://jimmy1205.neocities.org/faster_locker_version. But remember this version is created by nuitka a C compiler and it can get detected as a virus.

Product 1:
    This Product is to save your files or passwords in a folder with the name locker. (filename: locker.exe)
    How to lock your datas?
            1. Open locker.exe and wait, a folder named locker will be created.
            2. Then open the folder and put your vailbale informations in there.
            3. Close the folder and lock the folder by opening the .exe again, but don't close the window. It needs some time.
            4. If it had worked, the folder locker would have been invisible now.
            5. In this directory you can see a file named priv.key. Save it in another directory or somewhere safe.
            6. Save your key number somewhere safe and delete the key number out of the Terms of Use.

    How do you unlock your datas:
            1. Get your priv.key in the same directory and open the locker.exe
            2. Wait till the Window close and you will see the folder with your datas.

    How does this works?
    The locker.exe loosely encrypts this folder with an RSA key. The folder will then be hidden as an additional security measure. You can find the hidden hidden folder again by directory name + \locker. When decrypting, the priv.key is read and used for encryption


Problem fixes:
    1. If any of your files are corrupted after decryption (filename.filetype+enc), you need to put the file in the same directory as the .exe and encrypt the files. Let's assume the 		folder is in this directory: 
        C:\Users\(Your username)\OneDrive\Desktop\locker
        then you need to add a locker:
        C:\Users\(Your username)\OneDrive\Desktop\locker\locker.
        Put the damaged file in the locker with the other encrypted files and decrypt the files again.
    2. If you had lost your key, than no problem. Send an email to nguyenhungjimmy.luong@gmail.com and write:
        I lost my unlock key. The key number is: "insert your key number"


Warnings:
Once you delete the key, all of your data is almost impossible to recoverable. You can try to find out the source code and the key used to encrypt the files, but the key can only encrypt and not decrypt. The key is also almost impossible even if you know the encryption key.
If you execute your file here: C:\, Windows will get encrypted and that isn't good. Then all your datas will be unrecoverable.

How safe is this method?
    This method is very safe. It is like the Bitlocker just I would say it is safer, because Bitlocker is using a 128 - Bit encryption meanwhile this programms are using a x - Bit encryptions.
    But the advantage of Bitlocker is you can't lose the method of decryption, because if you loose locker.exe or saver.exe your files are imossible to recover. So a tip save locker.exe or saver.exe too.
    And you can create your "priv.key" with bitlocker but here you have to use the priv.key.

For more Information or questions, please contact nguyenhungjimmy.luong@yahoo.com
