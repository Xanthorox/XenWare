# XenWare

high-impact ransomware designed for speed, deep system penetration, and cryptographically secure file locking, making recovery without the operator's unique private key computationally infeasible.

# How it Works:

It initializes by importing a master RSA-4096 public key. It gathers victim identifiers (Computer Name, IP, Location), generates a unique Victim ID, and immediately starts aggressive, multithreaded operations. Separate threads scan all accessible drives (Fixed, Network, Removable, excluding only CD-ROMs), skipping only the core Windows system directory, recycle bin, and its own log/readme files. It queues every other file type it finds. Worker threads pull files from this queue, performing the core encryption:

A unique AES-256 key is generated for the target file.

The file's content is encrypted using this unique AES key.

The unique AES key itself is then encrypted using the master RSA-4096 public key.

The encrypted file is saved with the .xanthorox extension (which is obfuscated in the code), containing the RSA-encrypted AES key followed by the AES-encrypted data.

The original file is deleted.
After all scanning and encryption threads complete, it changes the desktop wallpaper. Crucially, it then sends a notification via a configured Telegram bot, exfiltrating the victim's identifiers (Computer Name, IP, Location, Victim ID) and the total count of successfully encrypted files directly to the operator.


# Why it's Different:

Unlike ransomware using simpler methods, Xanthorox's per-file AES-256 key encrypted by a master RSA-4096 key makes brute-forcing or universal decryption impossible without the attacker's private key. Its aggressive multithreading aims for rapid encryption across multiple drives simultaneously, and its minimal exclusion list targets a vast range of files, including application data and user files outside standard libraries, maximizing disruption. The integrated Telegram bot notification provides immediate, remote confirmation of successful infection and key victim details to the operator. The extension obfuscation adds a layer against trivial modification.

# How its Built ?
it did not build the file with first prompt it took me several hour to make it and fixing it , i did not touched a single code The AI did everything 

Note = Full Prompt not showed for privacy 

https://github.com/user-attachments/assets/9366428c-aeba-48e8-8d30-37097087cb75

# How to Build And How to Use 

First place all the files in a one directory on a linux enviromnent 
![picture one](https://github.com/user-attachments/assets/6e0a1609-d53a-4912-8eb3-cffa6324a900)

Then Run the Build Bash script "bash builder_xanthorox" it will genereate some bytes out of your Key files 

then open another terminal and edit the main main cpp file and place yur bytes on this place

https://github.com/user-attachments/assets/d78a04c2-fc2d-4dfa-8fbe-3e7f24e3650b

Then hit enter and it will build your exe

https://github.com/user-attachments/assets/827a13eb-359f-4507-9f3a-ee180c4912ed

# How Xenware looks like on Action Bypassing defender

https://github.com/user-attachments/assets/5f4925da-5bd1-4ae3-8f36-632287ea1b69





