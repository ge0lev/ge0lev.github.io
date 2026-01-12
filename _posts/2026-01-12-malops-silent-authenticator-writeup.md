---
title: "Malops - Silent Authenticator Writeup"
date: 2026-01-12
categories: [malware,reversing,writeups]
tags: [linux,backdoor,malops]
image: 
  path: /assets/img/malops-silent-authenticator/feature-image.png
---


Challenge URL: [https://malops.io/challenges/silent-authenticator](link:https://malops.io/challenges/silent-authenticator)

#### Malops Tags : 
linux | backdoor 

---

#### Scenario:

A financial institution detected unusual SSH access patterns across multiple servers. Legitimate users were logging in at odd hours, yet security logs showed no anomalies. An incident responder discovered a modified PAM module on one of the compromised servers. Your task: Analyze this malicious PAM module to understand how attackers maintained persistent access and exfiltrated credentials. Uncover all backdoor capabilities and document the threat actor's techniques.

---

#### Question 1:
The malware hides sensitive strings using encryption. By analysing the decryption function, what is the single-byte XOR key stored at offset 0x00 in each encrypted string table entry?

* Hint: Examine the first byte at offset 0x00 in the structure at address tends with 0xC040.
* No idea what is the reason to go to that location, but going there (segment data.rel.o gives us the answer ***0x54***)

![](/assets/img/malops-silent-authenticator/encrypted-string-indexes.png)

#### Question 2:
The decryption function calculates the table entry offset by shifting the index. What is the shift value used in the 'shl' instruction to multiply the index by the entry size?
* By going to the XREF function of the .data.rel.ro structure of Question 1, we find the following code segment:

![](/assets/img/malops-silent-authenticator/decryption-function.png) 

* And on 0x032AA we can see the instruction ***shl rdi, 4*** , which gives us our answer "4".

#### Question 3:
Each encrypted string entry contains a pointer to the actual encrypted data. At what byte offset within the 16-byte entry structure is this pointer located?
* We can see that each offset occurs 8 bytes after the "54h" XOR key at offset 0x00. So, the byte offset for each pointer is ***8***.
  
#### Question 4:
The string length field is stored as a 16-bit value within each entry. At what byte offset is the length field located in the entry structure?
* Going back to the structure , we can see that 3 bytes after the XOR key is declared ,there are bytes indicating the length of the string

![](/assets/img/malops-silent-authenticator/encrypted-string-indexes.png)

* This leads us to the answer of the question, which is the number ***0x02 (decimal: 2)*** (since the offsets start at 0x00)

#### Question 5:
Analysing the encrypted strings table, how many total encrypted string entries does the malware store?
* By counting the number of the pointers on the structure , we are lead to the answer ( ***7*** )

#### Question 6:
The first encrypted byte of the backdoor password. What is this encrypted byte value?
* By visiting the highlighted offset

![](/assets/img/malops-silent-authenticator/index0.png)

  we are led to

![](/assets/img/malops-silent-authenticator/index0-encrypted.png)

  giving us the answer to the question, ***6D***.

#### Question 7:
what is the hardcoded master password that bypasses authentication for any user?
* Using python , we can create the following one-liner that does the Rolling XOR to decrypt the string
* `decrypted =  bytes(bytes.fromhex("6D62161E671E17321A776B3E616B")[i] ^ 0x54 ^ i for i in range(len(bytes.fromhex("6D62161E671E17321A776B3E616B"))))` 
  The above one-liner returns the string ***97@I7OEaF\*5a92***
  
#### Question 8:
What libc function does the malware call to compare the user-supplied password against the decrypted backdoor password?
* By checking the Imported functions we see the libc function ***strcmp*** , which is used to compare two strings.

#### Question 9:
Before checking the backdoor password, the malware retrieves the username using a PAM API function. What is the name of this function?
* Scrolling through the function , we see the call to the PAM API function ***pam_get_user***

![](/assets/img/malops-silent-authenticator/pam_get_user.png)

#### Question 10:
After decrypting string index 2, what is the full file path where the malware stores harvested credentials?
* By using the python one-liner of Question 7 for the encrypted string ***7B2025257F333B3D73733A3D2D2A74372B22*** , we get the decrypted string ***/usr/bin/.dbus.log***

#### Question 11:
Before writing credentials, the malware encodes them as hexadecimal. What sprintf format specifier is used for this hex encoding?
* By checking the XREFs of the sprintf function, we encounter the following call

![](/assets/img/malops-silent-authenticator/sprintf-call.png)

  in which we can see on the offset 0x003797 that the string ***%2X*** is passed to the sprintf function.

#### Question 12:
The credential log uses a specific format string for entries. What is the prefix text that appears before the encoded username in each log entry?
* Scrolling further down after the sprintf call , we encounter the following

![](/assets/img/malops-silent-authenticator/prefix-text.png)

  which indicates that the format string for the log entries is "***error ServiceUnknown->***"

#### Question 13:
What separator string appears between the encoded username and encoded password in the log format?
* Examining the string of Question 12 , we can see that the separator string between the variables denoted by *%s* is "***:***"

#### Question 14:
When opening the credential log for writing new entries, what fopen mode string is used?
* On the screenshot taken for Question 12 , we can see the call to fopen(). At offset 0x003937 we see that the mode provided to fopen() is "***a***"

#### Question 15:
After decrypting string index 3, what is the full path to the legitimate file used as a timestamp reference?
* Decrypting the string gives us "***/usr/bin/id /usr/bin/.db***"

#### Question 16:
After decrypting string index 4, what Unix command is used to copy the timestamp from the reference file? (First word only)
* Decrypting the string index 4 , we get the string "touch -r /usr/bin/id /usr/bin/.dbus.logs". The command is ***touch***

#### Question 17:
The timestamp manipulation command uses what flag to reference another file's timestamp?
* The flag used on the touch command is ***-r***.

#### Question 18:
what is the full path to the hidden directory where the malware looks for scripts to execute?
* By decrypting the string on the index 1 , we get the plaintext ***/var/spool/.network/***

#### Question 19:
What libc function is called to open the hidden directory for reading its contents?
* The function ***opendir*** is used to open the directory , at offset 0x003603

#### Question 20:
What libc function is called in a loop to iterate through each file in the hidden directory?
* Looking at the pseudocode of the function , we can see that during the opendir() loop , the function ***readdir()*** is used inside the loop

![](/assets/img/malops-silent-authenticator/readdir-loop.png)

#### Question 21:
The malware checks the d_type field to identify regular files. What decimal value indicates a regular file (DT_REG)?
* Using the screenshot on Question 20, we can see the condition ***v12->d_type == 8***, which indicates a regular file.

#### Question 22:
After decrypting string index 5, what Unix utility is prepended to commands to run them detached from the terminal?
* The decrypted string at index 5 gives us the command ***nohup*** , which allows an executed command to ignore the hang up signal and continue executing  after exiting the shell or the terminal.
  Note that IDA had incorrectly parsed the string at index5

![](/assets/img/malops-silent-authenticator/index5-wrong-definition.png)

  which could be misleading. We can undo the parsing by clicking on the line and pressing the "u" key which undefines the array to it's bytes form

![](/assets/img/malops-silent-authenticator/index5-undefined.png)

#### Question 23:
After decrypting string index 6, what is the full output redirection string appended to executed commands?
* The decrypted command for redirection is ***>/dev/null 2>&1 &***
  
#### Question 24:
What libc function is used to execute the constructed command string containing nohup and the script path?
* We can see on the following screenshot of the pseudocode that the libc function is ***system***

![](/assets/img/malops-silent-authenticator/system-call.png)

#### Question 25:
Before logging credentials, the malware checks if it has root privileges. What libc function returns the effective user ID?
* Continuing on the pseudocode , we see a call to ***geteuid*** (which is the libc function to get the effective user ID)

![](/assets/img/malops-silent-authenticator/geteuid.png)

#### Question 26:
What return value from geteuid indicates the process is running as root?
* The function return ***0*** if the process is running as root

#### Question 27:
What libc function is called to check if the credential log file already exists before writing?
* We can see on the screenshot that the malware uses ***access*** to see if the log file exists , and if not proceeds to create it

![](/assets/img/malops-silent-authenticator/access-call.png)

#### Question 28:
What is the name of the main PAM export function that contains all the backdoor logic?
* Going to the Exports view , we can see all of the exported function of the backdoor

![](/assets/img/malops-silent-authenticator/main-pam-export-func.png)

  Based on the previous Questions and investigation , the function containing the backdoor logic is ***pam_sm_authenticate***.

#### Question 29:
How many PAM module functions (pam_sm_*) are exported by this malicious module?
* Based on the screenshot on Question 28 , ***6*** pam_sm_* function are exported.

#### Question 30:
What string identifier is passed to pam_set_data to store the authentication return value?
* Using the following screenshots of the disassembly and the pseudocode of the function

![](/assets/img/malops-silent-authenticator/unix-setcred-return-1.png)

![](assets/img/malops-silent-authenticator/unix-setcred-return-2.png)

  we can see that the identifier is ***unix_setcred_return***.

#### Question 31:
What PAM internal data identifier string is used when prompting for and storing the user's password?
* We can see on the screenshot that the string for prompting for the password is ***-UN\*X-PASS***

![](/assets/img/malops-silent-authenticator/password-prompt.png)

#### Question 32:
When authentication fails, pam_fail_delay is called. What is the delay value in microseconds passed to this function?
* Tracing the XRef of pam_fail_delay , we find the following call

![](/assets/img/malops-silent-authenticator/pam-fail-delay-call.png)

  which shows that the delay value is ***2000000*** ms.

#### Question 33:
What is the size in bytes of the stack buffer used to construct command strings before execution? (Decimal)
* Inspecting the memset() call in the pseudocode, we can see that the 3rd argument (the size of the buffer) is ***512***

![](/assets/img/malops-silent-authenticator/memset-buffer-length.png)

#### Question 34:
When reading lines from the credential log, what is the maximum line length passed to fgets?
* Similar to Question 33 , but we can go directly to the disassembly view to get the hex value of the buffer length, which is ***0x200***

![](/assets/img/malops-silent-authenticator/fgets-buffer-length.png)

#### Question 35:
When updating an existing credential log entry, the malware uses a temporary file. What single-character filename is used for this temporary file?
* By examining the fopen() calls , we find various calls using the filename "***a***",which is the single character filename that the malware uses

![](/assets/img/malops-silent-authenticator/fopen-filename.png)
