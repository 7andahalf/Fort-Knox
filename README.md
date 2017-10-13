# Fort-Knox
A Virtual encrypted file system

### About

Fort Knox is a virtual encrypted file system. You can place some files in the 'files' directory and run fortKnox.py, login and encrypt those files. These files will be encrypted and stored in the 'vault'. Now you can delete those files in the 'files' folder. To retrieve them you can decrypt them using Fort Knox. Fort Knox has its own terminal like unix with some basic commands.

### Installation

Download the repo onto your system. Make sure you have the dependencies(Crypto.Cipher and colorama) installed. Use following commands to do that.

`pip install pycrypto colorama` (recommended)

if you don't have pip

`easy_install pycrypto`  

`easy_install colorama`



Run fortKnox.py
You can setup your password now. Enter a password of your choice and enter it again when asked.
Fort-knox will now be setup, Login again to start using.

###### Note:  
* You change password by typing 'changepass' and pressing enter.
* use 'help' for list of commands

### What this could be used for

- To maintain a diary. Simply create a folder in 'files' add your entries as files, decrypt and read when needed.
- To maintain a journal, working on a top-secret project? Use this as a journal
- To store your secret project files
- To store sensetive files/information like passwords

### Usage

Place files in 'files' folder.
List of commands:
- c : clears the screen
- ls : Lists all files in the current directory
- cd : changes directory. 'cd' goes to 'files'. 'cd ..' goes to prev directory.
- rm : deletes files. No need to type full name(but you can), type first letter and press enter, Knox will try to match the letter and give you list of possible matches and update filename until full partial match. when unique file/folder is found. It confirms and deletes. In case of files, if file is stored unencrypted in 'files' folder it will be red in color, this kind of file is called real file. If a file is encrypted and stored in vault, this is called virtual file and will be green in color. If a file is both real and virtual it is yellow. A folder is yellow if present in 'files', 'green' if present only as encrypted form. Removing a yellow file results in Knox asking you which file to delete real or virtual. Deleting a folder will result in deletion of real folder. Flags like f, r, v can be used: f is when you type the full name of file. r is to delete the real file, v to delete virtual file. Ex: 'rm s.pdf f' will delete only s.pdf, 'rm s' will look for files starting with s
- rmf : Same as rm, no confirmation is asked
- en : used to encrypt files. Use 'en all' to encrypt all files in present directory. Or use en <file name or folder name>
- de : used to decrypt files. Use 'de all' to decrypt all files in present directory. Or use de <file name or folder name>
- clean : 'rm' doesn't delete encrypted files permenently, use 'clean' to do that
- enrm : short for encrypt-delete encrypts everything in 'files' and deletes them
- backup : backs up encrypted files in 'backup' folder
- changepass : to change password
- chanhekey : to change key
- e : prints a tux because why not?


### Disclaimer
THIS DOCUMENT IS PROVIDED "AS IS," AND COPYRIGHT HOLDERS MAKE NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, OR TITLE; THAT THE CONTENTS OF THE DOCUMENT ARE SUITABLE FOR ANY PURPOSE; NOR THAT THE IMPLEMENTATION OF SUCH CONTENTS WILL NOT INFRINGE ANY THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS. COPYRIGHT HOLDERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THE DOCUMENT OR THE PERFORMANCE OR IMPLEMENTATION OF THE CONTENTS THEREOF. The name and trademarks of copyright holders may NOT be used in advertising or publicity pertaining to this document or its contents without specific, written prior permission. Title to copyright in this document will at all times remain with copyright holders.
