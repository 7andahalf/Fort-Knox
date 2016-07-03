#!/usr/bin/env python

'''
  ______         _     _  __
 |  ____|       | |   | |/ /
 | |__ ___  _ __| |_  | ' / _ __   _____  __
 |  __/ _ \| '__| __| |  < | '_ \ / _ \ \/ /
 | | | (_) | |  | |_  | . \| | | | (_) >  <
 |_|  \___/|_|   \__| |_|\_\_| |_|\___/_/\_\

 Fort Knox V0.1
 Vinay C K
 vinayck.com

'''
from __future__ import print_function
import getpass
import shutil, hashlib, binascii
import os, random, struct
from Crypto.Cipher import AES
import pprint, pickle
from colorama import Fore, Back, Style
import datetime, time

print(Fore.RED + '  ______         _     _  __                ')
print(Fore.GREEN + ' |  ____|       | |   | |/ /                ')
print(Fore.YELLOW + ' | |__ ___  _ __| |_  | \' / _ __   _____  __')
print(Fore.BLUE + ' |  __/ _ \| \'__| __| |  < | \'_ \ / _ \ \/ /')
print(Fore.MAGENTA + ' | | | (_) | |  | |_  | . \| | | | (_) >  < ')
print(Fore.CYAN + ' |_|  \___/|_|   \__| |_|\_\_| |_|\___/_/\_\ ')
print(Style.RESET_ALL)
print("v0.1 VINAY C K")


def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outfile.write(encryptor.encrypt(chunk))

def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0] + ".t"
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)

#string encryption functions; stringlength % 16 == 0
def scrypt(key, iv, stringin):
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    return encryptor.encrypt(stringin)
def sdcrypt(key, iv, stringin):
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    return decryptor.decrypt(stringin)

def setup():

    print("Welcome to Fort-Knox, setting up your vault")

    def getpassword(depth):
        if depth == 3:
            exit(1)
        pswd = getpass.getpass('PASSWORD: ')
        pswd2 = getpass.getpass('AGAIN: ')
        if(pswd != pswd2):
            print(Fore.RED, "Passwords don't match, try again", Style.RESET_ALL)
            return getpassword(depth + 1)
        return pswd
    pswd = getpassword(0)

    key = binascii.hexlify(os.urandom(16)) #AES key
    salt = binascii.hexlify(os.urandom(64)) #pdkbf2 salt

    for i in ["vault", "files", "backup"]:
        os.makedirs(i)

    with open('./vault/1.t', 'w') as file1:
        pickle.dump([{}, {}], file1 )
    with open('./vault/2.t', 'w') as file2:
        pickle.dump( {'fno': 3}, file2)
    with open('./vault/salt.ini', 'w') as saltfile:
        pickle.dump( salt, saltfile )

    for i in ['./vault/1.t', './vault/2.t']:
        encrypt_file(key, i, i[:-2:])
        os.remove(i)


    der_key = hashlib.pbkdf2_hmac('sha256', pswd,salt, 100000, 16)
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

    enckey = scrypt(der_key, iv, key)
    #print("dBug\n", "pswd ", pswd, "\nkey ", key, "\nsalt ", salt, "\nder key ", der_key, "\niv ", iv, "\nenckey ", enckey, "\n\n")
    with open('./vault/0', 'w') as file0:
        pickle.dump(iv, file0)
        pickle.dump(enckey, file0)

    print("Done! Please Login again.")
    exit(0)






try:
    with open('./vault/salt.ini', 'r') as open_config:
	       salt = pickle.load(open_config) # loads salt

except:
    setup()

pswd = getpass.getpass('PASSWORD: ')
with open("./vault/salt.ini") as saltfile:
    salt = pickle.load(saltfile)

try:

    der_key = hashlib.pbkdf2_hmac('sha256', pswd,salt, 100000, 16) #derived key

    with open('./vault/0', 'r') as file0:
        iv = pickle.load(file0)
        ckey = pickle.load(file0)

    key = sdcrypt(der_key, iv, ckey)
    decrypt_file(key, './vault/2')

    with open('./vault/2.t', 'r') as testfile:
        temp = pickle.load(testfile)
    os.remove('./vault/2.t')

    #print("dBug\n", "pswd ", pswd, "\nder key ", der_key, "\nsalt", salt, "iv ", iv, "\nenckey ", ckey, "key ", key )
    print(Fore.GREEN + "Access granted" + Style.RESET_ALL)

except:
    print("I think U is a intruder. okie. bi.")
    try:
        os.remove('./vault/2.t')
    except:
        pass
    exit(1)


dire = []
updv = None
updc = True

def getFile(i):
    decrypt_file(key, './vault/'+str(i))
    mfile = open('./vault/'+str(i)+'.t', 'rb')
    fil = pickle.load(mfile)
    mfile.close()
    os.remove('./vault/'+str(i)+'.t')
    return fil

def setFile(i, f):
    updc = True
    output = open('./vault/'+str(i)+'.t', 'wb+')
    pickle.dump(f, output)
    output.close()
    encrypt_file(key,'./vault/'+str(i)+'.t',out_filename='./vault/'+str(i))
    os.remove('./vault/'+str(i)+'.t')

def currDir():
    s, v = "./files/", getFile(1)
    for i in dire:
        s += i + '/'
        v = v[0][i]
    return (s, v)

def nameMatch(a, b):
    if(len(a) > len(b)):
        for i in range(len(b)):
            if a[i] != b[i]:
                return False
        return True
    else:
        for i in range(len(a)):
            if a[i] != b[i]:
                return False
        return True


def updDirs(di):
    global updv, updc
    if updv == None or updc:
        updv = getFile(1)
        updc = False

    ch = False
    s, v = "./files/", updv
    vv = v
    for i in di:
        s += i + '/'
        v = v[0][i]
    d = []
    for (dirpath, dirnames, filenames) in os.walk(s):
        d.extend(dirnames)
        break
    for i in d:
        if i not in v[0]:
            ch = True
            v[0][i] = [{},{}]
    if ch:
        setFile(1,vv)
    for i in v[0]:
        updDirs(di+[i])

def delFile(direc, n):
    v = getFile(1)
    vv = v
    for i in direc:
        v = v[0][i]
    os.rename('./vault/'+str(v[1][n]),'./vault/'+str(v[1][n])+'.d')
    v[1].pop(n, None)
    setFile(1, vv)

def delDir(direc):
    s, v = "./files/", getFile(1)
    for i in direc:
        s += i + '/'
        v = v[0][i]
    for i in v[0]:
        delDir(direc+[i])
    for i in v[1]:
        delFile(direc, i)

def enDir(direc):
    s, v = "./files/", getFile(1)
    for i in direc:
        s += i + '/'
        v = v[0][i]
    f = []
    for (dirpath, dirnames, filenames) in os.walk(s):
        f.extend(filenames)
        break
    for i in v[0]:
        enDir(direc+[i])
    for i in f:
        if i in v[1]:
            encrypt_file(key,s + i,out_filename='./vault/'+str(v[1][i]))
        else:
            no = getFile(2)['fno']
            encrypt_file(key,s + i,out_filename='./vault/'+str(no))
            sv = getFile(1)
            vv = sv
            for j in direc:
                sv = sv[0][j]
            sv[1][i] = no
            nn = getFile(2)
            nn['fno'] = no + 1
            setFile(2, nn)
            setFile(1, vv)

def deDir(direc):
    s, v = "./files/", getFile(1)
    for i in direc:
        s += i + '/'
        v = v[0][i]
    f = []
    for (dirpath, dirnames, filenames) in os.walk(s):
        f.extend(filenames)
        break
    for i in v[0]:
        deDir(direc+[i])
    for i in v[1]:
        if not os.path.exists(os.path.dirname(s + i)):
            try:
                os.makedirs(os.path.dirname(s + i))
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
        decrypt_file(key, './vault/'+str(v[1][i]), out_filename= s + i)

cc = ""

while True:
    print("\n>>> " + cc,end="")
    rc = raw_input()
    updDirs([])
    if rc != "":
        c = (cc + rc).split(" ")
    else:
        c = [""]
    cc = ""
    if(c[0] == "help"):
        print("List of commands")
        print("\tq : Quit")
        print("\tc : Clear screen")
        print("\tls : List all files in the current directory")
        print("\trm : Deletes a file or directory. rm <name> <arguments f, v, r> f: removes file with exact name, r removes real file, v removes virtual file. use rmf to remove without confirmation")
        print("\ten : Encrypts a file or directory. Use 'en all' to encrypt all files in present directory")
        print("\tde : Decrypts a file or directory. Use 'de all' to decrypt all files in present directory")
        print("\tclean : Permanently deletes trash")
        print("\tenrm : Encrypt all files and deletes real files")
        print("\tbackup : Backs up all encrypted files")
        print("\tchangepass : Changes password")
        print("\tchangekey : Changes encryption key")
        print("\tcd : Changes directory")
        print("\te : prints a tux")
    elif(c[0] == "q"):
        print("Good Bye")
        exit(1)
    elif(c[0] == "c"):
        os.system('clear')
        print(Fore.RED + '  ______         _     _  __                ')
        print(Fore.GREEN + ' |  ____|       | |   | |/ /                ')
        print(Fore.YELLOW + ' | |__ ___  _ __| |_  | \' / _ __   _____  __')
        print(Fore.BLUE + ' |  __/ _ \| \'__| __| |  < | \'_ \ / _ \ \/ /')
        print(Fore.MAGENTA + ' | | | (_) | |  | |_  | . \| | | | (_) >  < ')
        print(Fore.CYAN + ' |_|  \___/|_|   \__| |_|\_\_| |_|\___/_/\_\ ')
        print(Style.RESET_ALL)
        print("v0.1 VINAY C K")
    elif(c[0] == "ls"):
        t = currDir()
        f,d = [],[]
        for (dirpath, dirnames, filenames) in os.walk(t[0]):
            f.extend(filenames)
            d.extend(dirnames)
            break
        for i in d:
            print(Fore.YELLOW + i + '/' + Style.RESET_ALL)
        for i in t[1][0]:
            if i not in d:
                print(Fore.GREEN + i + '/' + Style.RESET_ALL)
        for i in t[1][1]:
            if i not in f:
                print(Fore.GREEN + i + Style.RESET_ALL)
        for i in f:
            if i in t[1][1]:
                print(Fore.YELLOW + i + Style.RESET_ALL)
            else:
                print(Fore.RED + i + Style.RESET_ALL)
    elif(c[0] == "rm" or c[0] == "rmf"):
        if len(c) < 2:
            print(Fore.CYAN + "rm [file/directory name]" + Style.RESET_ALL)
            continue
        force, virt, real = False, False, False
        if len(c) > 2:
            for i in c[2:]:
                if(i == 'f'):
                    force = True
                if(i == 'r'):
                    real = True
                elif(i == 'v'):
                    virt = True
        t = currDir()
        f,d = [],[]
        for (dirpath, dirnames, filenames) in os.walk(t[0]):
            f.extend(filenames)
            d.extend(dirnames)
            break

        pm = []

        for i in d:
            if nameMatch(i, c[1]) and not virt:
                pm.append([i,1])
        for i in t[1][0]:
            if nameMatch(i, c[1]) and not real:
                pm.append([i,0])
        for i in f:
            if nameMatch(i, c[1]) and not virt:
                pm.append([i,3])
        for i in t[1][1]:
            if nameMatch(i, c[1]) and not real:
                pm.append([i,2])
        if force:
            pp = []
            for i in pm:
                if i[0] == c[1]:
                    pp.append(i)
            pm = pp
        if(len(pm) == 0):
            print(Fore.RED + "File " + c[1] + " not found" + Style.RESET_ALL)
        elif(len(pm) == 1 or (len(pm) == 2 and pm[0][0] == pm[1][0])):
            if(len(pm) == 2):
                if(pm[0][1] == 2 or pm[0][1] == 3):
                    print("Delete real file(r) or virtual file(v)? ",end="")
                    df = raw_input()
                    if df == 'r':
                        pm = [[pm[0][0], 3]]
                    elif df == 'v':
                        pm = [[pm[0][0], 2]]
                    else:
                        print(Fore.GREEN + "Aborting" + Style.RESET_ALL)
                        continue
                else:
                    pm = [[pm[0][0], 1]]
            if(c[0] == "rmf"):
                con = 'y'
            else:
                print("Delete " + Fore.RED + pm[0][0] + Style.RESET_ALL + " ?")
                print("y to confirm, anyother key to abort:", end="")
                con = raw_input()
            if(con == 'y'):
                if(pm[0][1] == 1):
                    shutil.rmtree(t[0] + pm[0][0])
                elif(pm[0][1] == 3):
                    os.remove(t[0] + pm[0][0])
                elif(pm[0][1] == 2):
                    v = getFile(1)
                    vv = v
                    for i in dire:
                        v = v[0][i]
                    os.rename('./vault/'+str(v[1][pm[0][0]]),'./vault/'+str(v[1][pm[0][0]])+'.d')
                    v[1].pop(pm[0][0], None)
                    setFile(1, vv)
                elif(pm[0][1] == 0):
                    delDir(dire+[pm[0][0]])
                    v = getFile(1)
                    vv = v
                    for i in dire:
                        v = v[0][i]
                    v[0].pop(pm[0][0], None)
                    setFile(1, vv)
            else:
                print(Fore.GREEN + "Aborting" + Style.RESET_ALL)
        else:
            j = 0
            while True:
                try:
                    k = pm[0][0][j]
                    for i in pm:
                        if i[0][j] != k:
                            raise Exception
                except:
                    break
                j = j + 1
            cc = c[0] + " " + pm[0][0][:j]
            for i in pm:
                if(i[1] == 0 or i[1] == 2):
                    print(Fore.GREEN + 'VIRT ' + Fore.CYAN + i[0] + Style.RESET_ALL)
                else:
                    print(Fore.RED + 'REAL ' + Fore.CYAN + i[0] + Style.RESET_ALL)
    elif(c[0] == "en"):
        if(len(c) == 2):
            if(c[1] != 'all'):
                t = currDir()
                f,d = [],[]
                for (dirpath, dirnames, filenames) in os.walk(t[0]):
                    f.extend(filenames)
                    d.extend(dirnames)
                    break
                pm = []
                for i in d:
                    if nameMatch(i, c[1]):
                        pm.append([i,1])
                for i in f:
                    if nameMatch(i, c[1]):
                        pm.append([i,3])
                if(len(pm) == 0):
                    print(Fore.RED + "File " + c[1] + " not found" + Style.RESET_ALL)
                elif(len(pm) == 1):
                    if(pm[0][1] == 3):
                        if(pm[0][0] in t[1][1]):
                            v = getFile(1)
                            for i in dire:
                                v = v[0][i]
                            encrypt_file(key,t[0] + pm[0][0],out_filename='./vault/'+str(v[1][pm[0][0]]))
                            print(Fore.GREEN + "Rencrypting" + Style.RESET_ALL)
                        else:
                            no = getFile(2)['fno']
                            encrypt_file(key,t[0] + pm[0][0],out_filename='./vault/'+str(no))
                            v = getFile(1)
                            vv = v
                            for i in dire:
                                v = v[0][i]
                            v[1][pm[0][0]] = no
                            nn = getFile(2)
                            nn['fno'] = no + 1
                            setFile(2, nn)
                            setFile(1, vv)
                            print(Fore.GREEN + "Encrypting" + Style.RESET_ALL)
                    else:
                        enDir(dire + [pm[0][0]])
                else:
                    j = 0
                    while True:
                        try:
                            k = pm[0][0][j]
                            for i in pm:
                                if i[0][j] != k:
                                    raise Exception
                        except:
                            break
                        j = j + 1
                    cc = "en " + pm[0][0][:j]
                    for i in pm:
                        print(Fore.CYAN + i[0] + Style.RESET_ALL)
            else:
                enDir(dire)
        else:
            print(Fore.CYAN + "en [file/directory name] or all" + Style.RESET_ALL)
            continue
    elif(c[0] == "de"):
        if(len(c) == 2):
            if(c[1] != 'all'):
                t = currDir()
                f,d = [],[]
                for (dirpath, dirnames, filenames) in os.walk(t[0]):
                    f.extend(filenames)
                    d.extend(dirnames)
                    break
                pm = []
                for i in t[1][0]:
                    if nameMatch(i, c[1]):
                        pm.append([i,0])
                for i in t[1][1]:
                    if nameMatch(i, c[1]):
                        pm.append([i,2])
                if(len(pm) == 0):
                    print(Fore.RED + "File " + c[1] + " not found" + Style.RESET_ALL)
                elif(len(pm) == 1):
                    if(pm[0][1] == 2):
                        if not os.path.exists(os.path.dirname(t[0] + pm[0][0])):
                            try:
                                os.makedirs(os.path.dirname(t[0] + pm[0][0]))
                            except OSError as exc:
                                if exc.errno != errno.EEXIST:
                                    raise
                        decrypt_file(key, './vault/'+str(t[1][1][pm[0][0]]), out_filename= t[0] + pm[0][0])
                    else:
                        deDir(dire + [pm[0][0]])
                else:
                    j = 0
                    while True:
                        try:
                            k = pm[0][0][j]
                            for i in pm:
                                if i[0][j] != k:
                                    raise Exception
                        except:
                            break
                        j = j + 1
                    cc = "de " + pm[0][0][:j]
                    for i in pm:
                        print(Fore.CYAN + i[0] + Style.RESET_ALL)
            else:
                deDir(dire)
        else:
            print(Fore.CYAN + "de [file/directory name] or all" + Style.RESET_ALL)
            continue
    elif(c[0] == "cd"):
        if(len(c) == 1):
            dire = []
        elif(c[1] == ".."):
            dire = dire[:-1]
        else:
            t = currDir()
            d = []
            for (dirpath, dirnames, filenames) in os.walk(t[0]):
                d.extend(dirnames)
                break

            pm = []
            pmm = []

            for i in d:
                if nameMatch(i, c[1]):
                    pm.append([i,1])
                if i == c[1]:
                    pmm.append([i,1])
            for i in t[1][0]:
                if nameMatch(i, c[1]):
                    pm.append([i,0])
                if i == c[1]:
                    pmm.append([i,0])

            if(len(pmm) != 0):
                pm = pmm

            if(len(pm) == 0):
                print(Fore.RED + "Directory " + c[1] + " not found" + Style.RESET_ALL)
            elif(len(pm) == 1 or (len(pm) == 2 and pm[0][0] == pm[1][0])):
                dire.append(pm[0][0])
            else:
                j = 0
                while True:
                    try:
                        k = pm[0][0][j]
                        for i in pm:
                            if i[0][j] != k:
                                raise Exception
                    except:
                        break
                    j = j + 1
                cc = c[0] + " " + pm[0][0][:j]
                for i in pm:
                    if(i[1] == 0 or i[1] == 2):
                        print(Fore.GREEN + 'VIRT ' + Fore.CYAN + i[0] + Style.RESET_ALL)
                    else:
                        print(Fore.RED + 'REAL ' + Fore.CYAN + i[0] + Style.RESET_ALL)
    elif(c[0] == "changepass"):
        ps = getpass.getpass('Your current password: ')
        if ps != pswd:
            print("I think U is a intruder. okie. bi.")
            exit(1)
        ps1 = getpass.getpass('Enter new password: ')
        ps2 = getpass.getpass('Re-enter new password: ')
        if(ps1 != ps2):
            print(Fore.RED + "Passwords don't match" + Style.RESET_ALL)
        else:
            a = {'key' : key}
            output = open('./vault/0.t', 'wb+')
            pickle.dump(a, output)
            output.close()
            encrypt_file(ps1+ps2,'./vault/0.t',out_filename='./vault/0')
            os.remove('./vault/0.t')
            print(Fore.GREEN + "Password changed. Relogin" + Style.RESET_ALL)
            exit()
    elif(c[0] == "changekey"):
        print("Enter a new key 32 chars long")
        key1 = raw_input()
        if(len(key1) != 32):
            print("Y u no listen to me? I said 32 chars long")
            exit(1)
        print(Fore.GREEN + "Decrypting everything" + Style.RESET_ALL)
        deDir([])

        aa,bb = getFile(1), getFile(2)

        key = key1
        a = {'key' : key}
        output = open('./vault/0.t', 'wb+')
        pickle.dump(a, output)
        output.close()
        encrypt_file(pswd+pswd,'./vault/0.t',out_filename='./vault/0')
        os.remove('./vault/0.t')

        setFile(1,aa)
        setFile(2,bb)

        print(Fore.GREEN + "Encrypting everything using new key" + Style.RESET_ALL)
        enDir([])

        print(Fore.GREEN + "All done. Relogin." + Style.RESET_ALL)
        exit(1)
    elif(c[0] == "clean"):
        d = []
        for (dirpath, dirnames, filenames) in os.walk("./vault/"):
            d.extend(filenames)
            break
        nn = 0
        for i in d:
            if(i[-2:] == ".d"):
                nn += 1
                os.remove('./vault/' + i)
        print(Fore.GREEN + "Cleaned: Deleted " + str(nn) + " files" + Style.RESET_ALL)
    elif(c[0] == "backup"):
        shutil.copytree("./vault/","./backup/"+str(datetime.datetime.fromtimestamp(time.time()).strftime('%H.%M.%S-%d.%m.%Y'))+"/")
        print(Fore.GREEN + "Backup complete" + Style.RESET_ALL)
    elif(c[0] == "enrm"):
        print(Fore.GREEN + "Encrypting" + Style.RESET_ALL)
        enDir([])
        print(Fore.GREEN + "Deleting" + Style.RESET_ALL)
        shutil.rmtree('./files/')
        if not os.path.exists('./files/'):
            os.makedirs('./files/')
    elif(c[0] == "e"):
        os.system('clear')
        print("\
                                        .:xxxxxxxx:. \n\
                                     .xxxxxxxxxxxxxxxx. \n\
                                    :xxxxxxxxxxxxxxxxxxx:. \n\
                                   .xxxxxxxxxxxxxxxxxxxxxxx: \n\
                                  :xxxxxxxxxxxxxxxxxxxxxxxxx: \n\
                                  xxxxxxxxxxxxxxxxxxxxxxxxxxX: \n\
                                  xxx:::xxxxxxxx::::xxxxxxxxx: \n\
                                 .xx:   ::xxxxx:     :xxxxxxxx \n\
                                 :xx  x.  xxxx:  xx.  xxxxxxxx \n\
                                 :xx xxx  xxxx: xxxx  :xxxxxxx \n\
                                 'xx 'xx  xxxx:. xx'  xxxxxxxx \n\
                                  xx ::::::xx:::::.   xxxxxxxx \n\
                                  xx:::::.::::.:::::::xxxxxxxx \n\
                                  :x'::::'::::':::::':xxxxxxxxx. \n\
                                  :xx.::::::::::::'   xxxxxxxxxx \n\
                                  :xx: '::::::::'     :xxxxxxxxxx. \n\
                                 .xx     '::::'        'xxxxxxxxxx. \n\
                               .xxxx                     'xxxxxxxxx. \n\
                             .xxxx                         'xxxxxxxxx. \n\
                           .xxxxx:                          xxxxxxxxxx. \n\
                          .xxxxx:'                          xxxxxxxxxxx. \n\
                         .xxxxxx:::.           .       ..:::_xxxxxxxxxxx:. \n\
                        .xxxxxxx''      ':::''            ''::xxxxxxxxxxxx. \n\
                        xxxxxx            :                  '::xxxxxxxxxxxx \n\
                       :xxxx:'            :                    'xxxxxxxxxxxx: \n\
                      .xxxxx              :                     ::xxxxxxxxxxxx \n\
                      xxxx:'                                    ::xxxxxxxxxxxx \n\
                      xxxx               .                      ::xxxxxxxxxxxx. \n\
                  .:xxxxxx               :                      ::xxxxxxxxxxxx:: \n\
                  xxxxxxxx               :                      ::xxxxxxxxxxxxx: \n\
                  xxxxxxxx               :                      ::xxxxxxxxxxxxx: \n\
                  ':xxxxxx               '                      ::xxxxxxxxxxxx:' \n\
                    .:. xx:.                                   .:xxxxxxxxxxxxx' \n\
                  ::::::.'xx:.            :                  .:: xxxxxxxxxxx': \n\
          .:::::::::::::::.'xxxx.                            ::::'xxxxxxxx':::. \n\
          ::::::::::::::::::.'xxxxx                          :::::.'.xx.'::::::. \n\
          ::::::::::::::::::::.'xxxx:.                       :::::::.'':::::::::   \n\
          ':::::::::::::::::::::.'xx:'                     .'::::::::::::::::::::.. \n\
            :::::::::::::::::::::.'xx                    .:: ::::::::::::::::::::::: \n\
          .:::::::::::::::::::::::. xx               .::xxxx ::::::::::::::::::::::: \n\
          :::::::::::::::::::::::::.'xxx..        .::xxxxxxx ::::::::::::::::::::' \n\
          '::::::::::::::::::::::::: xxxxxxxxxxxxxxxxxxxxxxx :::::::::::::::::' \n\
            '::::::::::::::::::::::: xxxxxxxxxxxxxxxxxxxxxxx :::::::::::::::' \n\
                ':::::::::::::::::::_xxxxxx::'''::xxxxxxxxxx '::::::::::::' \n\
                     '':.::::::::::'                        `._'::::::'' ")
    else:
        if(c[0] != ''):
            print("Command '" + c[0] + "' not found. Use 'help' for the list of commands")
