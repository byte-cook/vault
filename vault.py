#!/usr/bin/env python3

import subprocess
import argparse
import sys
import os
import zipfile
import shutil
import getpass
import traceback
import hashlib
import logging
import shlex
import pyperclip
import threading
import gnureadline
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from textwrap import dedent

## pip3 install pycryptodome
## pip3 install pyperclip
## pip3 install gnureadline

# https://nitratine.net/blog/post/python-gcm-encryption-tutorial/

BUFFER_SIZE = 1024 * 1024
CLIPBOARD_SEC = 45
timer = None

class LineNumberError(Exception):
    def __init__(self, msg):
        self.msg = msg

class TextFileLine:
    def __init__(self, text, visible=False):
        self.text = text
        self.visible = visible
    
    def getPrintableText(self):
        return self.text.rstrip('\n')
        
    def isVisible(self):
        return self.visible
        
    def printLine(self, prefix):
        print('{}{}'.format(prefix, self.getPrintableText()))

class TextFile:
    def __init__(self, plaintext):
        self.dirty = False
        self.lines = []
        for line in plaintext.splitlines(True):
            self.lines.append(TextFileLine(line))
    
    def insert(self, index, contents):
        i = index
        for line in contents.splitlines(True):
            self.lines.insert(i, TextFileLine(line, True))
            self.dirty = True
            i += 1
    
    def line(self, fromIndex, toIndex):
        if fromIndex is None:
            for line in self.lines:
                line.visible = True
        else:
            indexes = sorted(range(fromIndex, toIndex+1), reverse=False)
            for i in indexes:
                self.lines[i].visible = True
    
    def find(self, searchText, beforeContext, afterContext):
        foundIndexes = []
        i = 2
        for i, line in enumerate(self.lines):
            lineText = line.getPrintableText()
            if searchText.lower() in lineText.lower():
                line.visible = True
                beforeIndexes = range(i-beforeContext, i)
                foundIndexes.extend(beforeIndexes)
                afterIndexes = range(i, i+afterContext+1)
                foundIndexes.extend(afterIndexes)
                
        foundIndexes = [i for i in foundIndexes if 0 <= i and i < len(self.lines)]
        for i in foundIndexes:
            self.lines[i].visible = True
            
    def delete(self, index):
        if index is None:
            self.lines.clear()
            self.dirty = True
        else:
            del self.lines[index]
            self.dirty = True
    
    def clearVisible(self):
        for line in self.lines:
            line.visible = False

    def printVisible(self):
        for i, line in enumerate(self.lines):
            if line.isVisible():
                line.printLine(self.getLinePrefix(i))

    def getLinePrefix(self, index):
        return '{:3d} | '.format(index+1)
                
    def getText(self, fromIndex, toIndex):
        text = ''
        indexes = sorted(range(fromIndex, toIndex+1), reverse=False)
        for i in indexes:
            text += (textFile.lines[i].text)
        return text
    
    def getEndIndex(self):
        return len(self.lines)
    
    def transformLineArgToIndexes(self, lineArg, supportRange=False, supportAppend=False):
        logging.debug('Transform line to index: {}'.format(lineArg))
        if supportRange:
            lineNoTokens = lineArg.split('-')
            if len(lineNoTokens) > 2:
                raise LineNumberError('Illegal range format')
        else:
            lineNoTokens = [lineArg]
        logging.debug('Tokens: {}'.format(lineNoTokens))
        
        min = 1
        max = len(self.lines) + 1 if supportAppend else len(self.lines)
        
        fromDefaultForEmpty = 1 if len(lineNoTokens) == 2 else None
        fromIndex = self._transformLineNoToIndex(lineNoTokens[0], min, max, fromDefaultForEmpty)
        if len(lineNoTokens) > 1:
            toDefaultForEmpty = len(self.lines) if len(lineNoTokens) == 2 else None
            toIndex = self._transformLineNoToIndex(lineNoTokens[1], min, max, toDefaultForEmpty)
        else:
            toIndex = fromIndex
        
        if fromIndex > toIndex:
            raise LineNumberError('From is greater than to')
        return (fromIndex, toIndex)
    
    def _transformLineNoToIndex(self, lineNumber, min, max, defaultForEmpty):
        try:
            if not lineNumber and defaultForEmpty is not None:
                lineNumber = defaultForEmpty
            lineNo = int(lineNumber)
            if min > lineNo or lineNo > max:
                raise LineNumberError('Line number is out of range: 1-{}'.format(len(self.lines)))
            return lineNo - 1
        except ValueError:
            raise LineNumberError('Illegal integer format: {}'.format(lineNumber))
    
    def toPlaintext(self):
        plaintext = ''
        for line in self.lines:
            plaintext += line.text
        return plaintext

def insert(textFile, lineArg, newLine=False, newLineNumber=1):
    logging.debug('Action INSERT: {}'.format(lineArg))
    if lineArg is None:
        index = textFile.getEndIndex()
    else:
        fromIndex, toIndex = textFile.transformLineArgToIndexes(lineArg, False, True)
        index = fromIndex
    
    if not newLine:
        print('Type text to insert. Use empty line to exit.')
        contents = ''
        i = index
        while True:
            try:
                line = input(textFile.getLinePrefix(i))
                if not line:
                    break
                contents += line + '\n'
                i += 1
            except EOFError:
                break
    else:
        contents = '\n' * newLineNumber
    textFile.insert(index, contents)

def edit(textFile, lineArgs, copy):
    logging.debug('Action EDIT: {}'.format(lineArgs))
    indexes = []
    for lineArg in lineArgs:
        fromIndex, toIndex = textFile.transformLineArgToIndexes(lineArg, True, False)
        indexes.extend(range(fromIndex, toIndex+1))

    indexes = sorted(set(indexes))
    
    copyMsg = ' The clipboard contains the current text of each line.' if copy else ''
    print('Type text to edit line. Use RETURN to exit.' + copyMsg)
    for i in indexes:
        if copy:
            pyperclip.copy(textFile.getText(i, i).rstrip('\n'))
        line = input(textFile.getLinePrefix(i))
        line += '\n'
        textFile.delete(i)
        textFile.insert(i, line)
    if copy:
        # clear clipboard
        pyperclip.copy('')

def delete(textFile, lineArgs):
    logging.debug('Action DELETE: {}'.format(lineArgs))
    if lineArgs is None:
        deleteAll = getYesOrNo('Should the complete file content be deleted?', default=False)
        if deleteAll:
            textFile.delete(None)
    else:
        indexes = []
        for lineArg in lineArgs:
            fromIndex, toIndex = textFile.transformLineArgToIndexes(lineArg, True, False)
            indexes.extend(range(fromIndex, toIndex+1))
        
        indexes = sorted(set(indexes), reverse=True)
        for i in indexes:
            textFile.delete(i)

def cut(textFile, lineArgs):
    logging.debug('Action CUT: {}'.format(lineArgs))
    copy(textFile, lineArgs)
    delete(textFile, lineArgs)
    
def copy(textFile, lineArgs, autoClearClipboard=True):
    logging.debug('Action COPY: {}'.format(lineArgs))
    text = ''
    for lineArg in lineArgs:
        fromIndex, toIndex = textFile.transformLineArgToIndexes(lineArg, True, False)
        text += textFile.getText(fromIndex, toIndex)
    text = text.rstrip('\n')
    pyperclip.copy(text)
    if autoClearClipboard:
        global timer
        if timer is not None:
            timer.cancel()
        timer = threading.Timer(CLIPBOARD_SEC, lambda: pyperclip.copy(''))
        timer.start()

def paste(textFile, lineArg):    
    logging.debug('Action PASTE: {}'.format(lineArg))
    if lineArg is None:
        index = textFile.getEndIndex()    
    else:
        fromIndex, toIndex = textFile.transformLineArgToIndexes(lineArg, False, True)
        index = fromIndex
    contents = pyperclip.paste()
    textFile.insert(index, contents)

def find(textFile, searchText, beforeContext, afterContext):
    logging.debug('Action FIND: {}'.format(searchText))
    textFile.clearVisible()
    textFile.find(searchText, beforeContext, afterContext)
    textFile.printVisible()
    
def line(textFile, lineArgs):
    logging.debug('Action LINE: {}'.format(lineArgs))
    textFile.clearVisible()
    if lineArgs is None:
        textFile.line(None, None)
    else:
        for lineArg in lineArgs:
            fromIndex, toIndex = textFile.transformLineArgToIndexes(lineArg, True, False)
            textFile.line(fromIndex, toIndex)
    textFile.printVisible()
    
def quit(textFile, force, password, filePath):
    logging.debug('Action QUIT: {}'.format(filePath))
    if textFile.dirty and not force:  
        writeFile = getYesOrNo('The file has been changed. Should the changes be saved?', default=None)
        if writeFile:
            write(textFile, password, filePath)
    global timer
    if timer is not None:
        timer.cancel()
        pyperclip.copy('')
    exit(0)

def write(textFile, password, filePath):
    logging.debug('Action WRITE: {}'.format(filePath))
    writeEncryptedFile(textFile.toPlaintext(), password, filePath)
    textFile.dirty = False
    
def read(textFile, password, filePath, force):
    logging.debug('Action READ: {}'.format(filePath))
    if not os.path.exists(filePath):
        return TextFile('')
    if textFile is not None and textFile.dirty and not force:
        readIn = getYesOrNo('The file has been changed. Should the file be read in again and all changes lost?', default=False)
        if not readIn:
            return textFile
    plaintext = readEncryptedFile(filePath, password)
    return TextFile(plaintext)

def readEncryptedFile(filePath, password):
    with open(filePath, 'rb') as fileIn:
        # Read salt and generate key
        # The salt we generated was 32 bits long
        salt = fileIn.read(32)  
        # Generate a key using the password and salt again
        key = scrypt(password, salt, key_len=32, N=2**17, r=8, p=1)  

        # Read nonce and create cipher
        # The nonce is 16 bytes long
        nonce = fileIn.read(16)  
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Identify how many bytes of encrypted there is
        # We know that the salt (32) + the nonce (16) + the data (?) + the tag (16) is in the file
        # So some basic algebra can tell us how much data we need to read to decrypt
        fileInSize = os.path.getsize(filePath)
        # Total - salt - nonce - tag = encrypted data
        encrypted_data_size = fileInSize - 32 - 16 - 16  
        
        decrypted_data = bytearray()
        # Read, decrypt and write the data
        for _ in range(int(encrypted_data_size / BUFFER_SIZE)):  # Identify how many loops of full buffer reads we need to do
            data = fileIn.read(BUFFER_SIZE)  # Read in some data from the encrypted file
            decrypted_data.extend(cipher.decrypt(data))  # Decrypt the data
        # Read whatever we have calculated to be left of encrypted data
        data = fileIn.read(int(encrypted_data_size % BUFFER_SIZE))  
        # Decrypt the data
        decrypted_data.extend(cipher.decrypt(data))  
        
        # Verify encrypted file was not tampered with
        tag = fileIn.read(16)
        try:
            cipher.verify(tag)
        except ValueError as e:
            raise e
            
        return decrypted_data.decode()
    
def writeEncryptedFile(plaintext, password, filePath):
    with open(filePath, 'wb') as fileOut:
        # Generate salt
        salt = get_random_bytes(32)  
        # Generate a key using the password and salt (length: 32*8=256)
        key = scrypt(password, salt, key_len=32, N=2**17, r=8, p=1) 
        # Write the salt to the top of the output file
        fileOut.write(salt)  
        
        # Create a cipher object to encrypt data
        cipher = AES.new(key, AES.MODE_GCM)  
        # Write out the nonce to the output file under the salt
        fileOut.write(cipher.nonce)
        
        # Encrypt the data we read
        encrypted_data = cipher.encrypt(plaintext.encode())  
        # Write the encrypted data to the output file
        fileOut.write(encrypted_data)  
        
        # == Get and write the tag for decryption verification
        # Signal to the cipher that we are done and get the tag
        tag = cipher.digest()  
        fileOut.write(tag)

def getPassword(repeatPrompt):
    if repeatPrompt:
        valid = False
        while not valid:
            password = getpass.getpass('Enter new master password: ')
            repeatedPassword = getpass.getpass('Repeat new master password: ')
            valid = password == repeatedPassword
            if not valid:
                print('Passwords are not equal')
    else:
        password = getpass.getpass('Enter master password: ')
    return password

def getYesOrNo(question, default=True):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    prompt = {True: " [Y/n] ", False: " [y/N] ", None: " [y/n] "}
    while True:
        print(question + prompt[default], end='')
        choice = input().lower()
        if default is not None and choice == "":
            return default
        elif choice in valid:
            return valid[choice]
        else:
            print('Please respond with "yes" or "no" (or "y" or "n").')

if __name__ == '__main__':
    try:
        PROG_DESC = """\
            Vault is an application to store secret data like passwords transparently in an encrypted file. It uses salted AES encryption in GCM mode to protect the data.
            
            If no argument is specified, the interactive mode is started, which allows to edit the encrypted file. 
            
            The editor is line-based, so it is recommended to save only one record per line. For example, user names and passwords should be stored in different lines.
            """
        parser = argparse.ArgumentParser(description=dedent(PROG_DESC), formatter_class=argparse.RawTextHelpFormatter)
        parser.add_argument("--debug", help="activate DEBUG logging", action="store_true")
        parser.add_argument("--import", dest='importStdin', help="import from stdin to the encrypted secret file", action="store_true")
        parser.add_argument("--export", dest='exportStdout', help="export the secret file in plaintext to stdout", action="store_true")
        parser.add_argument('file', nargs='?', help='the secret file', default=os.path.expanduser('~/my.vault'))

        args = parser.parse_args()
        
        level = logging.DEBUG if args.debug else logging.WARNING
        logging.basicConfig(format='%(levelname)s: %(message)s', level=level, force=True)
        
        vaultFile = os.path.abspath(args.file)
        logging.debug('Vault file: {}'.format(vaultFile))

        if args.importStdin:
            logging.debug('Importing from stdin...')
            if os.path.exists(vaultFile):
                print('Import failed. The target file "{}" does already exist.'.format(vaultFile))
                exit(1)
                # Note: getYesOrNo does not work because stdin is already closed
                # overwrite = getYesOrNo('Should the file be overwritten?', default=False)
                # if not overwrite:
            
            plaintext = sys.stdin.read()
            password = getPassword(True)
            writeEncryptedFile(plaintext, password, vaultFile)
        elif args.exportStdout:
            logging.debug('Exporting to stdout...')
            
            if not os.path.exists(vaultFile):
                print('File "{}" does not exist.'.format(vaultFile))
                exit(1)
            
            password = getPassword(False)
            plaintext = readEncryptedFile(vaultFile, password)
            print(plaintext)
        else:
            logging.debug('Starting interactive mode...')

            password = getPassword(not os.path.exists(vaultFile))
            textFile = read(None, password, vaultFile, True)
            print('Enter your command. Use "-h" to get help.')
        
            # internal command parser
            cmdParser = argparse.ArgumentParser(prog='', exit_on_error=False)
            subparsers = cmdParser.add_subparsers(dest='command')
            # find
            findParser = subparsers.add_parser('find', aliases=['f'], help='output lines if search text matches')
            findParser.add_argument('-B', dest='beforeContext', default=0, type=int, help='print NUM lines before context (default: 0)')
            findParser.add_argument('-A', dest='afterContext', default=5, type=int, help='print NUM lines after context (default: 5)')
            findParser.add_argument('-C', dest='context', default=0, type=int, help='print NUM lines before and after context (default: 0)')
            findParser.add_argument('text', help='the search text')
            # line
            lineParser = subparsers.add_parser('line', aliases=['l'], help='output lines by number')
            lineParser.add_argument('lineNumbers', nargs='*', help='line number or range, e.g. 1-7')
            # insert/newline/edit/delete
            insertParser = subparsers.add_parser('insert', aliases=['i'], help='insert new text')
            insertParser.add_argument('lineNumber', nargs='?', help='line number to insert, e.g. 7')
            newLineParser = subparsers.add_parser('newline', aliases=['nl'], help='insert new empty line')
            newLineParser.add_argument('-n', dest='number', default=1, type=int, help='number of new lines to insert (default: 1)')
            newLineParser.add_argument('lineNumber', nargs='?', help='line number to insert, e.g. 7')
            editParser = subparsers.add_parser('edit', aliases=['e'], help='edit lines')
            editParser.add_argument('-c', dest='copy', default=False, action='store_true', help='copy each line to clipboard to simplify editing of particular characters')
            editParser.add_argument('lineNumbers', nargs='+', help='line number or range, e.g. 1-7')
            deleteParser = subparsers.add_parser('del', aliases=['d'], help='delete lines')
            deleteParser.add_argument('lineNumbers', nargs='*', help='line number or range, e.g. 1-7')
            # read/write
            readParser = subparsers.add_parser('read', aliases=['r'], help='reads the vault file, unsaved changes are lost')
            readParser.add_argument('-f', dest='force', default=False, action='store_true', help='force read without asking')
            writeParser = subparsers.add_parser('write', aliases=['w'], help='write to vault file')
            writeParser.add_argument('-p', dest='changePassword', default=False, action='store_true', help='change password')
            # cut/copy/paste
            cutParser = subparsers.add_parser('cut', aliases=['x'], help=f'copy lines to clipboard and delete them, clipboard will automatically cleared after {CLIPBOARD_SEC} seconds')
            cutParser.add_argument('lineNumbers', nargs='+', help='line number or range, e.g. 1-7')
            copyParser = subparsers.add_parser('copy', aliases=['c'], help=f'copy lines to clipboard, clipboard will automatically cleared after {CLIPBOARD_SEC} seconds')
            copyParser.add_argument('lineNumbers', nargs='+', help='line number or range, e.g. 1-7')
            pasteParser = subparsers.add_parser('paste', aliases=['v'], help='paste lines from clipboard')
            pasteParser.add_argument('lineNumber', nargs='?', help='line number to insert, e.g. 7')
            # exit/help
            helpParser = subparsers.add_parser('help', aliases=['h', '?'], help='show this help message')
            exitParser = subparsers.add_parser('quit', aliases=['exit', 'q'], help='exit this application')
            exitParser.add_argument('-f', dest='force', default=False, action='store_true', help='force exit without asking')
            writeAndExitParser = subparsers.add_parser('wq', help='write to vault file and exit')

            while True:
                try:
                    prompt = input('* > ' if textFile.dirty else '  > ' )
                    if not prompt:
                        # empty prompt
                        continue
                    cmd = cmdParser.parse_args(shlex.split(prompt))
                except argparse.ArgumentError as e:
                    print(e)
                    logging.debug('{}: {}'.format(type(e), e))
                    if args.debug:
                        traceback.print_exc()
                    continue
                except (SystemExit, EOFError) as e:
                    continue
                
                try:
                    if cmd.command in ['quit', 'exit', 'q']:    
                        quit(textFile, cmd.force, password, vaultFile)
                    elif cmd.command in ['wq']:
                        write(textFile, password, vaultFile)
                        quit(textFile, True, password, vaultFile)
                    elif cmd.command in ['help', 'h', '?']:
                        cmdParser.print_help()
                    elif cmd.command in ['insert', 'i']:
                        insert(textFile, cmd.lineNumber if cmd.lineNumber else None)
                    elif cmd.command in ['newline', 'nl']:
                        insert(textFile, cmd.lineNumber if cmd.lineNumber else None, True, cmd.number)
                    elif cmd.command in ['find', 'f']:
                        beforeContext = cmd.beforeContext
                        afterContext = cmd.afterContext
                        if cmd.context:
                            beforeContext = afterContext = cmd.context
                        find(textFile, cmd.text, beforeContext, afterContext)
                    elif cmd.command in ['line', 'l']:
                        line(textFile, cmd.lineNumbers if cmd.lineNumbers else None)
                    elif cmd.command in ['write', 'w']:
                        if cmd.changePassword:
                            password = getPassword(True)
                        write(textFile, password, vaultFile)
                    elif cmd.command in ['read', 'r']:
                        textFile = read(textFile, password, vaultFile, cmd.force)
                    elif cmd.command in ['del', 'd']:
                        delete(textFile, cmd.lineNumbers if cmd.lineNumbers else None)
                    elif cmd.command in ['copy', 'c']:
                        copy(textFile, cmd.lineNumbers)
                    elif cmd.command in ['cut', 'x']:
                        cut(textFile, cmd.lineNumbers)
                    elif cmd.command in ['paste', 'v']:
                        paste(textFile, cmd.lineNumber if cmd.lineNumber else None)
                    elif cmd.command in ['edit', 'e']:
                        edit(textFile, cmd.lineNumbers if cmd.lineNumbers else None, cmd.copy)
                except LineNumberError as e:
                    print(e.msg)
                
    except Exception as e:
        print(e)
        logging.debug(type(e))
        if args.debug:
            traceback.print_exc()
    
