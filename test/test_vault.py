#!/usr/bin/env python3

import unittest
import os
import io
import sys
import shutil
from unittest import mock
from unittest import TestCase

# import from parent dir
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(PROJECT_DIR))
import vault
ROOT_DIR = os.path.join(PROJECT_DIR, 'root')
TEST_FILE = os.path.join(ROOT_DIR, 'testfile.vault')

# Usage:
# > test_vault.py
# > test_vault.py TestVault.test_remove_unmanaged_forced

class TestVault(unittest.TestCase):
    def setUp(self):
        os.makedirs(ROOT_DIR, exist_ok=True)
        shutil.rmtree(ROOT_DIR)
        os.makedirs(ROOT_DIR, exist_ok=True)
        
    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_insert(self, mocked_getpass, mocked_input):
        print('======= test_insert ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', '', 'l', 'wq']
        
        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1\nline 2')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_insert_nextline(self, mocked_getpass, mocked_input):
        print('======= test_insert_nextline ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', '', 'l', 'i 3', 'line 3', 'line 4', '', 'l', 'w', 'q']
        
        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1\nline 2\nline 3\nline 4')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_insert_outofrange(self, mocked_getpass, mocked_input):
        print('======= test_insert_outofrange ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', '', 'l', 'i 7', 'wq']
        
        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1\nline 2')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_edit(self, mocked_getpass, mocked_input):
        print('======= test_edit ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', '', 'l', 'edit 1', 'one', 'l', 'wq']

        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('one\nline 2')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_newline(self, mocked_getpass, mocked_input):
        print('======= test_newline ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', '', 'l', 'nl', 'l', 'i', 'line 4', '', 'l', 'wq']

        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1\nline 2\n\nline 4')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_delete(self, mocked_getpass, mocked_input):
        print('======= test_delete ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', '', 'l', 'd 2', 'l', 'wq']

        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_delete_range(self, mocked_getpass, mocked_input):
        print('======= test_delete_range ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', 'line 3', 'line 4', '', 'l', 'd 1-3', 'l', 'wq']

        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 4')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_delete_all(self, mocked_getpass, mocked_input):
        print('======= test_delete_all ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', 'line 3', 'line 4', '', 'l', 'd -', 'l', 'wq']

        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_delete_openend(self, mocked_getpass, mocked_input):
        print('======= test_delete_openend ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', 'line 3', 'line 4', '', 'l', 'd 3-', 'l', 'wq']

        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1\nline 2')
    
    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_change_password(self, mocked_getpass, mocked_input):
        print('======= test_change_password ===')
        mocked_getpass.side_effect = ['pwd', 'pwd', 'new-pwd', 'new-pwd']
        mocked_input.side_effect = ['i', 'line 1', 'line 2', '', 'w -p', 'q']
        
        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1\nline 2', password='new-pwd')

    @mock.patch('vault.input', create=True)
    @mock.patch('getpass.getpass', create=True)
    def test_copy_paste(self, mocked_getpass, mocked_input):
        print('======= test_copy_paste ===')
        mocked_getpass.side_effect = ['pwd', 'pwd']
        mocked_input.side_effect = ['i', 'line 1', '', 'l', 'c 1', 'v 2', 'l', 'wq']
        
        with self.assertRaises(SystemExit) as cm:
            vault.main(['--debug', TEST_FILE])
        self.assertEqual(cm.exception.code, 0)
        self.check_content('line 1\nline 1')

    def test_clean(self):
        print('======= test_clean ===')
        shutil.rmtree(ROOT_DIR)
    
    # Helper methods
    @mock.patch('getpass.getpass', create=True)
    def check_content(self, expectedContent, mocked_getpass, password='pwd'):
        mocked_getpass.side_effect = [password, password]
        capturedOutput = io.StringIO()
        sys.stdout = capturedOutput
        vault.main(['--debug', '--export', TEST_FILE])
        sys.stdout = sys.__stdout__
        self.assertEqual(expectedContent, capturedOutput.getvalue().rstrip('\n'))

if __name__ == '__main__':
    unittest.main()
    