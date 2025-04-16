"""
Test script for comparing C AES implementation with the Python one.
"""

import ctypes
import os
import random
import sys
import unittest
import copy
from aes import AES, sub_bytes, shift_rows, mix_columns, inv_sub_bytes, inv_shift_rows, inv_mix_columns

# Load the shared library
try:
    rijndael = ctypes.CDLL('./rijndael.so')
except OSError:
    print("Error: Could not load the rijndael.so library.")
    print("Make sure to compile the C code with 'make' before running this test.")
    sys.exit(1)


rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
rijndael.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]

rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
rijndael.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]

class TestAESImplementation(unittest.TestCase):
    def generate_random_data(self, size=16):
        """Generate random data of specified size."""
        return bytes([random.randint(0, 255) for _ in range(size)])

    def test_sub_bytes(self):
        """Test the SubBytes operation."""
        if hasattr(rijndael, 'sub_bytes'):
            rijndael.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
            
            for _ in range(3):  # Test with 3 random inputs
                # Create random data
                data = self.generate_random_data()
                
                # Create C array for input
                c_data = (ctypes.c_ubyte * 16)(*data)
                
                # Create Python state matrix and apply operation
                py_state = [list(data[i:i+4]) for i in range(0, len(data), 4)]
                sub_bytes(py_state)
                py_result = bytes(sum(py_state, []))
                
                # Apply C operation
                rijndael.sub_bytes(c_data)
                c_result = bytes(c_data)
                
                # Compare results
                self.assertEqual(c_result, py_result)
        else:
            print("sub_bytes not exposed for testing")

    def test_shift_rows(self):
        """Test the ShiftRows operation."""
        if hasattr(rijndael, 'shift_rows'):
            rijndael.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
            
            for _ in range(3):  # Test with 3 random inputs
                # Create random data
                data = self.generate_random_data()
                
                # Create C array for input
                c_data = (ctypes.c_ubyte * 16)(*data)
                
                # Create Python state matrix and apply operation
                py_state = [list(data[i:i+4]) for i in range(0, len(data), 4)]
                shift_rows(py_state)
                py_result = bytes(sum(py_state, []))
                
                # Apply C operation
                rijndael.shift_rows(c_data)
                c_result = bytes(c_data)
                
                # Compare results
                self.assertEqual(c_result, py_result)
        else:
            print("shift_rows not exposed for testing")

    def test_mix_columns(self):
        """Test the MixColumns operation."""
        if hasattr(rijndael, 'mix_columns'):
            rijndael.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
            
            for _ in range(3):  # Test with 3 random inputs
                # Create random data
                data = self.generate_random_data()
                
                # Create C array for input
                c_data = (ctypes.c_ubyte * 16)(*data)
                
                # Create Python state matrix and apply operation
                py_state = [list(data[i:i+4]) for i in range(0, len(data), 4)]
                mix_columns(py_state)
                py_result = bytes(sum(py_state, []))
                
                # Apply C operation
                rijndael.mix_columns(c_data)
                c_result = bytes(c_data)
                
                # Compare results
                self.assertEqual(c_result, py_result)
        else:
            print("mix_columns not exposed for testing")

    
    def test_full_encryption_decryption(self):
        """Test the full encryption and decryption process."""
        for _ in range(3):  # Test with 3 random inputs
            # Generate random plaintext and key
            plaintext = self.generate_random_data()
            key = self.generate_random_data()
            
            # Create C arrays
            c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)
            c_key = (ctypes.c_ubyte * 16)(*key)
            
            # Encrypt with Python
            py_aes = AES(key)
            py_ciphertext = py_aes.encrypt_block(plaintext)
            
            # Encrypt with C
            c_ciphertext_ptr = rijndael.aes_encrypt_block(c_plaintext, c_key)
            c_ciphertext = bytes(c_ciphertext_ptr[i] for i in range(16))
            
            # Compare encryption results
            self.assertEqual(c_ciphertext, py_ciphertext)
            
            # Create C array for ciphertext for decryption
            c_encrypted = (ctypes.c_ubyte * 16)(*c_ciphertext)
            
            # Decrypt with Python
            py_decrypted = py_aes.decrypt_block(py_ciphertext)
            
            # Decrypt with C
            c_decrypted_ptr = rijndael.aes_decrypt_block(c_encrypted, c_key)
            c_decrypted = bytes(c_decrypted_ptr[i] for i in range(16))
            
            # Compare decryption results
            self.assertEqual(c_decrypted, py_decrypted)
            
            # Verify we got back to the original plaintext
            self.assertEqual(c_decrypted, plaintext)
