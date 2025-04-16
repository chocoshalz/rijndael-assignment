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
