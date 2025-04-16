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