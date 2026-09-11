#!/usr/bin/env python3
"""Statically de-obfuscate AppleScript that hides strings as
(ASCII character N) / (character id N) concatenations. Never executes anything.
Usage: python3 deobfuscate_applescript.py <file.applescript>"""
import re, sys
s = open(sys.argv[1]).read().replace('\r', '')
s = re.sub(r'\((?:ASCII character|character id) (\d+)\)',
           lambda m: '"' + chr(int(m.group(1))).replace('"', '\\"') + '"', s)
prev = None
while prev != s:
    prev = s
    s = re.sub(r'"((?:[^"\\]|\\.)*)" & "((?:[^"\\]|\\.)*)"', r'"\1\2"', s)
print(s)
