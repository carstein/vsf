#!/usr/bin/env python3
# VSF: Very Simple Fuzzer
# author: carstein <michal.melewski@gmail.com>

import argparse
import random
import sys
import signal

from ptrace import debugger

FLIP_RATIO = 0.01 # 1% ratio of bit flips
FLIP_ARRAY = [1, 2, 4, 8, 16, 32, 64, 128]

MAGIC_VALS = [
  [0xFF],
  [0x7F],
  [0x00],
  [0xFF, 0xFF], # 0xFFFF
  [0x00, 0x00], # 0x0000
  [0xFF, 0xFF, 0xFF, 0xFF], # 0xFFFFFFFF
  [0x00, 0x00, 0x00, 0x00], # 0x80000000
  [0x00, 0x00, 0x00, 0x80], # 0x80000000
  [0x00, 0x00, 0x00, 0x40], # 0x40000000
  [0xFF, 0xFF, 0xFF, 0x7F], # 0x7FFFFFFF
]

def usage():
  print("Usage: {} <valid_jpg>".format(sys.argv[0]))

def execute_fuzz(dbg, data, counter):
  cmd = ['exif/exif', 'data/mutated.jpg']
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  try:
    sig = dbg.waitSignals()
  except:
    return
  
  if sig.signum == signal.SIGSEGV:
    proc.detach()
    with open("crashes/crash.{}.jpg".format(counter), "wb+") as fh:
      fh.write(data)

def create_new(data):
  path = "data/mutated.jpg"
  with open(path, "wb+") as fh:
    fh.write(data)

def magic(data, idx):
  picked_magic = random.choice(MAGIC_VALS)

  offset = 0
  for m in picked_magic:
    data[idx + offset] = m
    offset += 1

def bit_flip(byte):
  return byte ^ random.choice(FLIP_ARRAY)

def mutate(data):
  flips = int((len(data)-4) * FLIP_RATIO)
  flip_indexes = random.choices(range(2, (len(data) - 6)), k=flips)

  methods = [0,1]
  
  for idx in flip_indexes:
    method = random.choice(methods)

    if method == 0:
      data[idx] = bit_flip(data[idx])
    else:
      magic(data, idx)

  return data

def get_bytes(filename):
  with open(filename, "rb") as fh:
    return bytearray(fh.read())

def main():
  if len(sys.argv) < 2:
    usage()
  else:
    filename = sys.argv[1]
    orig_data = get_bytes(filename)
    dbg = debugger.PtraceDebugger()

    counter = 0
    while counter < 100000:
      data = orig_data[:]
      mutated_data = mutate(data)
      create_new(mutated_data) # new file 
      execute_fuzz(dbg, mutated_data, counter)

      if counter % 100 == 0:
        print("Counter: {}\r".format(counter),file=sys.stderr, end='')
      
      counter += 1 

    dbg.quit()

if __name__ == "__main__":
  sys.exit(main())