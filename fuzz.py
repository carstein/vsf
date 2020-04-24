#!/usr/bin/env python3
# VSF: Very Simple Fuzzer
# author: carstein <michal.melewski@gmail.com>

import argparse
import base64
import os
import os.path
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

# Gather unique crashes
crashes = {}

config = {
  'file': 'mutated.jpg', # name of the target file
  'target': '',     # Location of program to execute
  'corpus': '',     # Initial corpus of files to mutate
  'crashes_dir': 'crashes/', # Where to save crashes
  'rounds': 100000,  # How many fuzz iterations to run
  'seed': None,       # Seed for PRNG
}

def save_crashes():
  print("Saving crashes...")
  crash_dir = config['crashes_dir']
  
  if not os.path.exists(crash_dir):
    os.mkdir(crash_dir)

  for ip, data in crashes.items():
    filename = "crash.{:x}.jpg".format(ip)
    with open(os.path.join(crash_dir, filename), "wb+") as fh:
      fh.write(data)
  
  print("{} unique crashes.".format(len(crashes)))

def absolute_address(ip, mappings):
  for mapping in mappings:
    if ip in mapping:
      return ip-mapping.start

def execute_fuzz(dbg, data, counter):
  cmd = [config['target'], config['file']]
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  proc.cont()

  event = dbg.waitProcessEvent()
  
  if event.signum == signal.SIGSEGV:
    crash_ip = absolute_address(proc.getInstrPointer(), proc.readMappings())
    if crash_ip not in crashes:
      crashes[crash_ip] = data
    proc.detach()
  else:
    proc.detach()

def create_new(data):
  path = "mutated.jpg"
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

def get_corpus(path):
  corpus = []

  if os.path.isfile(path):
    with open(path, "rb") as fh:
      corpus.append(bytearray(fh.read()))
  elif os.path.isdir(path):
    for file in os.listdir(path):
      if os.path.isfile(file):
        with open(file, "rb") as fh:
          corpus.append(bytearray(fh.read()))

  return corpus


def create_config(args):
  config['target'] = args.target
  config['corpus'] = args.corpus
  
  if args.rounds:
    config['rounds'] = int(args.rounds)

  if args.seed:
    config['seed'] = base64.b64decode(seed)

def finish(sig, frame):
  print("Finishing fuzz job.")
  # Add function to dump all crashes
  save_crashes()
  sys.exit(1)

def main():
  signal.signal(signal.SIGINT, finish)
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--target", help = "target program", 
      required=True)
  parser.add_argument("-c", "--corpus", help = "corpus of files",
      required=True)
  parser.add_argument("-r", "--rounds", help = "number of rounds", 
      required=False)
  parser.add_argument("-s", "--seed", help = "seed for PRNG", 
      required=False)
  create_config(parser.parse_args())

  corpus = get_corpus(config['corpus'])
  dbg = debugger.PtraceDebugger()

  # Seed the PRNG
  if config['seed']:
    initial_seed = config['seed']
  else:
    initial_seed = os.urandom(24)
    
  random.seed(initial_seed)
  print("Starting new fuzzing run with seed {}".format(base64.b64encode(initial_seed).decode('utf-8')))

  # Fuzz loop
  for file in corpus:
    counter = 0
    while counter < config['rounds']:
      data = file[:]
      mutated_data = mutate(data)
      create_new(mutated_data)
      execute_fuzz(dbg, mutated_data, counter)

      if counter % 100 == 0:
        print("Counter: {}\r".format(counter),file=sys.stderr, end='')
      
      counter += 1
  
  #cleanup
  dbg.quit()
  save_crashes()

if __name__ == "__main__":
  sys.exit(main())