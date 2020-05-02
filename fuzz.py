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
import time

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

# List of unique crashes
crashes = {}

# list of traces
trace = {}

config = {
  'file': 'mutated.jpg', # name of the target file
  'target': '',     # Location of program to execute
  'corpus': '',     # Initial corpus of files to mutate
  'crashes_dir': 'crashes/', # Where to save crashes
  'rounds': 100000,  # How many fuzz iterations to run
  'seed': None,       # Seed for PRNG
}


def load_map(filename):
  with open(filename, 'r') as fh:
    for line in fh.readlines():
      pass

def save_crashes():
  print('Saving crashes...')
  crash_dir = config['crashes_dir']
  
  if not os.path.exists(crash_dir):
    os.mkdir(crash_dir)

  for ip, data in crashes.items():
    filename = 'crash.{:x}.jpg'.format(ip)
    with open(os.path.join(crash_dir, filename), 'wb+') as fh:
      fh.write(data)
  
  print('{} unique crashes.'.format(len(crashes)))

def get_base(vmmap):
  for m in vmmap:
    if 'x' in m.permissions and m.pathname.endswith(os.path.basename(config['target'])):
      return m.start

def execute_fuzz(dbg, data, counter, bpmap):
  trace = []
  cmd = [config['target'], config['file']]
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  base = get_base(proc.readMappings())

  # Inser breakpoints for tracing
  if bpmap:
    for offset in bpmap:
      proc.createBreakpoint(base + offset)
  
  while True:
    proc.cont()
    event = dbg.waitProcessEvent()
    
    if event.signum == signal.SIGSEGV:
      crash_ip = proc.getInstrPointer() - base - 1 # getInstrPointer() always returns instruction + 1
      if crash_ip not in crashes:
        crashes[crash_ip] = data
      proc.detach()
      break
    elif event.signum == signal.SIGTRAP:
      trace.append(proc.getInstrPointer() - base - 1)
    elif isinstance(event, debugger.ProcessExit):
      proc.detach()
      break
    else:
      print(event)
  
  # Program terminated
  return trace

def create_new(data):
  path = 'mutated.jpg'
  with open(path, 'wb+') as fh:
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
    with open(path, 'rb') as fh:
      corpus.append(bytearray(fh.read()))
  elif os.path.isdir(path):
    for file in os.listdir(path):
      if os.path.isfile(file):
        with open(file, 'rb') as fh:
          corpus.append(bytearray(fh.read()))

  return corpus

def get_bpmap(path):
  bpmap = []

  if path and os.path.isfile(path):
    with open(path, "r") as fh:
      bpmap = list(map(lambda x: int(x.strip(), 16), fh.readlines()))
  else:
    print("No breakpoint map; trace won't be generated")

  return bpmap

def create_config(args):
  config['target'] = args.target
  config['corpus'] = args.corpus
  config['bpmap'] = args.bpmap
  
  if args.rounds:
    config['rounds'] = int(args.rounds)

  if args.seed:
    config['seed'] = base64.b64decode(seed)

def finish(sig, frame):
  print('Finishing fuzz job.')
  # Add function to dump all crashes
  save_crashes()
  sys.exit(1)

def main():
  signal.signal(signal.SIGINT, finish)
  parser = argparse.ArgumentParser()
  parser.add_argument('-t', '--target', help = 'target program', 
      required=True)
  parser.add_argument('-b', '--bpmap', help = 'map of breakpoints for trace',
      required=False)
  parser.add_argument('-c', '--corpus', help = 'corpus of files',
      required=True)
  parser.add_argument('-r', '--rounds', help = 'number of rounds', 
      required=False)
  parser.add_argument('-s', '--seed', help = 'seed for PRNG', 
      required=False)
  create_config(parser.parse_args())

  bp_map = get_bpmap(config['bpmap'])
  corpus = get_corpus(config['corpus'])
  dbg = debugger.PtraceDebugger()

  # Seed the PRNG
  if config['seed']:
    initial_seed = config['seed']
  else:
    initial_seed = os.urandom(24)
    
  random.seed(initial_seed)
  print('Starting new fuzzing run with seed {}'.format(base64.b64encode(initial_seed).decode('utf-8')))
  
  # Fuzz loop
  for file in corpus:
    counter = 0
    start_time = time.time()
    while counter < config['rounds']:
      data = file[:]
      mutated_data = mutate(data)
      create_new(mutated_data)
      t = execute_fuzz(dbg, mutated_data, counter, bp_map)
      counter += 1
    
    x = counter / (time.time()-start_time)
    print('-> {:.0f} exec/sec'.format(x))
  
  #cleanup
  dbg.quit()
  save_crashes()

if __name__ == '__main__':
  sys.exit(main())