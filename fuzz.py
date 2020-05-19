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

SIZE = [4, 8, 16, 32, 64]
FLIP_ARRAY = [1, 2, 4, 8, 16, 32, 64, 128]
MAGIC_VALS = [
  [0xFF],
  [0x7F],
  [0x00],
  [0xFF, 0xFF], # 0xFFFF
  [0x00, 0x00], # 0x0000
  [0xFF, 0xFF, 0xFF, 0xFF], # 0xFFFFFFFF
  [0x00, 0x00, 0x00, 0x00], # 0x00000000
  [0x00, 0x00, 0x00, 0x80], # 0x80000000
  [0x00, 0x00, 0x00, 0x40], # 0x40000000
  [0xFF, 0xFF, 0xFF, 0x7F], # 0x7FFFFFFF
]

# Global flag to stop the mutator
stop_flag = False

# List of unique crashes
crashes = {}

# list of traces
trace = {}

config = {
  'file': 'mutated.jpg', # name of the target file
  'target': '',     # Location of program to execute
  'corpus': '',     # Initial corpus of files to mutate
  'crashes_dir': 'crashes/', # Where to save crashes
  'seed': None,       # Seed for PRNG
}

class Mutator:
  def __init__(self, core):
    # core set of samples
    self.core = core

    # Data format = > (array of bytearrays, coverage)
    self.trace = set() # Currently observed blocks
    self.corpus =   [] # Corpus of executed samples
    self.pool =     [] # Mutation pool
    self.samples =  [] # Mutated samples

  def __iter__(self):
    # Initiate mutation round
    self._fit_pool()
    self._mutate_pool()
    return self

  def __next__(self):
    if not self.samples:
      self._fit_pool()
      self._mutate_pool()

    global stop_flag
    if stop_flag:
      raise StopIteration
    else:
      return self.samples.pop()

  def _fit_pool(self):
    # fit function for our genetic algorithm
    # Always copy initial corpus
    print('### Fitting round\t\t')
    for sample in self.core:
      self.pool.append((sample, []))
    print('Pool size: {:d} [core samples promoted]'.format(len(self.pool)))

    # Select elements that uncovered new block
    for sample, trace in self.corpus:
      if trace - self.trace: 
        self.pool.append((sample, trace))

    print('Pool size: {:d} [new traces promoted]'.format(len(self.pool)))

    # Backfill to 100
    if self.corpus and len(self.pool) < 100:
      self.corpus.sort(reverse = True, key = lambda x: len(x[1]))

      for _ in range(min(100-len(self.pool), len(self.corpus))):
        # Exponential Distribution
        v = random.random() * random.random() * len(self.corpus)

        self.pool.append(self.corpus[int(v)])
        self.corpus.pop(int(v))
      
      print('Pool size: {:d} [backfill from corpus]'.format(len(self.pool)))
    print('### End of round\t\t')
    
    # Update trace info
    for _, t in self.corpus:
      self.trace |= t

    # Drop rest of the corpus
    self.corpus = []

  def _mutate_pool(self):
    # Create samples by mutating pool
    while self.pool:
      sample,_ = self.pool.pop()
      for _ in range(10):
        self.samples.append(Mutator.mutate_sample(sample))

  def update_corpus(self, data, trace = None):
    self.corpus.append((data, trace))

  @staticmethod
  def mutate_sample(sample):
    _sample = sample[:] # Copy sample

    methods = [
      Mutator.bit_flip,
      Mutator.byte_flip,
      Mutator.magic_number,
      Mutator.add_block,
      Mutator.remove_block,
    ]

    f = random.choice(methods)
    idx = random.choice(range(0, len(_sample)))
    f(idx, _sample)

    return _sample

  @staticmethod
  def bit_flip(index, _sample):
    num = random.choice(SIZE)
    for idx in random.choices(range(len(_sample)), k = num):
      _sample[idx] = _sample[idx] ^ random.choice(FLIP_ARRAY)

  @staticmethod
  def byte_flip(index, _sample):
    num = random.choice(SIZE)
    for idx in random.choices(range(len(_sample)), k = num):
      _sample[idx] = _sample[idx] ^ random.getrandbits(8)

  @staticmethod
  def magic_number(index, _sample):
    selected_magic = random.choice(MAGIC_VALS)

    # guard clause, we don't want to go off by one
    if index > (len(_sample) - len(selected_magic)): 
      index = len(_sample) - len(selected_magic)
    
    for c, v in enumerate(selected_magic):
      _sample[index + c] = v

  @staticmethod
  def add_block(index, _sample):
    size = random.choice(SIZE)
    _sample[index:index] = bytearray((random.getrandbits(8) for i in range(size)))

  @staticmethod
  def remove_block(index, _sample):
    size = random.choice(SIZE)

    _sample = _sample[:index] + _sample[index+size:]


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

def execute_fuzz(dbg, data, bpmap):
  trace = set()
  cmd = [config['target'], config['file']]
  pid = debugger.child.createChild(cmd, no_stdout=True, env=None)
  proc = dbg.addProcess(pid, True)
  base = get_base(proc.readMappings())

  # Insert breakpoints for tracing
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
      ip = proc.getInstrPointer()
      br = proc.findBreakpoint(ip-1).desinstall()
      proc.setInstrPointer(ip-1) # Rewind back to the correct code
      trace.add(ip - base - 1)
    elif event.signum == signal.SIGINT:
      print('Stoping execution')
      proc.detach()
      break
    elif isinstance(event, debugger.ProcessExit):
      proc.detach()
      break
    else:
      print('Something went wrong -> {}'.format(event))
  
  # Program terminated
  return trace

def save_file(data, path='mutated.jpg'):
  with open(path, 'wb+') as fh:
    fh.write(data)

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
      for line in fh.readlines():
        bpmap.extend(list(map(lambda x: int(x.strip(), 16), line.split())))
  else:
    print("No breakpoint map; trace won't be generated")

  return bpmap

def create_config(args):
  config['target'] = args.target
  config['corpus'] = args.corpus
  config['bpmap'] = args.bpmap

  if args.seed:
    config['seed'] = base64.b64decode(seed)

def finish(sig, frame):
  global stop_flag
  print('Finishing fuzz job.')
  stop_flag = True

def main():
  signal.signal(signal.SIGINT, finish)
  parser = argparse.ArgumentParser()
  parser.add_argument('-t', '--target', help = 'target program', 
      required=True)
  parser.add_argument('-b', '--bpmap', help = 'map of breakpoints for trace',
      required=False)
  parser.add_argument('-c', '--corpus', help = 'corpus of files',
      required=True)
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
  print('Starting new fuzzing run with seed {}'.format(
      base64.b64encode(initial_seed).decode('utf-8')))
  
  # Initialize mutator
  mutator = Mutator(corpus)

  counter = 0
  start_time = time.time()
  for sample in mutator:
    save_file(sample)
    trace = execute_fuzz(dbg, sample, bp_map)
    mutator.update_corpus(sample, trace)
    counter += 1

    print('#{:3d} Coverage {:.2f}%\r'.format(
        counter, (len(trace)/len(bp_map)) * 100), end='')

  x = counter / (time.time()-start_time)
  print('-> {:.0f} exec/sec'.format(x))
  
  #cleanup
  dbg.quit()
  save_crashes()

if __name__ == '__main__':
  sys.exit(main())