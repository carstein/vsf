#!/usr/bin/env python3

import argparse
import sys
import binaryninja as bn

skip_func = ['__libc_csu_init', 
             '__libc_csu_fini', 
             '_fini',
             '__do_global_dtors_aux',
             '_start',
             '_init',
             'sub_1034']

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-b', '--binary', help = 'binary to analyze', 
      required=True)
  args = parser.parse_args()

  bv = bn.BinaryViewType.get_view_of_file(args.binary)

  # select appropriate segment
  for s in bv.segments:
    if s.executable:
      base = s.start

  for func in bv.functions:
    # filter out the list of functions
    if func.symbol.type == bn.SymbolType.ImportedFunctionSymbol: continue
    if func.name in skip_func: continue

    #output = "{}: ".format(func.name)
    output = ""
    for bb in func:
      output += "0x{:x} ".format(bb.start-base)
      #break
    print(output)

if __name__ == '__main__':
  sys.exit(main())