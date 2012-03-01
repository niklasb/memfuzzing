"""
Simple memory tracer script, idea based on Tracer.py by sinn3r

Uses winappdbg instead of PyDbg (which doesn't seem to be updated anymore).
"""

import sys, os
import winappdbg
import struct
import argparse
import shutil
from collections import defaultdict
from memfuzzing import ui_select_process_id

class Tracer(object):
  def __init__(self, pid, functions, strings, log):
    self.functions = functions
    self.pid = pid
    self.strings = strings
    self.log = log
    self.injection_points = defaultdict(set)
    self.first_noise = True

  def smart_read_string(self, process, address):
    try:
      head = process.read(address, 10)
    except WindowsError:
      return None
    unicode = all(head[i] == 0 for i in (0, 2, 4)) and all(head[i] != 0 for i in (1, 3, 5))
    return process.peek_string(address, fUnicode=unicode) or None

  def get_injection_points(self):
    return self.injection_points

  def detect_injected_args(self, proc, thread, args):
    for i, arg in enumerate(args):
      stack_offset = (i + 1)*4

      strdata = self.smart_read_string(proc, arg)
      arg_packed = struct.pack(">I", arg)
      for s in self.strings:
        if strdata and s in strdata:
          yield (stack_offset, 1, arg, s)
        if s[:4] in arg_packed or s[:4] in arg_packed[::-1]:
          yield (stack_offset, 0, arg, None)

  def trace_call(self, event, ra, *args):
    proc, thread = event.get_process(), event.get_thread()
    injections = list(self.detect_injected_args(proc, thread, args))
    if not injections:
      if self.first_noise:
        self.log(" ... Noise ...")
        self.log("")
      self.first_noise = False
      return

    function_address = thread.get_pc()

    # save general injection point
    for offset, deref, _, _ in injections:
      self.injection_points[function_address].add((offset, deref))

    # log specific injection
    self.log("function_%08x(" % function_address)
    for offset, deref, arg, data in injections:
      if deref == 0:
        self.log('  [ESP+%s] 0x%08x'    % (offset, arg))
      elif deref == 1:
        self.log('  [ESP+%s] 0x%08x %s' % (offset, arg, repr(data[:10])))
    self.log(");")
    self.log("")
    self.first_noise = True

  def run(self):
    dbg = winappdbg.Debug()
    dbg.attach(self.pid)
    for addr in self.functions:
      dbg.hook_function(self.pid, addr, self.trace_call, paramCount=10)
    self.log("%s hooks added" % len(self.functions))
    self.log("")
    dbg.loop()


def parse_ida_functions(lines):
  for line in lines:
    line = line.strip()
    if not line: continue
    yield int(line.split()[2], 16)

def main():
  parser = argparse.ArgumentParser(description="Trace functions processing user input")
  parser.add_argument("functions_file",
                      help="Functions file in IDA copy&paste format")
  parser.add_argument("pattern",
                      help=("An ASCII pattern to look for. "
                            "First 4 bytes will be traced as DWORD as well"))
  parser.add_argument("-p", "--process",
                      help="The target process. Can be a PID or part of a process name", 
                      default='')
  parser.add_argument("-l", "--logfile",
                      help="The log file to write to (default: ./trace_log.log)",
                      default="trace_log.log")
  args = parser.parse_args()

  try:
    with open(args.functions_file, 'rb') as f:
      functions = list(parse_ida_functions(f))
  except OSError:
    print >>sys.stderr, "Error: Can't read functions file."
    return 1

  try:
    pid = int(args.process)
  except:
    pid = ui_select_process_id(args.process)

  # rotate log files
  for i in reversed(range(3)):
    filename = args.logfile + (".%i" % i if i else "")
    if os.path.exists(filename):
      shutil.move(filename, "%s.%i" % (args.logfile, i + 1))

  # set up logging
  logfile = open(args.logfile, "wb")
  def log(msg):
    print msg
    logfile.write(msg + '\n')

  # start the tracing
  log("Attaching to process with PID %d" % pid)
  tracer = Tracer(pid, functions, strings=[args.pattern], log=log)
  raw_input("Press Return to start the tracing...")
  tracer.run()

  logfile.write("Injection points:\n%s\n" % ("="*20))
  injection_points = tracer.get_injection_points()
  for function_addr in sorted(injection_points):
    args = injection_points[function_addr]
    arglist = ",".join("%d:%d" % (offset, deref) for offset, deref in sorted(args))
    logfile.write("%08x %s\n" % (function_addr, arglist))

if __name__ == "__main__":
  try:
    sys.exit(main() or 0)
  except KeyboardInterrupt:
    sys.exit(1)
