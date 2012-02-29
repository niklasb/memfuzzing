"""
Simple memory tracer script, idea based on Tracer.py by sinn3r

Uses winappdbg instead of PyDbg (which doesn't seem to be updated anymore).
"""

import sys, os
import winappdbg
import struct

class Tracer:
  def __init__(self, pid, functions, strings, log):
    self.functions = functions
    self.pid = pid
    self.strings = strings
    self.log = log

  def smart_read_string(self, process, address):
    try:
      head = process.read(address, 10)
    except WindowsError:
      return None
    unicode = all(head[i] == 0 for i in (0, 2, 4)) and all(head[i] != 0 for i in (1, 3, 5))
    return process.peek_string(address, fUnicode=unicode) or None

  def trace_call(self, event, ra, *args):
    results = []
    proc = event.get_process()
    for i, arg in enumerate(args):
      stack_offset = (i + 1)*4

      strdata = self.smart_read_string(proc, arg)
      if strdata and '\x00A\x00A' in strdata:
        print "yay."
      arg_packed = struct.pack(">I", arg)
      for s in self.strings:
        if strdata and s in strdata:
          results.append((stack_offset, 'ptr', arg, s))
        if s[:4] in arg_packed or s[:4] in arg_packed[::-1]:
          results.append((stack_offset, 'dword', arg, None))

    if results:
      function_address = hex(event.get_thread().get_pc())[2:]
      self.log("function_%s(" % function_address)
      for offset, control_type, arg, data in results:
        if control_type == 'dword':
          self.log('  [ESP+%s] 0x%08x' % (offset, arg))
        elif control_type == 'ptr':
          self.log('  [ESP+%s] 0x%08x %s' % (offset, arg, repr(data[:10])))
      self.log(");")
      self.log("")

  def run(self):
    dbg = winappdbg.Debug()
    dbg.attach(self.pid)
    for addr in self.functions:
      dbg.hook_function(self.pid, addr, self.trace_call, paramCount=10)
    self.log("%s hooks added" % len(self.functions))
    self.log("")
    dbg.loop()


def select_process_id(pattern=''):
  processes = [(p.get_pid(), p.get_filename())
               for p in winappdbg.System() if p.get_filename() and pattern in p.get_filename()]
  if len(processes) == 0:
    raise ValueError, "No such process: %s" % pattern
  if len(processes) == 1:
    return processes[0][0]

  print "===== Please pick a process to monitor ====="
  print "Choice | Process Name (PID)"

  for i, (pid, name) in enumerate(processes):
    print  "[%3d]    %s (%d)" % (i+1, name, pid)

  while 1:
    try:
      index = int(raw_input("Choose wise: "))
      if 1 <= index <= len(processes): break
      break
    except KeyboardInterrupt:
      raise
    except:
      print "\nIncorrect input."
      continue

  return processes[index - 1][0]

def parse_ida_functions(lines):
  for line in lines:
    if not line.startswith("sub_"): continue
    yield int(line.split()[0].replace("sub_", ""), 16)

def main():
  if len(sys.argv) not in (3, 4):
    print "Usage: %s functions.txt pattern [pid/part of proc name]" % sys.argv[0]
    return 1

  try:
    with open(sys.argv[1], 'rb') as f:
      functions = list(parse_ida_functions(f))
  except OSError:
    print "[*] Can't read functions file"
    return 1

  pattern = sys.argv[2]

  if len(sys.argv) >= 4:
    proc = sys.argv[3]
    try:
      pid = int(sys.argv[3])
    except:
      pid = select_process_id(proc)
  else:
    pid = select_process_id()

  # set up logging
  logfile = open("tracer_log.txt", "wb")
  def log(msg):
    print msg
    logfile.write(msg + '\n')

  # start the tracing
  tracer = Tracer(pid, functions, strings=[pattern], log=log)
  raw_input("Press Return to start the tracing...")
  tracer.run()

if __name__ == "__main__":
  try:
    sys.exit(main() or 0)
  except KeyboardInterrupt:
    sys.exit(1)
