"""
Simple memory tracer script, idea/code based on InMemoryFuzzer.py by sinn3r

Uses winappdbg instead of PyDbg (which doesn't seem to be updated anymore).
"""

import os, sys
import random
import time
import struct
import argparse

import winappdbg
from winappdbg import win32

from winappdbg_utils import ui_select_process_id, ProcessSnapshot, get_seh_chain, disasm_around
import templates

class FuzzGenerator(object):
  def __init__(self, seed=None):
    self.max_size = 30000
    self.common_delimiters = ["\x0a", "\x0d", ",", ".", ":", ";",
          "&", "%", "$", "\x20", "\x00", "#",
          "(", ")", "{", "}", "<", ">", "\"",
          "'", "\\", "|", "@", "*", "-"]

    self.common_strings = [ "\x41"*500,  "\x41"*1000, "\x41"*2000,
          "\x41"*3000, "\x41"*4000, "\x41"*5000,
          "\x41"*6000, "\x41"*7000, "\x41"*8000,
          "\x41"*10000,"\x41"*11000,"\x41"*12000,
          "~!@#$^&"*1000,  "~!@#$^&"*2000,
          "~!@#$^&"*3000,  "~!@#$^&"*4000,
          "~!@#$^&"*5000,  "%n%n%n%n%n", "%p%p%p%p",
          "%s"*500, "%x"*1000, "../"*1000,
          "../"*5000, "%%20x", "%2e%2e/"*1000,
          "16777215", "0x99999999", "0xffffffff",
          "%u000", "AAAA"+"../"+"A"*300, "%"+"A"*3000]

    self.random = random.Random(seed)

  def size(self):
    return self.random.randint(1, self.max_size)

  def binary(self):
    return ''.join(chr(self.random.randint(1, 128)) for i in range(self.size()))

  def ascii(self):
    return ''.join(chr(self.random.randint(65, 90)) for i in range(self.size()))

  def delimiter(self):
    return self.common() + self.random.choice(self.common_delimiters) + self.common()

  def common(self):
    return self.random.choice(self.common_strings)

  def surprise(self):
    return self.random.choice([self.common, self.delimiter, self.ascii, self.binary])()


class Report(object):
  def __init__(self, output_dir):
    self.exceptions = {}
    self.output_dir = output_dir
    with open(os.path.join(self.output_dir, "javascript.js"), "wb") as f:
      f.write(templates.crash_report_javascript)

  def add_exception(self, **exception):
    key = (exception["hook_addr"], exception["hook_arg"], exception["fault_addr"])
    if key in self.exceptions: return
    self.exceptions[key] = exception

    report = templates.crash_report_html.format(
                   input_size=len(exception["input"]),
                   hexdata=' '.join("%02x" % ord(b) for b in exception["input"]),
                   **exception)
    basename = "exception_%08x_%d_%08x.html" % key
    with open(os.path.join(self.output_dir, basename), "wb") as f:
      f.write(report)


class InMemoryFuzzer(winappdbg.EventHandler):
  def __init__(self, pid, hooks, report, source=None, badchars='\x00'):
    self.pid = pid

    self.badchars = badchars

    self.hooks = hooks
    self.hook_iter = iter(hooks)
    self.hook_addr = None
    self.hook_arg = 0
    self.hook_index = 0

    self.fuzz_counter = 0

    self.snapshot = None

    self.data_addr = None
    self.data = None

    self.source = source or FuzzGenerator()
    self.report = report

    self.dbg = None

  def pattern_offset(self, pattern):
    return self.data.find(pattern)

  def filter_bad_chars(self, data):
    return ''.join(c for c in data if c not in self.badchars)

  def dbgMonitor(self, pydbg):
    """
    Responsible for moving on to the next function, or terminate if all routines are fuzzed

    Parameter:
    pydbg - pydbg object that's attached to a process
    """
    if self.counter >= maxFuzzCount:
      #Reset everything for the next hooks
      if self.lastChunkAddr != 0x00000000:
        #If the last chunk hasn't been freed before the new one, free now!
        self.freeLastChunk(pydbg)
      pydbg.suspend_all_threads()
      pydbg.bp_del(self.hooks[self.hookIndex][0])  #Delete the entry hoook
      pydbg.bp_del(self.hooks[self.hookIndex][1])  #Delete the restore hook
      self.snapshotTaken = False
      self.hookIndex += 1        #Next set of hook points
      if self.hookIndex >= self.hooksSize:
        #It appears we're done fuzzing all the routines, closing app
        print "[*] We're done fuzzing."
        self.reporter.dump()      #Save results to disk before exiting
        pydbg.detach()
        pydbg.terminate_process()
        print "[*] Process terminated\r\n"
        self.analyze()
        sys.exit(0)
      print "[*] Moving on to the next routine..."
      pydbg.bp_set(self.hooks[self.hookIndex][0])  #Set a new snapshot point
      pydbg.bp_set(self.hooks[self.hookIndex][1])  #Set a new restore point
      self.counter = 0
      pydbg.process_restore()
      pydbg.resume_all_threads()

  def get_mem_overview(self, process, address):
    try:
      return "%s" % repr(process.read(address, 8))
    except:
      return ""

  violation_types = {
    win32.EXCEPTION_READ_FAULT    : 'read',
    win32.EXCEPTION_WRITE_FAULT   : 'write',
    win32.EXCEPTION_EXECUTE_FAULT : 'execute'
  }

  def access_violation(self, event):
    if event.is_first_chance():
      hook_info = [
        'Routine #%s' % str(self.hook_index + 1),
        'Entry point: %08x' % self.hook_addr,
        'Argument:    ESP+%d' % self.hook_arg,
      ]
      fault_address = event.get_fault_address()
      violation = "%s violation on %08x" % (self.violation_types[event.get_fault_type()],
                                            fault_address)
      bug_type = None

      print "test"
      thread, process = event.get_thread(), event.get_process()
      context = thread.get_context()
      regs = ['%s=%08x %s' % (reg.upper(), context[reg], self.get_mem_overview(process, context[reg]))
              for reg in ['Eax', 'Ecx', 'Edx', 'Ebx', 'Esp', 'Ebp', 'Esi', 'Edi', 'Eip']]

      pc = thread.get_pc()
      try:
        disasm = disasm_around(process, pc, 15)
      except WindowsError:
        disasm = [(pc, 0, '[disassembly not available]', '00')]
      instruction_dump = ["0x%08x  %s%s" % (addr, instruction.lower(),
                                            '  <--- Crash' if addr == pc else '')
                          for addr, size, instruction, hex in disasm]

      sehdump = ["Next SEH record  SE Handler    Offset"]
      for nseh, seh in get_seh_chain(thread):
        offset = self.pattern_offset(struct.pack("<I", nseh))
        sehdump.append('%08x         %08x      %s' % (nseh, seh, str(offset) if offset > 0 else ''))
        if not bug_type and nseh == seh != 0xffffffff or offset >= 0:
            bug_type = "This appears to be a stack overflow: SEH overwrite"

      eip_offset = self.pattern_offset(struct.pack("<I", pc))
      if not bug_type and eip_offset >= 0:
        bug_type = "This appears to be a stack overflow: EIP overwrite"

      unlines = '\n'.join

      for line in hook_info:
        print '[*]', line
      print "[*] %s%s" % (violation, ' (%s)' % bug_type if bug_type else '')

      self.report.add_exception(
        hook_info  = unlines(hook_info),
        hook_addr  = self.hook_addr,
        hook_arg   = self.hook_arg,
        fault_addr = fault_address,
        violation  = violation,
        registers  = unlines(regs),
        assembly   = unlines(instruction_dump),
        seh        = unlines(sehdump),
        bug_type   = bug_type or 'n/a',
        input      = self.data,
      )

    event.continueStatus = win32.DBG_EXCEPTION_HANDLED

  def handle_function_enter(self, event):
    thread, process = event.get_thread(), event.get_process()
    ra = process.read_pointer(thread.get_sp())
    event.debug.break_at(process.get_pid(), ra, self.handle_function_leave)

    try:
      if not self.snapshot:
        self.snapshot = ProcessSnapshot.create(event.get_process())
      else:
        self.snapshot.restore()

      data = self.source.surprise()
      data = self.filter_bad_chars(data) + "\x00"

      if self.data_addr:
        win32.VirtualFreeEx(process.get_handle(), self.data_addr, 0)
      data_addr = win32.VirtualAllocEx(process.get_handle(),
                                       0, len(data),
                                       win32.MEM_COMMIT,
                                       win32.PAGE_READWRITE)
      assert data_addr != 0
      process.write(data_addr, data)

      self.data_addr, self.data = data_addr, data

      arg_offset = self.hook_arg
      process.write_pointer(thread.get_sp() + arg_offset, data_addr)
      self.fuzz_counter += 1
    except:
      import traceback
      print traceback.format_exc(sys.exc_info()[1])
      sys.exit(1)

  def handle_function_leave(self, event, *args):
    event.get_thread().set_pc(self.hook_addr)

  def next_hook(self):
    try:
      self.snapshot = None
      # remove old breakpoints
      if self.hook_addr:
        self.dbg.dont_hook_function(self.hook_addr)
      self.hook_addr, self.hook_arg = next(self.hook_iter)
      self.dbg.break_at(self.pid, self.hook_addr, self.handle_function_enter)
      print "[*] Ok! Trigger the hook point %08x for me will ya?" % self.hook_addr
      self.dbg.loop()
    except StopIteration:
      return False
    else:
      return True

  def run(self):
    self.dbg = winappdbg.Debug(self)
    self.dbg.attach(self.pid)
    self.next_hook()
    #dbg.set_callback(USER_CALLBACK_DEBUG_EVENT, self.dbgMonitor)  #Set User Call Back Handler


def parse_hookpoints(stream):
  for line in stream:
    line = line.strip()
    if not line or line.startswith("#"): continue
    arguments = line.split()
    yield (int(arguments[0], 16), int(arguments[1]))

def main():
  parser = argparse.ArgumentParser(description="In-memory fuzzer")
  parser.add_argument("hook_file",
                      help="Hooks input file (line format: <funcaddr> <argument>)")
  parser.add_argument("-p", "--process",
                      help="The target process. Can be a PID or part of a process name",
                      default='')
  parser.add_argument("-o", "--output-dir",
                      help="The output directory to write to (default: ./crashbin)",
                      default="crashbin")
  parser.add_argument("-s", "--seed", type=int,
                      help="Seed to be used for the RNG (defaults to random)")
  args = parser.parse_args()

  with open(args.hook_file, 'r') as f:
    hooks = list(parse_hookpoints(f))

  try:
    pid = int(args.process)
  except:
    pid = ui_select_process_id(args.process)

  # make output dir
  if not os.path.exists(args.output_dir):
    os.mkdir(args.output_dir)

  fuzzer = InMemoryFuzzer(pid, hooks,
                          report=Report(args.output_dir),
                          source=FuzzGenerator(args.seed))

  print "Attaching to process with PID %d" % pid
  fuzzer.run()

if __name__ == "__main__":
  sys.exit(main() or 0)
