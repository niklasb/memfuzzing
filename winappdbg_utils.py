"""
Helpers for winappdbg to replace some of pydbg's functionality.
"""

import winappdbg
from winappdbg import win32

def ui_select_process_id(pattern=''):
  processes = [(p.get_pid(), p.get_filename())
               for p in winappdbg.System() if p.get_filename() and pattern in p.get_filename()]
  if len(processes) == 0:
    raise ValueError, "No such process: %s" % pattern
  if len(processes) == 1:
    return processes[0][0]

  print "===== Please pick a process to monitor ====="
  print "Choice | Process Name (PID)"

  for i, (pid, name) in enumerate(processes):
    print  "[%3d]    %s (%d)" % (i + 1, name, pid)

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

class suspended_threads(object):
  def __init__(self, process):
    self.process = process
  def __enter__(self):
    for thread in self.process.iter_threads(): thread.suspend()
    return self.process
  def __exit__(self, *exc):
    for thread in self.process.iter_threads(): thread.resume()
    return False

def get_seh_chain(thread):
  process = thread.get_process()
  seh_block = thread.get_seh_chain_pointer()
  while seh_block != 0xffffffff:
    try:
      nseh = process.read_pointer(seh_block)
      seh  = process.read_pointer(seh_block + 4)
    except WindowsError:
      return
    yield (nseh, seh)
    seh_block = nseh

def disasm_around(process, address, instr_count=5):
  reference = process.disassemble_instruction(address)
  window_size = (instr_count * 64) // 5
  for start in range(address - window_size, address):
    try:
      instructions = process.disassemble(start, window_size * 2)
      i = instructions.index(reference)
    except (WindowsError, ValueError):
      continue
    return instructions[max(i - instr_count, 0):i + instr_count + 1]
  else:
    raise WindowsError

class ProcessSnapshot(object):
  def __init__(self, process, contexts, pages):
    self.process = process
    self.contexts = contexts
    self.pages = pages

  skip_pages_with_flags = (
    win32.PAGE_READONLY,
    win32.PAGE_EXECUTE_READ,
    win32.PAGE_GUARD,
    win32.PAGE_NOACCESS,
  )

  @classmethod
  def create(cls, process):
    with suspended_threads(process):
      contexts = { thread:thread.get_context() for thread in process.iter_threads() }

      pages = {}
      for mbi in process.get_memory_map():
        if mbi.State != win32.MEM_COMMIT or mbi.Type == win32.MEM_IMAGE:
          continue
        if any(mbi.Protect & flag for flag in cls.skip_pages_with_flags):
          continue

        data = process.read(mbi.BaseAddress, mbi.RegionSize)
        pages[mbi] = data

      return cls(process, contexts, pages)

  def restore(self):
    with suspended_threads(self.process):
      for thread, context in self.contexts.iteritems():
        thread.set_context(context)
      for mbi, data in self.pages.iteritems():
        self.process.poke(mbi.BaseAddress, data)
