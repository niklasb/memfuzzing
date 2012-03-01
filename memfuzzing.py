"""
Some shared code between tracer.py and fuzzer.py
"""

import winappdbg

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
