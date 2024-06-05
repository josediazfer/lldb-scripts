#!/usr/bin/python3


# Requiere export LLDB_DEBUGSERVER_PATH=/usr/bin/lldb-server-10
# Sino no encuentra el ejecutable lldb-server que lanza el ejecutable a depurar

import lldb
import os
import tempfile
import atexit
import sys

def set_lldb_expr_prefix_file(debugger, expr_file):
  interpreter = debugger.GetCommandInterpreter()
  rto = lldb.SBCommandReturnObject()
  interpreter.HandleCommand("settings set target.language c", rto);
  interpreter.HandleCommand("settings set target.expr-prefix %s" % expr_file, rto)
  if not rto.Succeeded():
     raise Exception("failed to execute lldb command!")

def process_close_fd(fd):
    interpreter = debugger.GetCommandInterpreter()
    rto = lldb.SBCommandReturnObject()
    interpreter.HandleCommand("e -l c -- close(%d)" % fd, rto) 
    if not rto.Succeeded():
       raise Exception("failed to execute lldb command!")

def gen_lldb_expr_file():
    fp = tempfile.NamedTemporaryFile(delete=False)
    atexit.register(lambda : os.unlink(fp.name))
    fp.write(rb"""extern "C" {
    int close(int);
}
""")
    fp.close()

    return fp.name

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("usage:\n   proc-close-fd proc_name|pid fd")
        exit(1)

    # Create a new debugger instance
    proc_name = sys.argv[1]
    proc_fd = int(sys.argv[2])
    debugger = lldb.SBDebugger.Create()
    expr_config_file = gen_lldb_expr_file()
    set_lldb_expr_prefix_file(debugger, expr_config_file)
    target = debugger.CreateTarget('')
    error = lldb.SBError()

    if (os.getenv("LLDB_DEBUG") != None):
        debugger.EnableLog("lldb", os.getenv("LLDB_DEBUG").split(","))

    if proc_name.isnumeric():
        process = target.AttachToProcessWithID(debugger.GetListener(), int(proc_name), error)
    else:
        process = target.AttachToProcessWithName(debugger.GetListener(), proc_name, False, error)
    if (process == None or not error.Success()):
        raise Exception("can not attach to process '%s' - %s" % (proc_name, error.GetCString()));

    print("attached to process '%s'" % proc_name)
    process_close_fd(proc_fd)
    process.Detach()
    print("file descriptor closed with the number '%d'" % proc_fd)
