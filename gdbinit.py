import os
import json
import atexit
import signal

import pwndbg
from pwndbg.commands.context import contextoutput

clear_context = False # I like being able to scroll up

# Would it be more sensical to use the kitten python API? Yes. Yes it would.

def panic(ret: int, msg):
    # We let the user read the error message before exiting
    # because exiting directly will close the debugger window
    # if it was spawned from pwntools
    print(msg)
    input("Press Enter to exit...")
    exit(ret)

def pid_from_id(id: int):
    ls = json.loads(os.popen(f"kitten @ ls --match id:{id}").read())
    panes_pid[id] = int(ls[0]["tabs"][0]["windows"][0]["pid"])
    return panes_pid[id]

def path_from_id(id: int):
    # return os.popen(f"kitten @ ls | jq -r '.[] | .tabs[].windows[] | select(.id == {id}) | .pid' | xargs -I{{}} ls -l /proc/{{}}/fd | grep pts | awk '{{print $NF}}' | uniq").read().strip()
    pid = pid_from_id(id)
    fd_path = f"/proc/{pid}/fd"
    open_fds = os.listdir(fd_path)
    fd_paths = [
        os.readlink(os.path.join(fd_path, fd))
        for fd in open_fds
    ]
    for p in fd_paths:
        if p.startswith("/dev/pts/"):
            return p
    panic(4, f"Couldn't find path from window id {id}, pid {pid}")

def number_of_windows():
    # return int(os.popen("kitten @ ls | jq '[.[].tabs[] | select(.is_focused)] | .[0].windows | length'").read().strip())
    ls = json.loads(os.popen("kitten @ ls").read())
    for oswindow in ls:
        for tab in oswindow["tabs"]:
            if tab["is_focused"]:
                return len(tab["windows"])
    return 0

def get_focused_id():
    # return int(os.popen("kitten @ ls | jq '.[].tabs[].windows[] | select(.is_self).id'").read().strip())
    ls = json.loads(os.popen("kitten @ ls --match state:focused").read())
    return int(ls[0]["tabs"][0]["windows"][0]["id"])

def open_layout(one_already_open: bool):
    if one_already_open:
        # Since the main pane/section doesn't need to be very wide
        # we can give the pwntools output more space
        os.popen("kitten @ resize-window --axis=horizontal --increment=-5").read()
        
    panes["disasm"] = os.popen('kitten @ launch --location=hsplit --cwd=current --bias=25 cat').read().strip()

    if not one_already_open:
        # https://github.com/kovidgoyal/kitty/issues/4216
        os.popen("kitten @ action layout_action rotate 180").read()
    else:
        # In case the screen was already vertically split because of another window (e.g. pwntools output)
        os.popen("kitten @ action layout_action move_to_screen_edge top").read().strip()
        os.popen("kitten @ action layout_action bias 75").read()

    panes["stack"] = os.popen("kitten @ launch --location=hsplit --cwd=current --bias=40 cat").read().strip()
    panes["backtrace"] = os.popen("kitten @ launch --location=after --cwd=current --bias=30 cat").read().strip()
    os.popen(f"kitten @ focus-window --match id:{panes["disasm"]}").read()
    panes["regs"] = os.popen("kitten @ launch --location=after --cwd=current --bias=40 cat").read().strip()
    # os.popen(f"kitten @ focus-window --match id:{main_section}").read()
    # panes["python"] = os.popen("kitten @ launch --location=after --cwd=current --bias=30 python").read().strip()
    os.popen(f"kitten @ focus-window --match id:{main_section}").read()

def attach_to_pwndbg():
    panes_paths = {}
    for sec in panes:
        panes_paths[sec] = path_from_id(int(panes[sec])) 

    # Tell pwndbg which panes are to be used for what
    for section, id in panes.items():
        contextoutput(section, panes_paths[section], clear_context, 'top', None)

    # Add remaining sections to already existing panes
    contextoutput("legend", panes_paths['stack'], clear_context, 'top', None)
    contextoutput("args", panes_paths["regs"], clear_context, 'top', None)
    contextoutput("code", panes_paths["disasm"], clear_context, 'top', None)
    contextoutput("ghidra", panes_paths["disasm"], clear_context, 'top', None)
    contextoutput("expressions", panes_paths['backtrace'], clear_context, 'top', None)
    contextoutput("last_signal", panes_paths["backtrace"], clear_context, 'top', None)
    contextoutput("heap_tracker", panes_paths["backtrace"], clear_context, 'top', None)

def cleanup_config():
    pwndbg.config.context_disasm_lines.value = 21
    pwndbg.config.context_stack_lines.value = 18
    pwndbg.config.context_code_lines.value = 15
    # Give backtrace a little more color
    pwndbg.config.backtrace_prefix_color.value = "red,bold"
    pwndbg.config.backtrace_address_color.value = "gray"
    pwndbg.config.backtrace_symbol_color.value = "red"
    pwndbg.config.backtrace_frame_label_color.value = "green"   

def register_exit():
    # atexit.register(lambda: [os.popen(F"kitten @ close-window --match id:{id}").read() for id in panes.values()])
    # Sending SIGTERM instead of "kitten @ close-window" is faster,
    # allowing gdb to finish sooner, and preventing pwntools
    # from interrupting us with SIGTERM while we are already closing.
    # It should also allow for a more graceful exit for the panes.
    def kill_panes():
        for id, pid in panes_pid.items():
            if id != main_section:
                os.kill(pid, signal.SIGTERM)
    atexit.register(kill_panes)

panes = {}
panes_pid = {}
main_section = get_focused_id()
num_of_win = number_of_windows()
if num_of_win > 2:
    panic(1, f"Too many windows open! ({num_of_win} > 2)")
elif num_of_win <= 0:
    panic(2, f"No tab is focused? ({num_of_win} <= 0)")

open_layout(num_of_win == 2)
register_exit() # register early in case we error out
attach_to_pwndbg()
cleanup_config()

