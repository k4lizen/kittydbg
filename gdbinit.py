import os
import atexit

import pwndbg
from pwndbg.commands.context import contextoutput

# Would it be more sensical to use the kitten python API? Yes. Yes it would.

def path_from_id(id: int):
    return os.popen(f"kitten @ ls | jq -r '.[] | .tabs[].windows[] | select(.id == {id}) | .pid' | xargs -I{{}} ls -l /proc/{{}}/fd | grep pts | awk '{{print $NF}}' | uniq").read().strip()

def number_of_windows():
    return int(os.popen("kitten @ ls | jq '[.[].tabs[] | select(.is_focused)] | .[0].windows | length'").read().strip())

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
        # Disguisting but what can I do? No option to resize with bias and move_to_screen_edge is bugged
        os.popen("kitten @ resize-window --axis=vertical --increment=14").read()

    panes["stack"] = os.popen("kitten @ launch --location=hsplit --cwd=current --bias=40 cat").read().strip()
    panes["backtrace"] = os.popen("kitten @ launch --location=after --cwd=current --bias=30 cat").read().strip()
    os.popen(f"kitten @ focus-window --match id:{panes["disasm"]}").read()
    panes["regs"] = os.popen("kitten @ launch --location=after --cwd=current --bias=50 cat").read().strip()
    # os.popen(f"kitten @ focus-window --match id:{main_section}").read()
    # panes["python"] = os.popen("kitten @ launch --location=after --cwd=current --bias=30 python").read().strip()
    os.popen(f"kitten @ focus-window --match id:{main_section}").read()

def attach_to_pwndbg():
    panes_paths = {}
    for sec in panes:
        panes_paths[sec] = path_from_id(panes[sec]) 

    # Tell pwndbg which panes are to be used for what
    for section, id in panes.items():
        contextoutput(section, panes_paths[section], False, 'top', None)

    # Add remaining sections to already existing panes
    contextoutput("legend", panes_paths['stack'], None)
    contextoutput("args", panes_paths["regs"], False, 'top', None)
    contextoutput("code", panes_paths["disasm"], False, 'top', None)
    contextoutput("ghidra", panes_paths["disasm"], False, 'top', None)
    contextoutput("expressions", panes_paths['backtrace'], False, 'top', None)
    contextoutput("last_signal", panes_paths["backtrace"], False, 'top', None)
    contextoutput("heap_tracker", panes_paths["backtrace"], False, 'top', None)

def cleanup_config():
    # FIXME: if kitty fixes bias/move fix this to be the same number always
    pwndbg.config.context_disasm_lines.value = 18 if num_of_win == 1 else 21
    pwndbg.config.context_stack_lines.value = 18
    pwndbg.config.context_code_lines.value = 15
    # Give backtrace a little more color
    pwndbg.config.backtrace_prefix_color.value = "red,bold"
    pwndbg.config.backtrace_address_color.value = "gray"
    pwndbg.config.backtrace_symbol_color.value = "red"
    pwndbg.config.backtrace_frame_label_color.value = "green"   

def register_exit():
    atexit.register(lambda: [os.popen(F"kitten @ close-window --match id:{id}").read() for id in panes.values()])

panes = {}
main_section = os.popen("kitten @ ls | jq -r '.[].tabs[].windows[] | select(.is_self).id'").read().strip()

num_of_win = number_of_windows()
if num_of_win > 2:
    print("Too many windows open! (> 2)")
    exit(1)

open_layout(num_of_win == 2)
attach_to_pwndbg()
cleanup_config()
register_exit()

