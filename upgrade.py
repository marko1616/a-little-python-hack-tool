import requests, zipfile, os, shutil
print("请不要在下载过程中终止程序不然你就只能去github更新了")
input("按回车开始下载")
for i in os.listdir(os.getcwd()):
    print("删除文件:" + i)
    if i == 'upgrade.py':
        continue
    try:
        shutil.rmtree(os.getcwd() + "\\" + i)
    except NotADirectoryError:
        os.unlink(os.getcwd() + "\\" + i)
res = 0
def download():
    try:
        global res
        res = requests.get("https://github.com/marko1616/a-little-python-hack-tool/archive/master.zip")
        print("下载成功正在解压...")
    except:
        print("下载失败尝试重新下载")
        download()
print("开始下载")
download()
file = open('upgrade.zip','wb')
file.write(res.content)
file.close()
file = zipfile.ZipFile("upgrade.zip","r")
file.extractall(os.getcwd())
for i in os.listdir(os.getcwd() + "\\a-little-python-hack-tool-master"):
    print("更新文件:" + os.getcwd() + "\\a-little-python-hack-tool-master\\" + i)
    try:
        shutil.copytree(os.getcwd() + "\\a-little-python-hack-tool-master\\" + i,os.getcwd() + "\\" + i)
    except NotADirectoryError:
        shutil.copy(os.getcwd() + "\\a-little-python-hack-tool-master\\" + i,os.getcwd())
input("更新成功按回车退出") 
        
