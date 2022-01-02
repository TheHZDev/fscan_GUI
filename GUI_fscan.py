from os.path import isfile
from threading import Thread

import subprocess
import wx

"""
fscan项目Github地址：https://github.com/shadow1ng/fscan
--------------
扫描（端口）模式：
-m all = 启用全部扫描模式
（事实上有mgo、icmp、ftp、smb、rdp、redis、ms17010、cve20200796、portscan、mssql、mysql、psql、fcgi、mem、main、ssh、
findnet、netbios、web）
-p {single_port}|{port1-port2}|{port1,port2,port3,...} = 指定端口进行扫描
-pa {single_port}|{port1-port2}|{port1, port2, port3, ...} = 在-p指定的端口中加上一个或多个端口进行扫描
-pn {single_port}|{port1-port2}|{port1, port2, port3, ...} = 在-p和-pa的端口组合中，跳过一个或多个端口
-pocname {webpocname} = 指定Poc的模糊名字（实际上有这么多）
（都是从源码下的POC目录下yml截取过来的）
-proxy {ip:port} = 指定代理
-t {int} = 指定扫描线程数量（默认600）
-time {int} = 端口扫描超时时间（默认3000ms）

日志保存：
-no = 不保存扫描日志（和-o参数冲突）
-o "{log_save_path}" = 指定日志保存地址（和-no参数冲突）

存活检测：
-ping = 使用Ping而不是ICMP探测存货（和-np参数冲突）
-np = 禁用存活扫描（与-ping参数冲突）

爆破相关：
-domain = SMB爆破设置域名（What？）
-user {single_username} = 指定爆破时的用户名
-userf {FilePath} = 指定爆破时的用户名文件
-pwd {single_Passwd} = 指定爆破时的密码
-pwdf {FilePath} = 指定爆破时的密码文件
-c {command}|{command1;command2} = SSH爆破成功后执行的远程命令
-rf {PubKey_Path} = Redis未授权写入的SSH公钥（文件导入）
-sshkey {SSH_Key} = SSH访问时配合的私钥（应该是配合-rf来使用）（文件导入）
-rs {IP:Port} = Redis未授权写入计划任务反弹Shell的NC监听端口

Web扫描：
-u url = 指定单个URL
-uf url.file = 从指定文件导入URL列表（一行一个）
-wt {int} = Web扫描超时时间
-cookie “{Cookie_str}” = 带上指定Cookie去访问网站
-nopoc = 禁止Web相关的POC扫描
-num {int} = Web POC扫描速率（和-nopoc冲突）

杂项：
完成后是否回显日志
超时强制终止
"""


class GUI_fscan(wx.Frame):

    def __init__(self):
        wx.Frame.__init__(self, None, id=wx.ID_ANY, title=u"fscan外壳工具（by TheHZDev）", pos=wx.DefaultPosition,
                          size=wx.Size(753, 709), style=wx.DEFAULT_FRAME_STYLE | wx.TAB_TRAVERSAL)

        self.SetSizeHints(wx.DefaultSize, wx.DefaultSize)
        self.SetFont(
            wx.Font(wx.NORMAL_FONT.GetPointSize(), wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL,
                    False, wx.EmptyString))

        bSizer1 = wx.BoxSizer(wx.VERTICAL)

        self.SelectFSCANEXEPathButton = wx.Button(self, wx.ID_ANY, u"选择fscan.exe路径", wx.DefaultPosition, wx.DefaultSize,
                                                  0)
        self.SelectFSCANEXEPathButton.SetFont(
            wx.Font(15, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        bSizer1.Add(self.SelectFSCANEXEPathButton, 0, wx.ALL | wx.EXPAND, 5)

        self.ShowFSCANParaText = wx.TextCtrl(self, wx.ID_ANY, u"未指定fscan可执行文件路径！", wx.DefaultPosition, wx.Size(-1, 60),
                                             wx.TE_CHARWRAP | wx.TE_MULTILINE | wx.TE_READONLY)
        bSizer1.Add(self.ShowFSCANParaText, 0, wx.ALL | wx.EXPAND, 5)

        self.ExecuteCheckTaskButton = wx.Button(self, wx.ID_ANY, u"开始执行", wx.DefaultPosition, wx.DefaultSize, 0)
        self.ExecuteCheckTaskButton.SetFont(
            wx.Font(15, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.ExecuteCheckTaskButton.Enable(False)

        bSizer1.Add(self.ExecuteCheckTaskButton, 0, wx.ALL | wx.EXPAND, 5)

        gSizer1 = wx.GridSizer(1, 3, 0, 0)

        sbSizer1 = wx.StaticBoxSizer(wx.StaticBox(self, wx.ID_ANY, u"端口扫描模式"), wx.VERTICAL)

        gSizer2 = wx.GridSizer(0, 2, 0, 0)

        self.IsSpecialPortScanMode = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"扫描模式", wx.DefaultPosition,
                                                 wx.DefaultSize, 0)
        self.IsSpecialPortScanMode.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsSpecialPortScanMode.SetToolTip(u"-m string\n设置扫描模式: -m ssh (default \"all\")")

        gSizer2.Add(self.IsSpecialPortScanMode, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        SpecialPortScanChoiceChoices = [u"all", u"mgo", u"icmp", u"ftp", u"smb", u"rdp", u"redis", u"ms17010",
                                        u"cve20200796", u"portscan", u"mssql", u"mysql", u"psql", u"fcgi", u"mem",
                                        u"main", u"ssh", u"findnet", u"netbios", u"web"]
        self.SpecialPortScanChoice = wx.Choice(sbSizer1.GetStaticBox(), wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize,
                                               SpecialPortScanChoiceChoices, 0)
        self.SpecialPortScanChoice.SetSelection(0)
        self.SpecialPortScanChoice.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.SpecialPortScanChoice.Enable(False)

        gSizer2.Add(self.SpecialPortScanChoice, 0, wx.ALIGN_RIGHT | wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        self.IsUseSpecialScanPortMode = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"扫描特定端口", wx.DefaultPosition,
                                                    wx.DefaultSize, 0)
        self.IsUseSpecialScanPortMode.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsUseSpecialScanPortMode.SetToolTip(
            u"-p string\n设置扫描的端口: 22 | 1-65535 | 22,80,3306 (default \"21,22,80,81,135,139,443,445,1433,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017\")")

        gSizer2.Add(self.IsUseSpecialScanPortMode, 0, wx.ALL | wx.EXPAND, 5)

        self.InputMainPortButton = wx.Button(sbSizer1.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                             wx.DefaultSize, 0)
        self.InputMainPortButton.Enable(False)

        gSizer2.Add(self.InputMainPortButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsAddExtraPortScan = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"增加扫描端口", wx.DefaultPosition,
                                              wx.DefaultSize, 0)
        self.IsAddExtraPortScan.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsAddExtraPortScan.SetToolTip(u"-pa string\n新增需要扫描的端口,-pa 3389 (会在原有端口列表基础上,新增该端口)")

        gSizer2.Add(self.IsAddExtraPortScan, 0, wx.ALL | wx.EXPAND, 5)

        self.InputExtraPortButton = wx.Button(sbSizer1.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                              wx.DefaultSize, 0)
        self.InputExtraPortButton.Enable(False)

        gSizer2.Add(self.InputExtraPortButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsExcludePort = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"排除端口", wx.DefaultPosition,
                                         wx.DefaultSize, 0)
        self.IsExcludePort.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsExcludePort.SetToolTip(u"-pn string\n扫描时要跳过的端口,as: -pn 445")

        gSizer2.Add(self.IsExcludePort, 0, wx.ALL | wx.EXPAND, 5)

        self.InputExcludePortButton = wx.Button(sbSizer1.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                                wx.DefaultSize, 0)
        self.InputExcludePortButton.Enable(False)

        gSizer2.Add(self.InputExcludePortButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsSpecialPOCName = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"指定POC名称", wx.DefaultPosition,
                                            wx.DefaultSize, 0)
        self.IsSpecialPOCName.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsSpecialPOCName.SetToolTip(u"-pocname string\n指定web poc的模糊名字, -pocname weblogic")

        gSizer2.Add(self.IsSpecialPOCName, 0, wx.ALIGN_CENTER_VERTICAL | wx.ALL, 5)

        SpecialPOCNameChoiceChoices = [u"74cms", u"active", u"activemq", u"airflow", u"alibaba", u"amtt", u"apache",
                                       u"aspcms", u"bash", u"bt742", u"cacti", u"chinaunicom", u"cisco", u"citrix",
                                       u"coldfusion", u"confluence", u"consul", u"coremail", u"couchcms", u"couchdb",
                                       u"craftcms", u"datang", u"dedecms", u"discuz", u"dlink", u"docker", u"dotnetcms",
                                       u"draytek", u"druid", u"drupal", u"dubbo", u"duomicms", u"dvr", u"e-zkeco",
                                       u"ecology", u"ecshop", u"eea", u"elasticsearch", u"etcd", u"etouch", u"exchange",
                                       u"eyou", u"f5", u"fangweicms", u"feifeicms", u"finecms", u"finereport",
                                       u"flexpaper", u"flink", u"fortigate", u"frp", u"gateone", u"gilacms", u"gitlab",
                                       u"gitlist", u"glassfish", u"go", u"gocd", u"h2", u"h3c", u"h5s", u"hadoop",
                                       u"hanming", u"harbor", u"hikvision", u"hjtcloud", u"huawei", u"ifw8", u"iis",
                                       u"influxdb", u"inspur", u"jboss", u"jeewms", u"jellyfin", u"jenkins", u"jetty",
                                       u"jira", u"joomla", u"jumpserver", u"jupyter", u"kafka", u"kibana", u"kingdee",
                                       u"kingsoft", u"kong", u"kubernetes", u"kyan", u"landray", u"lanproxy",
                                       u"laravel", u"maccms", u"maccmsv10", u"metinfo", u"minio", u"mongo", u"mpsec",
                                       u"msvod", u"myucms", u"nagio", u"natshell", u"netentsec", u"netgear", u"nextjs",
                                       u"nexus", u"nexusdb", u"nhttpd", u"node", u"novnc", u"nps", u"ns", u"nsfocus",
                                       u"nuuo", u"odoo", u"openfire", u"opentsdb", u"panabit", u"pandorafms",
                                       u"pbootcms", u"php", u"phpcms", u"phpmyadmin", u"phpok", u"phpshe", u"phpstudy",
                                       u"phpunit", u"powercreator", u"prometheus", u"pulse", u"pyspider", u"qibocms",
                                       u"qilin", u"qizhi", u"qnap", u"rabbitmq", u"rails", u"razor", u"rconfig",
                                       u"resin", u"rockmongo", u"ruijie", u"ruoyi", u"saltstack", u"samsung",
                                       u"sangfor", u"satellian", u"seacms", u"seacmsv645", u"secnet", u"seeyon",
                                       u"shiziyu", u"shopxo", u"showdoc", u"skywalking", u"solarwinds", u"solr",
                                       u"sonarqube", u"sonicwall", u"spark", u"spon", u"spring", u"springboot",
                                       u"springcloud", u"struts2", u"supervisord", u"swagger", u"tamronos", u"telecom",
                                       u"tensorboard", u"terramaster", u"thinkadmin", u"thinkcmf", u"thinkphp",
                                       u"thinkphp5", u"thinkphp5023", u"tianqing", u"tomcat", u"tongda", u"tpshop",
                                       u"tvt", u"typecho", u"ueditor", u"uwsgi", u"vbulletin", u"vmware", u"weaver",
                                       u"weblogic", u"webmin", u"weiphp", u"wifisky", u"wordpress", u"wuzhicms",
                                       u"xdcms", u"xiuno", u"xunchi", u"yapi", u"yccms", u"yonyou", u"youphptube",
                                       u"yungoucms", u"zabbix", u"zcms", u"zeit", u"zeroshell", u"zimbra", u"zzcms"]
        self.SpecialPOCNameChoice = wx.Choice(sbSizer1.GetStaticBox(), wx.ID_ANY, wx.DefaultPosition, wx.DefaultSize,
                                              SpecialPOCNameChoiceChoices, wx.CB_SORT)
        self.SpecialPOCNameChoice.SetSelection(0)
        self.SpecialPOCNameChoice.Enable(False)

        gSizer2.Add(self.SpecialPOCNameChoice, 0, wx.ALIGN_CENTER_VERTICAL | wx.ALIGN_RIGHT | wx.ALL, 5)

        self.IsMultiThreads = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"多线程数", wx.DefaultPosition,
                                          wx.DefaultSize, 0)
        self.IsMultiThreads.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsMultiThreads.SetToolTip(u"-t int\n扫描线程 (default 600)")

        gSizer2.Add(self.IsMultiThreads, 0, wx.ALL | wx.EXPAND, 5)

        self.InputThreadsIntTextEntry = wx.TextCtrl(sbSizer1.GetStaticBox(), wx.ID_ANY, u"600", wx.DefaultPosition,
                                                    wx.DefaultSize, wx.TE_CENTER)
        self.InputThreadsIntTextEntry.Enable(False)

        gSizer2.Add(self.InputThreadsIntTextEntry, 0, wx.ALL | wx.EXPAND, 5)

        self.IsPortScanTimeout = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"端口扫描超时", wx.DefaultPosition,
                                             wx.DefaultSize, 0)
        self.IsPortScanTimeout.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsPortScanTimeout.SetToolTip(u"-time int\n端口扫描超时时间 (default 3)")

        gSizer2.Add(self.IsPortScanTimeout, 0, wx.ALL | wx.EXPAND, 5)

        self.InputPortScanTimeoutTextEntry = wx.TextCtrl(sbSizer1.GetStaticBox(), wx.ID_ANY, u"3", wx.DefaultPosition,
                                                         wx.DefaultSize, wx.TE_CENTER)
        self.InputPortScanTimeoutTextEntry.Enable(False)

        gSizer2.Add(self.InputPortScanTimeoutTextEntry, 0, wx.ALL | wx.EXPAND, 5)

        self.IsWebScanTimeout = wx.CheckBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"Web扫描超时", wx.DefaultPosition,
                                            wx.DefaultSize, 0)
        self.IsWebScanTimeout.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsWebScanTimeout.SetToolTip(u"-wt int\nweb访问超时时间 (default 5)")

        gSizer2.Add(self.IsWebScanTimeout, 0, wx.ALL | wx.EXPAND, 5)

        self.InputWebScanTimeoutTextEntry = wx.TextCtrl(sbSizer1.GetStaticBox(), wx.ID_ANY, u"5", wx.DefaultPosition,
                                                        wx.DefaultSize, wx.TE_CENTER)
        self.InputWebScanTimeoutTextEntry.Enable(False)
        self.InputWebScanTimeoutTextEntry.SetToolTip(u"Web扫描超时时间，单位是秒/s。")

        gSizer2.Add(self.InputWebScanTimeoutTextEntry, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer1.Add(gSizer2, 1, wx.EXPAND, 5)

        sbSizer7 = wx.StaticBoxSizer(wx.StaticBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"Web扫描"), wx.VERTICAL)

        gSizer7 = wx.GridSizer(0, 2, 0, 0)

        self.SingleURLRadio = wx.RadioButton(sbSizer7.GetStaticBox(), wx.ID_ANY, u"单个URL", wx.DefaultPosition,
                                             wx.DefaultSize, 0)
        self.SingleURLRadio.SetValue(True)
        self.SingleURLRadio.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        gSizer7.Add(self.SingleURLRadio, 0, wx.ALL | wx.EXPAND, 5)

        self.InputSingleScanURLButton = wx.Button(sbSizer7.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                                  wx.DefaultSize, 0)
        self.InputSingleScanURLButton.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        gSizer7.Add(self.InputSingleScanURLButton, 0, wx.ALL | wx.EXPAND, 5)

        self.MultiURLRadio = wx.RadioButton(sbSizer7.GetStaticBox(), wx.ID_ANY, u"从文件导入URL", wx.DefaultPosition,
                                            wx.DefaultSize, 0)
        self.MultiURLRadio.SetFont(
            wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        gSizer7.Add(self.MultiURLRadio, 0, wx.ALL | wx.EXPAND, 5)

        self.InputURLFromFileButton = wx.Button(sbSizer7.GetStaticBox(), wx.ID_ANY, u"导入...", wx.DefaultPosition,
                                                wx.DefaultSize, 0)
        self.InputURLFromFileButton.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputURLFromFileButton.Enable(False)

        gSizer7.Add(self.InputURLFromFileButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsUserCookies = wx.CheckBox(sbSizer7.GetStaticBox(), wx.ID_ANY, u"自定义Cookies", wx.DefaultPosition,
                                         wx.DefaultSize, 0)
        gSizer7.Add(self.IsUserCookies, 0, wx.ALL | wx.EXPAND, 5)

        self.InputUserCookiesButton = wx.Button(sbSizer7.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                                wx.DefaultSize,
                                                0)
        self.InputUserCookiesButton.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputUserCookiesButton.Enable(False)

        gSizer7.Add(self.InputUserCookiesButton, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer7.Add(gSizer7, 1, wx.EXPAND, 5)

        sbSizer1.Add(sbSizer7, 1, wx.EXPAND, 5)

        sbSizer8 = wx.StaticBoxSizer(wx.StaticBox(sbSizer1.GetStaticBox(), wx.ID_ANY, u"IP扫描"), wx.VERTICAL)

        gSizer5 = wx.GridSizer(0, 2, 0, 0)

        self.SingleIPRadio = wx.RadioButton(sbSizer8.GetStaticBox(), wx.ID_ANY, u"单个目标IP", wx.DefaultPosition,
                                            wx.DefaultSize, 0)
        self.SingleIPRadio.SetValue(True)
        self.SingleIPRadio.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        gSizer5.Add(self.SingleIPRadio, 0, wx.ALL | wx.EXPAND, 5)

        self.InputSingleScanIPButton = wx.Button(sbSizer8.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                                 wx.DefaultSize, 0)
        self.InputSingleScanIPButton.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        gSizer5.Add(self.InputSingleScanIPButton, 0, wx.ALL | wx.EXPAND, 5)

        self.MultiIPRadio = wx.RadioButton(sbSizer8.GetStaticBox(), wx.ID_ANY, u"从文件导入IP", wx.DefaultPosition,
                                           wx.DefaultSize, 0)
        self.MultiIPRadio.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        gSizer5.Add(self.MultiIPRadio, 0, wx.ALL | wx.EXPAND, 5)

        self.InputIPAddressFromFilePathButton = wx.Button(sbSizer8.GetStaticBox(), wx.ID_ANY, u"导入...",
                                                          wx.DefaultPosition, wx.DefaultSize, 0)
        self.InputIPAddressFromFilePathButton.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputIPAddressFromFilePathButton.Enable(False)

        gSizer5.Add(self.InputIPAddressFromFilePathButton, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer8.Add(gSizer5, 1, wx.EXPAND, 5)

        sbSizer1.Add(sbSizer8, 1, wx.EXPAND, 5)

        gSizer1.Add(sbSizer1, 1, wx.EXPAND, 5)

        bSizer3 = wx.BoxSizer(wx.VERTICAL)

        sbSizer3 = wx.StaticBoxSizer(wx.StaticBox(self, wx.ID_ANY, u"日志存放"), wx.VERTICAL)

        self.DontSaveLogRadio = wx.RadioButton(sbSizer3.GetStaticBox(), wx.ID_ANY, u"不保存日志", wx.DefaultPosition,
                                               wx.DefaultSize, 0)
        self.DontSaveLogRadio.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.DontSaveLogRadio.SetToolTip(u"-no\n扫描结果不保存到文件中")

        sbSizer3.Add(self.DontSaveLogRadio, 0, wx.ALL, 5)

        self.DefaultSaveLogRadio = wx.RadioButton(sbSizer3.GetStaticBox(), wx.ID_ANY, u"默认（保存为result.txt）",
                                                  wx.DefaultPosition, wx.DefaultSize, 0)
        self.DefaultSaveLogRadio.SetValue(True)
        self.DefaultSaveLogRadio.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        sbSizer3.Add(self.DefaultSaveLogRadio, 0, wx.ALL, 5)

        gSizer4 = wx.GridSizer(0, 2, 0, 0)

        self.UseUserLogPathRadio = wx.RadioButton(sbSizer3.GetStaticBox(), wx.ID_ANY, u"自定义", wx.DefaultPosition,
                                                  wx.DefaultSize, 0)
        self.UseUserLogPathRadio.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.UseUserLogPathRadio.SetToolTip(u"-o string\n扫描结果保存到哪 (default \"result.txt\")")

        gSizer4.Add(self.UseUserLogPathRadio, 0, wx.ALL | wx.EXPAND, 5)

        self.InputUserLogPathButton = wx.Button(sbSizer3.GetStaticBox(), wx.ID_ANY, u"无路径", wx.DefaultPosition,
                                                wx.DefaultSize, 0)
        self.InputUserLogPathButton.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputUserLogPathButton.Enable(False)

        gSizer4.Add(self.InputUserLogPathButton, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer3.Add(gSizer4, 1, wx.EXPAND, 5)

        bSizer3.Add(sbSizer3, 1, 0, 5)

        LiveDetectOptionsChoices = [u"ICMP存活检测（默认）", u"Ping存活检测", u"跳过存活检测"]
        self.LiveDetectOptions = wx.RadioBox(self, wx.ID_ANY, u"存活检测设置", wx.DefaultPosition, wx.DefaultSize,
                                             LiveDetectOptionsChoices, 1, wx.RA_SPECIFY_COLS)
        self.LiveDetectOptions.SetSelection(0)
        self.LiveDetectOptions.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.LiveDetectOptions.SetToolTip(u"-np\n跳过存活探测\n\n-ping\n使用ping代替icmp进行存活探测")

        bSizer3.Add(self.LiveDetectOptions, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer4 = wx.StaticBoxSizer(wx.StaticBox(self, wx.ID_ANY, u"杂项设置"), wx.VERTICAL)

        self.IsShowLogAfterExecute = wx.CheckBox(sbSizer4.GetStaticBox(), wx.ID_ANY, u"执行完毕后回显日志", wx.DefaultPosition,
                                                 wx.DefaultSize, 0)
        self.IsShowLogAfterExecute.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsShowLogAfterExecute.SetToolTip(u"选中后，执行完毕后弹出新窗口回显日志。")

        sbSizer4.Add(self.IsShowLogAfterExecute, 0, wx.ALL | wx.EXPAND, 5)

        gSizer8 = wx.GridSizer(0, 2, 0, 0)

        self.IsForceTimeout = wx.CheckBox(sbSizer4.GetStaticBox(), wx.ID_ANY, u"强制程序超时", wx.DefaultPosition,
                                          wx.DefaultSize, 0)
        self.IsForceTimeout.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsForceTimeout.SetToolTip(u"选中后，超时一定秒数后fscan将被强制终止运行。")

        gSizer8.Add(self.IsForceTimeout, 0, wx.ALL | wx.EXPAND, 5)

        self.InputForceTimeoutSecondsTextEntry = wx.TextCtrl(sbSizer4.GetStaticBox(), wx.ID_ANY, u"0",
                                                             wx.DefaultPosition, wx.DefaultSize, wx.TE_CENTER)
        self.InputForceTimeoutSecondsTextEntry.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputForceTimeoutSecondsTextEntry.Enable(False)
        self.InputForceTimeoutSecondsTextEntry.SetToolTip(u"超时时间，单位是秒/s。")

        gSizer8.Add(self.InputForceTimeoutSecondsTextEntry, 0, wx.ALL | wx.ALIGN_CENTER_VERTICAL, 5)

        sbSizer4.Add(gSizer8, 1, wx.EXPAND, 5)

        bSizer3.Add(sbSizer4, 1, wx.EXPAND, 5)

        sbSizer2 = wx.StaticBoxSizer(wx.StaticBox(self, wx.ID_ANY, u"代理设置"), wx.VERTICAL)

        self.NoProxyRadio = wx.RadioButton(sbSizer2.GetStaticBox(), wx.ID_ANY, u"无代理", wx.DefaultPosition,
                                           wx.DefaultSize, 0)
        self.NoProxyRadio.SetValue(True)
        self.NoProxyRadio.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        sbSizer2.Add(self.NoProxyRadio, 0, wx.ALL | wx.EXPAND, 5)

        self.UseSystemProxyRadio = wx.RadioButton(sbSizer2.GetStaticBox(), wx.ID_ANY, u"使用系统代理", wx.DefaultPosition,
                                                  wx.DefaultSize, 0)
        self.UseSystemProxyRadio.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        sbSizer2.Add(self.UseSystemProxyRadio, 0, wx.ALL, 5)

        gSizer3 = wx.GridSizer(0, 2, 0, 0)

        self.UseUserProxyRadio = wx.RadioButton(sbSizer2.GetStaticBox(), wx.ID_ANY, u"自定义代理", wx.DefaultPosition,
                                                wx.DefaultSize, 0)
        self.UseUserProxyRadio.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.UseUserProxyRadio.SetToolTip(u"-proxy string\n设置代理, -proxy http://127.0.0.1:8080")

        gSizer3.Add(self.UseUserProxyRadio, 0, wx.ALL | wx.EXPAND, 5)

        self.InputUserProxyButton = wx.Button(sbSizer2.GetStaticBox(), wx.ID_ANY, u"未设置", wx.DefaultPosition,
                                              wx.DefaultSize, 0)
        self.InputUserProxyButton.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputUserProxyButton.Enable(False)

        gSizer3.Add(self.InputUserProxyButton, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer2.Add(gSizer3, 1, wx.EXPAND, 5)

        bSizer3.Add(sbSizer2, 1, wx.EXPAND, 5)

        gSizer1.Add(bSizer3, 1, wx.EXPAND, 5)

        bSizer2 = wx.BoxSizer(wx.VERTICAL)

        sbSizer5 = wx.StaticBoxSizer(wx.StaticBox(self, wx.ID_ANY, u"暴破相关"), wx.VERTICAL)

        gSizer6 = wx.GridSizer(0, 2, 0, 0)

        self.IsSpecialSMBDomain = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"SMB暴破域名", wx.DefaultPosition,
                                              wx.DefaultSize, 0)
        self.IsSpecialSMBDomain.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsSpecialSMBDomain.SetToolTip(u"-domain string\nsmb爆破模块时,设置域名")

        gSizer6.Add(self.IsSpecialSMBDomain, 0, wx.ALL | wx.EXPAND, 5)

        self.InputSpecialDomainSMBButton = wx.Button(sbSizer5.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                                     wx.DefaultSize, 0)
        self.InputSpecialDomainSMBButton.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputSpecialDomainSMBButton.Enable(False)

        gSizer6.Add(self.InputSpecialDomainSMBButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsInputUserNameFromFile = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"导入用户名", wx.DefaultPosition,
                                                   wx.DefaultSize, 0)
        self.IsInputUserNameFromFile.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsInputUserNameFromFile.SetToolTip(u"-userf string\n指定爆破时的用户名文件")

        gSizer6.Add(self.IsInputUserNameFromFile, 0, wx.ALL | wx.EXPAND, 5)

        self.InputUserFromFileButton = wx.Button(sbSizer5.GetStaticBox(), wx.ID_ANY, u"导入...", wx.DefaultPosition,
                                                 wx.DefaultSize, 0)
        self.InputUserFromFileButton.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputUserFromFileButton.Enable(False)

        gSizer6.Add(self.InputUserFromFileButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsInputPasswdFromFile = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"导入密码本", wx.DefaultPosition,
                                                 wx.DefaultSize, 0)
        self.IsInputPasswdFromFile.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsInputPasswdFromFile.SetToolTip(u"-pwdf string\n指定爆破时的密码文件")

        gSizer6.Add(self.IsInputPasswdFromFile, 0, wx.ALL | wx.EXPAND, 5)

        self.InputPasswdFromFileButton = wx.Button(sbSizer5.GetStaticBox(), wx.ID_ANY, u"导入...", wx.DefaultPosition,
                                                   wx.DefaultSize, 0)
        self.InputPasswdFromFileButton.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputPasswdFromFileButton.Enable(False)

        gSizer6.Add(self.InputPasswdFromFileButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsSSHCommandAfterSuccess = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"SSH执行命令", wx.DefaultPosition,
                                                    wx.DefaultSize, 0)
        self.IsSSHCommandAfterSuccess.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsSSHCommandAfterSuccess.SetToolTip(u"-c string\nssh命令执行")

        gSizer6.Add(self.IsSSHCommandAfterSuccess, 0, wx.ALL | wx.EXPAND, 5)

        self.InputSSHCommand = wx.Button(sbSizer5.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition, wx.DefaultSize,
                                         0)
        self.InputSSHCommand.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputSSHCommand.Enable(False)

        gSizer6.Add(self.InputSSHCommand, 0, wx.ALL | wx.EXPAND, 5)

        self.IsPathAfterSuccess = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"FCGI/SMB路径", wx.DefaultPosition,
                                              wx.DefaultSize, 0)
        self.IsPathAfterSuccess.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsPathAfterSuccess.SetToolTip(u"-path string\nFCGI、SMB remote file path")

        gSizer6.Add(self.IsPathAfterSuccess, 0, wx.ALL | wx.EXPAND, 5)

        self.InputSMBOrFCGIPathButton = wx.Button(sbSizer5.GetStaticBox(), wx.ID_ANY, u"无", wx.DefaultPosition,
                                                  wx.DefaultSize, 0)
        self.InputSMBOrFCGIPathButton.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputSMBOrFCGIPathButton.Enable(False)

        gSizer6.Add(self.InputSMBOrFCGIPathButton, 0, wx.ALL | wx.EXPAND, 5)

        self.IsSpecialPOCScanSpeed = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"POC扫描速率", wx.DefaultPosition,
                                                 wx.DefaultSize, 0)
        self.IsSpecialPOCScanSpeed.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsSpecialPOCScanSpeed.SetToolTip(u"-num int\nweb poc 发包速率  (default 20)")

        gSizer6.Add(self.IsSpecialPOCScanSpeed, 0, wx.ALL | wx.EXPAND, 5)

        self.InputPOCScanSpeedTextEntry = wx.TextCtrl(sbSizer5.GetStaticBox(), wx.ID_ANY, u"20", wx.DefaultPosition,
                                                      wx.DefaultSize, wx.TE_CENTER)
        self.InputPOCScanSpeedTextEntry.Enable(False)

        gSizer6.Add(self.InputPOCScanSpeedTextEntry, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer5.Add(gSizer6, 1, wx.EXPAND, 5)

        self.IsNoPOCMode = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"禁用POC探测", wx.DefaultPosition,
                                       wx.DefaultSize, 0)
        self.IsNoPOCMode.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsNoPOCMode.SetToolTip(u"-nopoc\n跳过web poc扫描")

        sbSizer5.Add(self.IsNoPOCMode, 0, wx.ALL | wx.EXPAND, 5)

        self.IsNoBruteExploit = wx.CheckBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"禁用密码暴破", wx.DefaultPosition,
                                            wx.DefaultSize, 0)
        self.IsNoBruteExploit.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.IsNoBruteExploit.SetToolTip(u"-nobr\n跳过sql、ftp、ssh等的密码爆破")

        sbSizer5.Add(self.IsNoBruteExploit, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer6 = wx.StaticBoxSizer(wx.StaticBox(sbSizer5.GetStaticBox(), wx.ID_ANY, u"Redis未授权利用"), wx.VERTICAL)

        self.IsEnableRedisHack = wx.CheckBox(sbSizer6.GetStaticBox(), wx.ID_ANY, u"启用Redis未授权利用工具", wx.DefaultPosition,
                                             wx.DefaultSize, 0)
        self.IsEnableRedisHack.SetFont(
            wx.Font(13, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))

        sbSizer6.Add(self.IsEnableRedisHack, 0, wx.ALL, 5)

        self.InputSSHPublicKeyButton = wx.Button(sbSizer6.GetStaticBox(), wx.ID_ANY, u"SSH公钥", wx.DefaultPosition,
                                                 wx.DefaultSize, 0)
        self.InputSSHPublicKeyButton.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputSSHPublicKeyButton.Enable(False)
        self.InputSSHPublicKeyButton.SetToolTip(u"-rf string\n指定redis写公钥用模块的文件 (as: -rf id_rsa.pub)")

        sbSizer6.Add(self.InputSSHPublicKeyButton, 0, wx.ALL | wx.EXPAND, 5)

        self.InputSSHPrivateKeyButton = wx.Button(sbSizer6.GetStaticBox(), wx.ID_ANY, u"SSH私钥", wx.DefaultPosition,
                                                  wx.DefaultSize, 0)
        self.InputSSHPrivateKeyButton.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputSSHPrivateKeyButton.Enable(False)
        self.InputSSHPrivateKeyButton.SetToolTip(u"-sshkey string\nssh连接时,指定ssh私钥")

        sbSizer6.Add(self.InputSSHPrivateKeyButton, 0, wx.ALL | wx.EXPAND, 5)

        self.InputShellIPAndPortButton = wx.Button(sbSizer6.GetStaticBox(), wx.ID_ANY, u"输入NC反弹IP和端口",
                                                   wx.DefaultPosition, wx.DefaultSize, 0)
        self.InputShellIPAndPortButton.SetFont(
            wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, False, wx.EmptyString))
        self.InputShellIPAndPortButton.Enable(False)
        self.InputShellIPAndPortButton.SetToolTip(u"-rs string\nredis计划任务反弹shell的ip端口 (as: -rs 192.168.1.1:6666)")

        sbSizer6.Add(self.InputShellIPAndPortButton, 0, wx.ALL | wx.EXPAND, 5)

        sbSizer5.Add(sbSizer6, 1, wx.EXPAND, 5)

        bSizer2.Add(sbSizer5, 1, wx.EXPAND, 5)

        gSizer1.Add(bSizer2, 1, wx.EXPAND, 5)

        bSizer1.Add(gSizer1, 1, wx.EXPAND, 5)

        self.SetSizer(bSizer1)
        self.Layout()

        self.Centre(wx.BOTH)

        # Connect Events
        self.SelectFSCANEXEPathButton.Bind(wx.EVT_BUTTON, self.SelectFSCANEXEPathButtonOnButtonClick)
        self.SelectFSCANEXEPathButton.Bind(wx.EVT_ENTER_WINDOW, self.SelectFSCANEXEPathButtonOnEnterWindow)
        self.SelectFSCANEXEPathButton.Bind(wx.EVT_LEAVE_WINDOW, self.SelectFSCANEXEPathButtonOnLeaveWindow)
        self.ExecuteCheckTaskButton.Bind(wx.EVT_BUTTON, self.ExecuteCheckTaskButtonOnButtonClick)
        self.IsSpecialPortScanMode.Bind(wx.EVT_CHECKBOX, self.IsSpecialPortScanModeOnCheckBox)
        self.SpecialPortScanChoice.Bind(wx.EVT_CHOICE, self.SpecialPortScanChoiceOnChoice)
        self.IsUseSpecialScanPortMode.Bind(wx.EVT_CHECKBOX, self.IsUseSpecialScanPortModeOnCheckBox)
        self.InputMainPortButton.Bind(wx.EVT_BUTTON, self.InputMainPortButtonOnButtonClick)
        self.InputMainPortButton.Bind(wx.EVT_ENTER_WINDOW, self.InputMainPortButtonOnEnterWindow)
        self.InputMainPortButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputMainPortButtonOnLeaveWindow)
        self.IsAddExtraPortScan.Bind(wx.EVT_CHECKBOX, self.IsAddExtraPortScanOnCheckBox)
        self.InputExtraPortButton.Bind(wx.EVT_BUTTON, self.InputExtraPortButtonOnButtonClick)
        self.InputExtraPortButton.Bind(wx.EVT_ENTER_WINDOW, self.InputExtraPortButtonOnEnterWindow)
        self.InputExtraPortButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputExtraPortButtonOnLeaveWindow)
        self.IsExcludePort.Bind(wx.EVT_CHECKBOX, self.IsExcludePortOnCheckBox)
        self.InputExcludePortButton.Bind(wx.EVT_BUTTON, self.InputExcludePortButtonOnButtonClick)
        self.InputExcludePortButton.Bind(wx.EVT_ENTER_WINDOW, self.InputExcludePortButtonOnEnterWindow)
        self.InputExcludePortButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputExcludePortButtonOnLeaveWindow)
        self.IsSpecialPOCName.Bind(wx.EVT_CHECKBOX, self.IsSpecialPOCNameOnCheckBox)
        self.SpecialPOCNameChoice.Bind(wx.EVT_CHOICE, self.SpecialPOCNameChoiceOnChoice)
        self.IsMultiThreads.Bind(wx.EVT_CHECKBOX, self.IsMultiThreadsOnCheckBox)
        self.InputThreadsIntTextEntry.Bind(wx.EVT_KILL_FOCUS, self.InputThreadsIntTextEntryOnKillFocus)
        self.IsPortScanTimeout.Bind(wx.EVT_CHECKBOX, self.IsPortScanTimeoutOnCheckBox)
        self.InputPortScanTimeoutTextEntry.Bind(wx.EVT_KILL_FOCUS, self.InputPortScanTimeoutTextEntryOnKillFocus)
        self.IsWebScanTimeout.Bind(wx.EVT_CHECKBOX, self.IsWebScanTimeoutOnCheckBox)
        self.InputWebScanTimeoutTextEntry.Bind(wx.EVT_KILL_FOCUS, self.InputWebScanTimeoutTextEntryOnKillFocus)
        self.SingleURLRadio.Bind(wx.EVT_RADIOBUTTON, self.SingleURLRadioOnRadioButton)
        self.InputSingleScanURLButton.Bind(wx.EVT_BUTTON, self.InputSingleScanURLButtonOnButtonClick)
        self.InputSingleScanURLButton.Bind(wx.EVT_ENTER_WINDOW, self.InputSingleScanURLButtonOnEnterWindow)
        self.InputSingleScanURLButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputSingleScanURLButtonOnLeaveWindow)
        self.MultiURLRadio.Bind(wx.EVT_RADIOBUTTON, self.MultiURLRadioOnRadioButton)
        self.InputURLFromFileButton.Bind(wx.EVT_BUTTON, self.InputURLFromFileButtonOnButtonClick)
        self.InputURLFromFileButton.Bind(wx.EVT_ENTER_WINDOW, self.InputURLFromFileButtonOnEnterWindow)
        self.InputURLFromFileButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputURLFromFileButtonOnLeaveWindow)
        self.IsUserCookies.Bind(wx.EVT_CHECKBOX, self.IsUserCookiesOnCheckBox)
        self.InputUserCookiesButton.Bind(wx.EVT_BUTTON, self.InputUserCookiesOnButtonClick)
        self.InputUserCookiesButton.Bind(wx.EVT_ENTER_WINDOW, self.InputUserCookiesOnEnterWindow)
        self.InputUserCookiesButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputUserCookiesOnLeaveWindow)
        self.SingleIPRadio.Bind(wx.EVT_RADIOBUTTON, self.SingleIPRadioOnRadioButton)
        self.InputSingleScanIPButton.Bind(wx.EVT_BUTTON, self.InputSingleScanIPButtonOnButtonClick)
        self.InputSingleScanIPButton.Bind(wx.EVT_ENTER_WINDOW, self.InputSingleScanIPButtonOnEnterWindow)
        self.InputSingleScanIPButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputSingleScanIPButtonOnLeaveWindow)
        self.MultiIPRadio.Bind(wx.EVT_RADIOBUTTON, self.MultiIPRadioOnRadioButton)
        self.InputIPAddressFromFilePathButton.Bind(wx.EVT_BUTTON, self.InputIPAddressFromFilePathButtonOnButtonClick)
        self.InputIPAddressFromFilePathButton.Bind(wx.EVT_ENTER_WINDOW,
                                                   self.InputIPAddressFromFilePathButtonOnEnterWindow)
        self.InputIPAddressFromFilePathButton.Bind(wx.EVT_LEAVE_WINDOW,
                                                   self.InputIPAddressFromFilePathButtonOnLeaveWindow)
        self.DontSaveLogRadio.Bind(wx.EVT_RADIOBUTTON, self.DontSaveLogRadioOnRadioButton)
        self.DefaultSaveLogRadio.Bind(wx.EVT_RADIOBUTTON, self.DefaultSaveLogRadioOnRadioButton)
        self.UseUserLogPathRadio.Bind(wx.EVT_RADIOBUTTON, self.UseUserLogPathRadioOnRadioButton)
        self.InputUserLogPathButton.Bind(wx.EVT_BUTTON, self.InputUserLogPathButtonOnButtonClick)
        self.InputUserLogPathButton.Bind(wx.EVT_ENTER_WINDOW, self.InputUserLogPathButtonOnEnterWindow)
        self.InputUserLogPathButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputUserLogPathButtonOnLeaveWindow)
        self.LiveDetectOptions.Bind(wx.EVT_RADIOBOX, self.LiveDetectOptionsOnRadioBox)
        self.IsShowLogAfterExecute.Bind(wx.EVT_CHECKBOX, self.IsShowLogAfterExecuteOnCheckBox)
        self.IsForceTimeout.Bind(wx.EVT_CHECKBOX, self.IsForceTimeoutOnCheckBox)
        self.InputForceTimeoutSecondsTextEntry.Bind(wx.EVT_KILL_FOCUS,
                                                    self.InputForceTimeoutSecondsTextEntryOnKillFocus)
        self.NoProxyRadio.Bind(wx.EVT_RADIOBUTTON, self.NoProxyRadioOnRadioButton)
        self.UseSystemProxyRadio.Bind(wx.EVT_RADIOBUTTON, self.UseSystemProxyRadioOnRadioButton)
        self.UseUserProxyRadio.Bind(wx.EVT_RADIOBUTTON, self.UseUserProxyRadioOnRadioButton)
        self.InputUserProxyButton.Bind(wx.EVT_BUTTON, self.InputUserProxyButtonOnButtonClick)
        self.InputUserProxyButton.Bind(wx.EVT_ENTER_WINDOW, self.InputUserProxyButtonOnEnterWindow)
        self.InputUserProxyButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputUserProxyButtonOnLeaveWindow)
        self.IsSpecialSMBDomain.Bind(wx.EVT_CHECKBOX, self.IsSpecialSMBDomainOnCheckBox)
        self.InputSpecialDomainSMBButton.Bind(wx.EVT_BUTTON, self.InputSpecialDomainSMBButtonOnButtonClick)
        self.InputSpecialDomainSMBButton.Bind(wx.EVT_ENTER_WINDOW, self.InputSpecialDomainSMBButtonOnEnterWindow)
        self.InputSpecialDomainSMBButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputSpecialDomainSMBButtonOnLeaveWindow)
        self.IsInputUserNameFromFile.Bind(wx.EVT_CHECKBOX, self.IsInputUserNameFromFileOnCheckBox)
        self.InputUserFromFileButton.Bind(wx.EVT_BUTTON, self.InputUserFromFileButtonOnButtonClick)
        self.InputUserFromFileButton.Bind(wx.EVT_ENTER_WINDOW, self.InputUserFromFileButtonOnEnterWindow)
        self.InputUserFromFileButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputUserFromFileButtonOnLeaveWindow)
        self.IsInputPasswdFromFile.Bind(wx.EVT_CHECKBOX, self.IsInputPasswdFromFileOnCheckBox)
        self.InputPasswdFromFileButton.Bind(wx.EVT_BUTTON, self.InputPasswdFromFileButtonOnButtonClick)
        self.InputPasswdFromFileButton.Bind(wx.EVT_ENTER_WINDOW, self.InputPasswdFromFileButtonOnEnterWindow)
        self.InputPasswdFromFileButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputPasswdFromFileButtonOnLeaveWindow)
        self.IsSSHCommandAfterSuccess.Bind(wx.EVT_CHECKBOX, self.IsSSHCommandAfterSuccessOnCheckBox)
        self.InputSSHCommand.Bind(wx.EVT_BUTTON, self.InputSSHCommandOnButtonClick)
        self.InputSSHCommand.Bind(wx.EVT_ENTER_WINDOW, self.InputSSHCommandOnEnterWindow)
        self.InputSSHCommand.Bind(wx.EVT_LEAVE_WINDOW, self.InputSSHCommandOnLeaveWindow)
        self.IsPathAfterSuccess.Bind(wx.EVT_CHECKBOX, self.IsPathAfterSuccessOnCheckBox)
        self.InputSMBOrFCGIPathButton.Bind(wx.EVT_BUTTON, self.InputSMBOrFCGIPathButtonOnButtonClick)
        self.InputSMBOrFCGIPathButton.Bind(wx.EVT_ENTER_WINDOW, self.InputSMBOrFCGIPathButtonOnEnterWindow)
        self.InputSMBOrFCGIPathButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputSMBOrFCGIPathButtonOnLeaveWindow)
        self.IsSpecialPOCScanSpeed.Bind(wx.EVT_CHECKBOX, self.IsSpecialPOCScanSpeedOnCheckBox)
        self.InputPOCScanSpeedTextEntry.Bind(wx.EVT_KILL_FOCUS, self.InputPOCScanSpeedTextEntryOnKillFocus)
        self.IsNoPOCMode.Bind(wx.EVT_CHECKBOX, self.IsNoPOCModeOnCheckBox)
        self.IsNoBruteExploit.Bind(wx.EVT_CHECKBOX, self.IsNoBruteExploitOnCheckBox)
        self.IsEnableRedisHack.Bind(wx.EVT_CHECKBOX, self.IsEnableRedisHackOnCheckBox)
        self.InputSSHPublicKeyButton.Bind(wx.EVT_BUTTON, self.InputSSHPublicKeyButtonOnButtonClick)
        self.InputSSHPublicKeyButton.Bind(wx.EVT_ENTER_WINDOW, self.InputSSHPublicKeyButtonOnEnterWindow)
        self.InputSSHPublicKeyButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputSSHPublicKeyButtonOnLeaveWindow)
        self.InputSSHPrivateKeyButton.Bind(wx.EVT_BUTTON, self.InputSSHPrivateKeyButtonOnButtonClick)
        self.InputSSHPrivateKeyButton.Bind(wx.EVT_ENTER_WINDOW, self.InputSSHPrivateKeyButtonOnEnterWindow)
        self.InputSSHPrivateKeyButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputSSHPrivateKeyButtonOnLeaveWindow)
        self.InputShellIPAndPortButton.Bind(wx.EVT_BUTTON, self.InputShellIPAndPortButtonOnButtonClick)
        self.InputShellIPAndPortButton.Bind(wx.EVT_ENTER_WINDOW, self.InputShellIPAndPortButtonOnEnterWindow)
        self.InputShellIPAndPortButton.Bind(wx.EVT_LEAVE_WINDOW, self.InputShellIPAndPortButtonOnLeaveWindow)

        # 预定义Radio组内联调
        self.radioGroup_url = [{'radio': self.SingleURLRadio, 'obj': [self.InputSingleScanURLButton]},
                               {'radio': self.MultiURLRadio, 'obj': [self.InputURLFromFileButton]}]
        self.radioGroup_ip = [{'radio': self.SingleIPRadio, 'obj': [self.InputSingleScanIPButton]},
                              {'radio': self.MultiIPRadio, 'obj': [self.InputIPAddressFromFilePathButton]}]
        self.radioGroup_log = [{'radio': self.DontSaveLogRadio, 'key': 'dontSaveLog'},
                               {'radio': self.DefaultSaveLogRadio},
                               {'radio': self.UseUserLogPathRadio, 'obj': [self.InputUserLogPathButton],
                                'key': 'useLogPath'}]
        self.radioGroup_proxy = [{'radio': self.NoProxyRadio},
                                 {'radio': self.UseSystemProxyRadio, 'key': 'useSystemProxy'},
                                 {'radio': self.UseUserProxyRadio, 'key': 'useUserProxy',
                                  'obj': [self.InputUserProxyButton]}]

    def __del__(self):
        pass

    # 公共缓存设置
    fscan_execute_path = ''
    fscan_version = ''
    global_run_config = {
        'mainPort': '', 'extraPort': '', 'excludePort': '',
        'threads': 600, 'portScanTimeout': 3, 'webScanTimeout': 5, 'useCookies': '',
        'useLogPath': '', 'forceExecuteTimeout': -1,
        'useUserProxy': '', 'smbDomain': '', 'useUserBook': '',
        'usePasswdBook': '', 'remoteSSHCommand': '', 'remotePath': '', 'pocScanSpeed': 20,
        'redisPubKeyPath': '', 'redisPriKeyPath': '', 'redisShellIPAddress': ''
    }
    global_enable_config = {
        'module': False, 'mainPort': False, 'extraPort': False, 'excludePort': False, 'specialPOC': False,
        'threads': False, 'portScanTimeout': False, 'webScanTimeout': False, 'useCookies': False,
        'dontSaveLog': False, 'useLogPath': False, 'forceExecuteTimeout': False, 'showLogAfterFinish': False,
        'useSystemProxy': False, 'useUserProxy': False, 'smbDomain': False, 'useUserBook': False,
        'usePasswdBook': False, 'remoteSSHCommand': False, 'remotePath': False, 'pocScanSpeed': False,
        'noPOCScan': False, 'noPasswdBrute': False, 'useRedis': False
    }
    global_target_config = {
        'single_ip': '', 'ip_from_file': '',
        'single_url': '', 'url_from_file': ''
    }
    # 公共const变量
    const_wx_ask = wx.YES_NO | wx.ICON_QUESTION
    const_wx_openFile = wx.FD_OPEN | wx.FD_FILE_MUST_EXIST
    const_wx_saveFile = wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT
    const_label_not_null = '可用'
    const_label_null = '无'
    const_label_no_input = '导入...'
    const_label_no_config = '未设置'
    const_label_show_or_modify = '查看/更改'
    const_label_add = '增加'
    const_ask_yesORno = '\n单击“是”，继续修改。\n单击“否”，取消修改操作。'
    const_input_PortScan = "请输入端口：\n不同的端口可用英文逗号(,)分开，或者用连接符(-)连接。"
    const_msg_ShowPort = "当前的端口信息为\n%s" + const_ask_yesORno
    const_input_Url = "请输入URL地址："
    const_msg_ShowSingleUrl = "当前待扫描的URL是：\n%s" + const_ask_yesORno
    const_input_IP = "请输入IP地址及其子网（用/隔开IP地址和子网）："
    const_msg_ShowSingleIP = "当前待扫描的IP地址是：\n%s" + const_ask_yesORno
    const_msg_CommonInputFileShow = "%s的导入路径是：\n%s" + const_ask_yesORno
    const_msg_CommonOutputFileShow = "%s的保存路径是：\n%s" + const_ask_yesORno
    const_input_Proxy = "请输入要使用的自定义HTTP代理："
    const_msg_ShowProxy = "当前的HTTP代理为：\n%s" + const_ask_yesORno
    const_input_SSHCommand = "请输入SSH爆破成功后要执行的命令：\n（多个命令用英文分号区隔）"
    const_msg_ShowSSHCommand = "SSH爆破成功后执行以下命令：\n%s" + const_ask_yesORno
    const_input_SMBDomain = "请输入SMB爆破时使用的参考域名："
    const_msg_ShowSMBDomain = "当前使用的SMB爆破域名为：\n%s" + const_ask_yesORno
    const_input_RemotePath = "请输入爆破时使用的SMB/FCGI路径："
    const_msg_ShowRemotePath = "当前使用的SMB/FCGI路径为：\n%s" + const_ask_yesORno
    const_input_Cookies = "请输入Web扫描时使用的自定义Cookies字符串："
    const_msg_ShowCookies = "当前Web扫描所使用的自定义Cookie是：\n%s" + const_ask_yesORno
    const_input_nc_Shell = "请输入Redis未授权写入Crontab反弹Shell的目标IP和端口："
    const_msg_ShowNCShell = "当前NC反弹的目的地址是：\n%s"

    # 主要应用函数
    def buildExecutePath(self) -> str:
        if len(self.fscan_execute_path) < 1:
            return '未指定fscan可执行文件路径！'
        pass

    def updateUI(self):
        self.ShowFSCANParaText.SetValue(self.buildExecutePath())
        pass

    def thread_DetectFSCANVersion(self):
        if not (isfile(self.fscan_execute_path) and self.fscan_execute_path.endswith('.exe')):
            return
        self.fscan_version = ''
        runResult = subprocess.run('"%s" --version' % self.fscan_execute_path, capture_output=True,
                                   encoding='UTF-8')
        # 这应该很快就结束，--version实际上不能为fscan所识别
        # 由于非正常终止，程序返回了出错代码（测试时为2）
        for line in runResult.stderr.splitlines():
            if 'version' in line:
                self.fscan_version = line.replace(':', '').split()[-1]
                break
        if len(self.fscan_version) > 0:
            self.SelectFSCANEXEPathButton.SetLabel('已检测的fscan版本：%s' % self.fscan_version)

    def simpleEnableLink(self, obj1: wx.CheckBox, obj2: wx.Control, register: str = ''):
        """这是一个简单的链式反应，obj1为判断信号，obj2和register为后续动作（obj2启用/禁用）"""
        if obj1.GetValue():
            obj2.Enable()
            if register in self.global_enable_config.keys():
                self.global_enable_config[register] = True
        else:
            obj2.Disable()
            if register in self.global_enable_config.keys():
                self.global_enable_config[register] = False
        self.updateUI()

    def commonInputTextEntryDialog(self, toSetButton: wx.Button, toRWDictName: str, toRWKey: str, toShowMsg: str,
                                   toShowInputHint: str):
        """
        通用需要对话框的函数例程\n
        :param toSetButton: 待设置标题的按钮
        :param toRWDictName: 待读写的字典/列表
        :param toRWKey: 字典的键/列表索引
        :param toShowMsg: 显示在询问列表中的字段
        :param toShowInputHint: 显示在输入框的字段
        """
        if toRWDictName == 'run':
            toRWDict = self.global_run_config
        else:
            toRWDict = self.global_target_config
        if len(toRWDict[toRWKey]) > 0:
            askDialog = wx.MessageDialog(self, toShowMsg % toRWDict[toRWKey], '信息', self.const_wx_ask)
            if askDialog.ShowModal() == wx.ID_NO:
                return
        inputDialog = wx.TextEntryDialog(self, toShowInputHint, '输入', toRWDict[toRWKey])
        inputDialog.ShowModal()
        toRWDict[toRWKey] = inputDialog.GetValue().strip()
        self.commonButtonSetLabel(toRWDictName, toRWKey, toSetButton, self.const_label_show_or_modify,
                                  self.const_label_add)
        self.updateUI()

    def commonInputFileDialog(self, toSetButton: wx.Button, toRWDictName: str, toRWKey: str,
                              toShowMsgArgs: str, dialogMode: str = 'open'):
        """这个只考虑文件对话框"""
        if toRWDictName == 'run':
            toRWDict = self.global_run_config
        else:
            toRWDict = self.global_target_config
        if dialogMode == 'save':
            toShowMsg = self.const_msg_CommonOutputFileShow
            fileMode = self.const_wx_saveFile
            dialogMsg = '保存'
        else:
            toShowMsg = self.const_msg_CommonInputFileShow
            fileMode = self.const_wx_openFile
            dialogMsg = '打开'
        if len(toRWDict[toRWKey]) > 0:
            askDialog = wx.MessageDialog(self, toShowMsg % (toShowMsgArgs, toRWDict[toRWKey]), '信息', self.const_wx_ask)
            if askDialog.ShowModal() == wx.ID_NO:
                return
        fileDialog = wx.FileDialog(self, dialogMsg, wildcard='文本文件|*.txt|所有文件|*.*', style=fileMode)
        fileDialog.ShowModal()
        if len(fileDialog.GetPath().strip()) > 0:
            toRWDict[toRWKey] = fileDialog.GetPath().strip()
            self.commonButtonSetLabel(toRWDictName, toRWKey, toSetButton, self.const_label_show_or_modify,
                                      self.const_label_add)
            self.updateUI()

    def commonButtonSetLabel(self, toRWDictName: str, toReadKey: str, toSetButton: wx.Button, trueStr: str = '',
                             falseStr: str = ''):
        """根据字段读取运行配置（简单判断长度），然后为给定的按钮设置标牌"""
        if toRWDictName == 'run':
            toRWDict = self.global_run_config
        elif toRWDictName == 'enable':
            toRWDict = self.global_enable_config
        else:
            toRWDict = self.global_target_config
        if toReadKey not in toRWDict.keys() or not isinstance(toSetButton, wx.Button):
            return
        if len(toRWDict[toReadKey]) > 0:
            if len(trueStr) > 0:
                toSetButton.SetLabel(trueStr)
        elif len(falseStr) > 0:
            toSetButton.SetLabel(falseStr)

    def radioGroupUpdate(self, radioGroup: list, setValueIndex: int):
        """radio组内联调，负责处理事务组单元"""
        try:
            for radioID in range(len(radioGroup)):
                if radioID != setValueIndex:
                    radioGroup[radioID].get('radio').SetValue(False)
                if 'obj' in radioGroup[radioID].keys():
                    for objUnit in radioGroup[radioID].get('obj'):
                        if isinstance(objUnit, wx.Control):
                            if radioID == setValueIndex:
                                objUnit.Enable()
                            else:
                                objUnit.Disable()
                if 'key' in radioGroup[radioID].keys():
                    if radioGroup[radioID].get('key') in self.global_enable_config.keys():
                        if radioID != setValueIndex:
                            self.global_enable_config[radioGroup[radioID].get('key')] = False
                        else:
                            self.global_enable_config[radioGroup[radioID].get('key')] = True
        finally:
            pass

    def commonTextEntryOnKillFocus(self, toRWKey: str, toRWTextEntry: wx.TextEntry):
        """本次读写的输入框都只要求输入正整数，因此可以极大简化"""
        if not isinstance(toRWTextEntry, wx.TextEntry) or toRWKey not in self.global_run_config.keys():
            return
        tStr: str = toRWTextEntry.GetValue()
        if tStr.isdigit():
            self.global_run_config[toRWKey] = int(tStr)
            self.updateUI()
        else:
            toRWTextEntry.SetValue(str(self.global_run_config[toRWKey]))

    # Virtual event handlers, override them in your derived class
    def SelectFSCANEXEPathButtonOnButtonClick(self, event):
        fileOpenDialog = wx.FileDialog(self, '选择fscan.exe路径', defaultFile='fscan.exe',
                                       wildcard='fscan主程序|*.exe', style=self.const_wx_openFile)
        fileOpenDialog.ShowModal()
        executePath: str = fileOpenDialog.GetPath()
        if isfile(executePath) and executePath.endswith('.exe'):
            self.fscan_execute_path = executePath
            Thread(target=self.thread_DetectFSCANVersion).start()
            self.ExecuteCheckTaskButton.Enable()
        event.Skip()

    def SelectFSCANEXEPathButtonOnEnterWindow(self, event):
        if len(self.fscan_version) > 0:
            self.SelectFSCANEXEPathButton.SetLabel('重新选择fscan.exe路径')
        event.Skip()

    def SelectFSCANEXEPathButtonOnLeaveWindow(self, event):
        if len(self.fscan_version) > 0:
            self.SelectFSCANEXEPathButton.SetLabel('已检测的fscan版本：%s' % self.fscan_version)
        event.Skip()

    def ExecuteCheckTaskButtonOnButtonClick(self, event):
        event.Skip()

    def IsSpecialPortScanModeOnCheckBox(self, event):
        self.simpleEnableLink(self.IsSpecialPortScanMode, self.SpecialPortScanChoice, 'module')
        event.Skip()

    def SpecialPortScanChoiceOnChoice(self, event):
        self.updateUI()
        event.Skip()

    def IsUseSpecialScanPortModeOnCheckBox(self, event):
        self.simpleEnableLink(self.IsUseSpecialScanPortMode, self.InputMainPortButton, 'mainPort')
        event.Skip()

    def InputMainPortButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputMainPortButton, 'run', 'mainPort',
                                        self.const_msg_ShowPort, self.const_input_PortScan)
        event.Skip()

    def InputMainPortButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'mainPort', self.InputMainPortButton, self.const_label_show_or_modify,
                                  self.const_label_add)
        event.Skip()

    def InputMainPortButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'mainPort', self.InputMainPortButton, self.const_label_not_null,
                                  self.const_label_null)
        event.Skip()

    def IsAddExtraPortScanOnCheckBox(self, event):
        self.simpleEnableLink(self.IsAddExtraPortScan, self.InputExtraPortButton, 'extraPort')
        event.Skip()

    def InputExtraPortButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputExtraPortButton, 'run', 'extraPort',
                                        self.const_msg_ShowPort, self.const_input_PortScan)
        event.Skip()

    def InputExtraPortButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'extraPort', self.InputExtraPortButton, self.const_label_show_or_modify,
                                  self.const_label_add)
        event.Skip()

    def InputExtraPortButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'extraPort', self.InputExtraPortButton, self.const_label_not_null,
                                  self.const_label_null)
        event.Skip()

    def IsExcludePortOnCheckBox(self, event):
        self.simpleEnableLink(self.IsExcludePort, self.InputExcludePortButton, 'excludePort')
        event.Skip()

    def InputExcludePortButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputExcludePortButton, 'run', 'excludePort',
                                        self.const_msg_ShowPort, self.const_input_PortScan)
        event.Skip()

    def InputExcludePortButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'excludePort', self.InputExtraPortButton, self.const_label_show_or_modify,
                                  self.const_label_add)
        event.Skip()

    def InputExcludePortButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'excludePort', self.InputExtraPortButton, self.const_label_not_null,
                                  self.const_label_null)
        event.Skip()

    def IsSpecialPOCNameOnCheckBox(self, event):
        self.simpleEnableLink(self.IsSpecialPOCName, self.SpecialPOCNameChoice, 'specialPOC')
        event.Skip()

    def SpecialPOCNameChoiceOnChoice(self, event):
        self.updateUI()
        event.Skip()

    def IsMultiThreadsOnCheckBox(self, event):
        self.simpleEnableLink(self.IsMultiThreads, self.InputThreadsIntTextEntry, 'threads')
        event.Skip()

    def InputThreadsIntTextEntryOnKillFocus(self, event):
        self.commonTextEntryOnKillFocus('threads', self.InputThreadsIntTextEntry)
        event.Skip()

    def IsPortScanTimeoutOnCheckBox(self, event):
        self.simpleEnableLink(self.IsPortScanTimeout, self.InputPortScanTimeoutTextEntry, 'portScanTimeout')
        event.Skip()

    def InputPortScanTimeoutTextEntryOnKillFocus(self, event):
        self.commonTextEntryOnKillFocus('portScanTimeout', self.InputPortScanTimeoutTextEntry)
        event.Skip()

    def IsWebScanTimeoutOnCheckBox(self, event):
        self.simpleEnableLink(self.IsWebScanTimeout, self.InputWebScanTimeoutTextEntry, 'webScanTimeout')
        event.Skip()

    def InputWebScanTimeoutTextEntryOnKillFocus(self, event):
        self.commonTextEntryOnKillFocus('webScanTimeout', self.InputWebScanTimeoutTextEntry)
        event.Skip()

    def SingleURLRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_url, 0)
        self.updateUI()
        event.Skip()

    def InputSingleScanURLButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputSingleScanURLButton, 'target', 'single_url',
                                        self.const_msg_ShowSingleUrl, self.const_input_Url)
        event.Skip()

    def InputSingleScanURLButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('target', 'single_url', self.InputSingleScanURLButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputSingleScanURLButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('target', 'single_url', self.InputSingleScanURLButton,
                                  self.const_label_not_null, self.const_label_null)
        event.Skip()

    def MultiURLRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_url, 1)
        self.updateUI()
        event.Skip()

    def InputURLFromFileButtonOnButtonClick(self, event):
        self.commonInputFileDialog(self.InputURLFromFileButton, 'target', 'url_from_file', '待扫描URL')
        event.Skip()

    def InputURLFromFileButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('target', 'url_from_file', self.InputSingleScanURLButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputURLFromFileButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('target', 'url_from_file', self.InputSingleScanURLButton, self.const_label_not_null,
                                  self.const_label_no_input)
        event.Skip()

    def IsUserCookiesOnCheckBox(self, event):
        self.simpleEnableLink(self.IsUserCookies, self.InputUserCookiesButton, 'useCookies')
        event.Skip()

    def InputUserCookiesOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputUserCookiesButton, 'run', 'useCookies',
                                        self.const_msg_ShowCookies, self.const_input_Cookies)
        event.Skip()

    def InputUserCookiesOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'useCookies', self.InputUserCookiesButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputUserCookiesOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'useCookies', self.InputUserCookiesButton,
                                  self.const_label_not_null, self.const_label_null)
        event.Skip()

    def SingleIPRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_ip, 0)
        self.updateUI()
        event.Skip()

    def InputSingleScanIPButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputSingleScanIPButton, 'target', 'single_ip',
                                        self.const_msg_ShowSingleIP, self.const_input_IP)
        event.Skip()

    def InputSingleScanIPButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('target', 'single_ip', self.InputSingleScanIPButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputSingleScanIPButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('target', 'single_ip', self.InputSingleScanIPButton,
                                  self.const_label_not_null, self.const_label_null)
        event.Skip()

    def MultiIPRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_ip, 1)
        self.updateUI()
        event.Skip()

    def InputIPAddressFromFilePathButtonOnButtonClick(self, event):
        self.commonInputFileDialog(self.InputIPAddressFromFilePathButton, 'target', 'ip_from_file', '待扫描IP')
        event.Skip()

    def InputIPAddressFromFilePathButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('target', 'ip_from_file', self.InputIPAddressFromFilePathButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputIPAddressFromFilePathButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('target', 'ip_from_file', self.InputIPAddressFromFilePathButton,
                                  self.const_label_not_null, self.const_label_no_input)
        event.Skip()

    def DontSaveLogRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_log, 0)
        self.updateUI()
        event.Skip()

    def DefaultSaveLogRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_log, 1)
        self.updateUI()
        event.Skip()

    def UseUserLogPathRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_log, 2)
        self.updateUI()
        event.Skip()

    def InputUserLogPathButtonOnButtonClick(self, event):
        self.commonInputFileDialog(self.InputUserLogPathButton, 'run', 'useLogPath', '扫描日志', 'save')
        event.Skip()

    def InputUserLogPathButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'useLogPath', self.InputUserLogPathButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputUserLogPathButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'useLogPath', self.InputUserLogPathButton,
                                  self.const_label_not_null, self.const_label_no_config)
        event.Skip()

    def LiveDetectOptionsOnRadioBox(self, event):
        self.updateUI()
        event.Skip()

    def IsShowLogAfterExecuteOnCheckBox(self, event):
        self.global_enable_config['showLogAfterFinish'] = self.IsShowLogAfterExecute.GetValue()
        event.Skip()

    def IsForceTimeoutOnCheckBox(self, event):
        self.simpleEnableLink(self.IsForceTimeout, self.InputForceTimeoutSecondsTextEntry, 'forceExecuteTimeout')
        event.Skip()

    def InputForceTimeoutSecondsTextEntryOnKillFocus(self, event):
        self.commonTextEntryOnKillFocus('forceExecuteTimeout', self.InputForceTimeoutSecondsTextEntry)
        event.Skip()

    def NoProxyRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_proxy, 0)
        self.updateUI()
        event.Skip()

    def UseSystemProxyRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_proxy, 1)
        self.updateUI()
        event.Skip()

    def UseUserProxyRadioOnRadioButton(self, event):
        self.radioGroupUpdate(self.radioGroup_proxy, 2)
        self.updateUI()
        event.Skip()

    def InputUserProxyButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputUserProxyButton, 'run', 'useUserProxy',
                                        self.const_msg_ShowProxy, self.const_input_Proxy)
        event.Skip()

    def InputUserProxyButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'useUserProxy', self.InputUserProxyButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputUserProxyButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'useUserProxy', self.InputUserProxyButton,
                                  self.const_label_not_null, self.const_label_no_config)
        event.Skip()

    def IsSpecialSMBDomainOnCheckBox(self, event):
        self.simpleEnableLink(self.IsSpecialSMBDomain, self.InputSpecialDomainSMBButton, 'smbDomain')
        event.Skip()

    def InputSpecialDomainSMBButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputSpecialDomainSMBButton, 'run', 'smbDomain',
                                        self.const_msg_ShowSMBDomain, self.const_input_SMBDomain)
        event.Skip()

    def InputSpecialDomainSMBButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'smbDomain', self.InputSpecialDomainSMBButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputSpecialDomainSMBButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'smbDomain', self.InputSpecialDomainSMBButton,
                                  self.const_label_not_null, self.const_label_null)
        event.Skip()

    def IsInputUserNameFromFileOnCheckBox(self, event):
        self.simpleEnableLink(self.IsInputUserNameFromFile, self.InputUserFromFileButton, 'useUserBook')
        event.Skip()

    def InputUserFromFileButtonOnButtonClick(self, event):
        self.commonInputFileDialog(self.InputUserFromFileButton, 'run', 'useUserBook', '用户字典')
        event.Skip()

    def InputUserFromFileButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'smbDomain', self.InputUserFromFileButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputUserFromFileButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'smbDomain', self.InputUserFromFileButton,
                                  self.const_label_not_null, self.const_label_no_input)
        event.Skip()

    def IsInputPasswdFromFileOnCheckBox(self, event):
        self.simpleEnableLink(self.IsInputPasswdFromFile, self.InputPasswdFromFileButton, 'usePasswdBook')
        event.Skip()

    def InputPasswdFromFileButtonOnButtonClick(self, event):
        self.commonInputFileDialog(self.InputPasswdFromFileButton, 'run', 'usePasswdBook', '密码字典')
        event.Skip()

    def InputPasswdFromFileButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'usePasswdBook', self.InputPasswdFromFileButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputPasswdFromFileButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'usePasswdBook', self.InputPasswdFromFileButton,
                                  self.const_label_not_null, self.const_label_no_input)
        event.Skip()

    def IsSSHCommandAfterSuccessOnCheckBox(self, event):
        self.simpleEnableLink(self.IsSSHCommandAfterSuccess, self.InputSSHCommand, 'remoteSSHCommand')
        event.Skip()

    def InputSSHCommandOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputSSHCommand, 'run', 'remoteSSHCommand',
                                        self.const_msg_ShowSSHCommand, self.const_input_SSHCommand)
        event.Skip()

    def InputSSHCommandOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'remoteSSHCommand', self.InputSSHCommand,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputSSHCommandOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'remoteSSHCommand', self.InputSSHCommand,
                                  self.const_label_not_null, self.const_label_null)
        event.Skip()

    def IsPathAfterSuccessOnCheckBox(self, event):
        self.simpleEnableLink(self.IsPathAfterSuccess, self.InputSMBOrFCGIPathButton, 'remotePath')
        event.Skip()

    def InputSMBOrFCGIPathButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputSMBOrFCGIPathButton, 'run', 'remotePath',
                                        self.const_msg_ShowRemotePath, self.const_input_RemotePath)
        event.Skip()

    def InputSMBOrFCGIPathButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'remotePath', self.InputSMBOrFCGIPathButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputSMBOrFCGIPathButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'remotePath', self.InputSMBOrFCGIPathButton,
                                  self.const_label_show_or_modify, self.const_label_no_config)
        event.Skip()

    def IsSpecialPOCScanSpeedOnCheckBox(self, event):
        self.simpleEnableLink(self.IsSpecialPOCScanSpeed, self.InputPOCScanSpeedTextEntry, 'pocScanSpeed')
        event.Skip()

    def InputPOCScanSpeedTextEntryOnKillFocus(self, event):
        self.commonTextEntryOnKillFocus('pocScanSpeed', self.InputPOCScanSpeedTextEntry)
        event.Skip()

    def IsNoPOCModeOnCheckBox(self, event):
        self.global_run_config['noPOCScan'] = self.IsNoPOCMode.GetValue()
        self.updateUI()
        event.Skip()

    def IsNoBruteExploitOnCheckBox(self, event):
        self.global_run_config['noPasswdBrute'] = self.IsNoPOCMode.GetValue()
        self.updateUI()
        event.Skip()

    def IsEnableRedisHackOnCheckBox(self, event):
        if self.IsEnableRedisHack.GetValue():
            self.InputSSHPublicKeyButton.Enable()
            self.InputSSHPrivateKeyButton.Enable()
            self.InputShellIPAndPortButton.Enable()
        else:
            self.InputSSHPublicKeyButton.Disable()
            self.InputSSHPrivateKeyButton.Disable()
            self.InputShellIPAndPortButton.Disable()
        self.global_enable_config['useRedis'] = self.IsEnableRedisHack.GetValue()
        self.updateUI()
        event.Skip()

    def InputSSHPublicKeyButtonOnButtonClick(self, event):
        self.commonInputFileDialog(self.InputSSHPublicKeyButton, 'run', 'redisPubKeyPath', 'SSH公钥')
        event.Skip()

    def InputSSHPublicKeyButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'redisPubKeyPath', self.InputSSHPublicKeyButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputSSHPublicKeyButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'redisPubKeyPath', self.InputSSHPublicKeyButton,
                                  'SSH公钥（已导入）', 'SSH公钥')
        event.Skip()

    def InputSSHPrivateKeyButtonOnButtonClick(self, event):
        self.commonInputFileDialog(self.InputSSHPrivateKeyButton, 'run', 'redisPriKeyPath', 'SSH私钥')
        event.Skip()

    def InputSSHPrivateKeyButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'redisPriKeyPath', self.InputSSHPrivateKeyButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputSSHPrivateKeyButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'redisPriKeyPath', self.InputSSHPrivateKeyButton,
                                  'SSH私钥（已导入）', 'SSH私钥')
        event.Skip()

    def InputShellIPAndPortButtonOnButtonClick(self, event):
        self.commonInputTextEntryDialog(self.InputShellIPAndPortButton, 'run', 'redisShellIPAddress',
                                        self.const_msg_ShowNCShell, self.const_input_nc_Shell)
        event.Skip()

    def InputShellIPAndPortButtonOnEnterWindow(self, event):
        self.commonButtonSetLabel('run', 'redisShellIPAddress', self.InputShellIPAndPortButton,
                                  self.const_label_show_or_modify, self.const_label_add)
        event.Skip()

    def InputShellIPAndPortButtonOnLeaveWindow(self, event):
        self.commonButtonSetLabel('run', 'redisShellIPAddress', self.InputShellIPAndPortButton,
                                  'Shell->' + self.global_run_config['redisShellIPAddress'], '输入NC反弹IP和端口')
        event.Skip()
