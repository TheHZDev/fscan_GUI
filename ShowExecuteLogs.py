import wx


class ShowExecuteLog(wx.Frame):

    def __init__(self, parent, LogStr: str, Command: str):
        wx.Frame.__init__(self, parent, id=wx.ID_ANY, title=u"执行日志回显", pos=wx.DefaultPosition, size=wx.Size(640, 480),
                          style=wx.CAPTION | wx.CLOSE_BOX | wx.MINIMIZE | wx.MINIMIZE_BOX | wx.TAB_TRAVERSAL)

        self.SetSizeHints(wx.DefaultSize, wx.DefaultSize)

        bSizer4 = wx.BoxSizer(wx.VERTICAL)

        self.ShowLogs = wx.TextCtrl(self, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.Size(630, 400),
                                    wx.TE_AUTO_URL | wx.TE_CHARWRAP | wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2)
        bSizer4.Add(self.ShowLogs, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 5)

        gSizer9 = wx.GridSizer(0, 2, 0, 0)

        self.SaveLogsButton = wx.Button(self, wx.ID_ANY, u"另存为", wx.DefaultPosition, wx.DefaultSize, 0)
        gSizer9.Add(self.SaveLogsButton, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL | wx.ALIGN_BOTTOM, 5)

        self.ExitButton = wx.Button(self, wx.ID_ANY, u"关闭", wx.DefaultPosition, wx.DefaultSize, 0)
        gSizer9.Add(self.ExitButton, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL | wx.ALIGN_BOTTOM, 5)

        bSizer4.Add(gSizer9, 1, wx.EXPAND, 5)

        self.SetSizer(bSizer4)
        self.Layout()

        self.Centre(wx.BOTH)

        # Connect Events
        self.SaveLogsButton.Bind(wx.EVT_BUTTON, self.SaveLogsButtonOnButtonClick)
        self.ExitButton.Bind(wx.EVT_BUTTON, self.ExitButtonOnButtonClick)

        # Init
        self.ShowLogs.SetValue('命令执行：\n%s\n' % Command + '-' * 10 + '\n' + LogStr)

    def __del__(self):
        pass

    # Virtual event handlers, override them in your derived class
    def SaveLogsButtonOnButtonClick(self, event):
        fileDialog = wx.FileDialog(self, '另存为', wildcard='文本文件|*.log|所有文件|*.*',
                                   style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT)
        fileDialog.ShowModal()
        if len(fileDialog.GetPath()) > 0:
            try:
                tF = open(fileDialog.GetPath(), 'w', encoding='UTF-8')
                tF.write(self.ShowLogs.GetValue())
                tF.close()
                wx.MessageDialog(self, '保存成功！', '完成', wx.ICON_INFORMATION).ShowModal()
            except:
                wx.MessageDialog(self, '保存失败！', '错误', wx.ICON_ERROR).ShowModal()
        event.Skip()

    def ExitButtonOnButtonClick(self, event):
        self.Close()
        event.Skip()
