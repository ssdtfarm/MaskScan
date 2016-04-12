#!coding=utf-8

#slowhttp漏洞检测

import urllib2
import re

class slowhttp():
	def __init__(self,domain,port,name):
		self.domain=domain
		self.port=port
		self.name=name
		self.urls="http://"+self.domain+":"+str(port)
		self.server=r"Apache[^//]*/[1,2][^()]*"
		self.list=[]
		self.dict={}
		pass

	def run(self):
		try:
			#print u'进行slowhttp漏洞检测......'
			#print self.urls
			sock = urllib2.urlopen(self.urls,timeout=5) 
			result=sock.headers.values()       #获取服务器信息

			for i in result:
				p=re.compile(self.server)
				list_s=p.findall(i)
				if len(list_s)>0:              #apache为1.x或者2.x的输出
					self.list.append(self.name)   #网站名称
					self.list.append(self.urls) #网站url
					self.list.append('null')   #漏洞具体连接
					self.dict['slowhttp']=self.list #漏洞字典

					print u'[INFO]: %s 网站存在slowhttp漏洞'  % self.urls

					return self.dict
					
		except:
			#print e
			pass




