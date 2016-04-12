#!coding=utf-8

# 主程序，负责调用其他模块，进行扫描！

from optparse import OptionParser
from lib.scan_data import scan_data
from lib.scan_threading import thread_start

class maskscan:
	def __init__(self):
		self.url=[]
		pass

	def run(self):
		#运行函数
		self.prints()

		if self.options.url or self.options.txt or self.options.excel:

			self.urls()

			#多线程启动
			thread_start(self.url)


		elif self.options.vulnerability:

			self.vulnerability()

		else:
			self.option.print_help()

	def urls(self):
		#获取url数据函数,返回的是一个list
		self.url=scan_data(self.options).run()  #获取域名信息   格式[[domain,(port)],] or [[domain,(port),name]]
		#print len(self.url)
		pass

	def prints(self):
		self.option=OptionParser()
		self.option.add_option('-u', '--url', default=False,help='-u http(s)://www.maskghost.com(:8080)/')
		self.option.add_option('-t', '--txt', default=False,help='-t Filepath(.txt)')
		self.option.add_option('-e', '--excel',default=False,help='-e Filepath(.xls)')
		self.option.add_option('-v', '--vulnerability',default=False,help=u'-v all')			
		self.options,self.arg=self.option.parse_args()	
		return self.options

	def vulnerability(self):
		print u""
		print u"2016.3.17"
		print u"Vulnerability_List:"
		print ""
		print u"SlowHttp-----------slowhttp漏洞，存在于apache低版本"
		print u"WebDav-------------webdav漏洞，存在于IIS容器，配置不当"
		print u"HeartBleed---------heartbleed漏洞，存在于openssl"

mask=maskscan()
mask.run()

