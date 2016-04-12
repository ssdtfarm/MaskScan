#!coding=utf-8

# 负责数据操作，域名获取，域名解析等
import codecs
import urlparse
import xlrd
import types

class scan_data:
	def __init__(self,options):
		self.list_domain=[]
		self.list_url=[]
		self.options=options

	def txt(self):  #从文本中获取url

		#获取完整url数据，用于漏洞检测
		try:
			self.list_url=codecs.open(self.options.txt,encoding='gbk').readlines()
			self.list_url=[i.replace('\n','') for i in self.list_url]
			
			return self.list_url    #返回一个url列表[url1,url2,url3......]
		except:
			print u"filepath error：not found %s" % self.options.txt


	def url(self):    #直接获取url
		self.list_url.append(self.options.url)
		return self.list_url        #返回一个列表[url]

	def excel(self):  #从excel中获取url
		try:
			workbook=xlrd.open_workbook(self.options.excel)
			worksheet=workbook.sheets()[0]
			num_rows=worksheet.nrows
			for row in range(num_rows):
				cell1=worksheet.cell_value(row,0)
				cell2=worksheet.cell_value(row,1)
				self.list_name=[]
				self.list_name.append(cell1)   #name 网站名称
				self.list_name.append(cell2)   #url  网站url
				self.list_url.append(self.list_name)
			return self.list_url     #返回一个列表[[name1,url1],[name2,url2]......]
		except:
			print u"filepath error：not found %s" % self.options.excel

	def domain(self):
		#获取domain数据，用于漏洞检测
		try:
			for i in self.list_url:  #url列表
				leixing=type(i)
				if leixing is types.ListType:
					name=i[0]
					url=i[1]
					m=urlparse.urlparse(url)
					j=m.netloc
					s=m.scheme
					n=j.split(':')
					if len(n)<2:
						n.append(80)
					n.append(name)
					if s=="https":
						n.append(443)
						n.append(name)
					self.list_domain.append(n)      #返回的是[[domain,port,name],[domain,port,name]]  or [[domain,name],]
				else:
					m=urlparse.urlparse(i)
					j=m.netloc
					s=m.scheme
					n=j.split(':')
					if len(n)<2:
						n.append(80)
					if s=="https":
						n.append(443)
					self.list_domain.append(n)      #返回的是[[domain,port],[domain,port]]  or [[domain],[domain]]

			return self.list_domain
		except Exception,e:
			print e
			print u'url填写有误！'

	def run(self):
		if self.options.url:
			self.url()
		elif self.options.txt:
			self.txt()
		else:
			self.excel()

		self.domain()

		return self.list_domain
		#print self.list_domain

