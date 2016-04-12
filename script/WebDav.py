#!coding=utf-8

# webdav漏洞检测脚本

import httplib
import re


class webDav:
	def __init__(self,domain,port,name):
		self.domain=domain
		self.port=port
		self.name=name
		self.urls="http://"+self.domain+':'+str(self.port)
		self.list_all=['PUT','COPY']
		self.content=""
		self.status=0
		self.list=[]
		self.dict={}

	def webDav(self,options):
		try:
			conn=httplib.HTTPConnection(self.domain,self.port,True,5)
			conn.request(options,'/','',{'user-agent':'test'})
			res=conn.getresponse()
			self.content=str(res.msg)
			self.status=res.status
			return self.content
			return self.status
		except:
			#print e
			pass

	def run(self):
		#print u'进行webdav漏洞检测......'
		self.webDav('OPTIONS')

		if self.status==200:
			re_t=r'Allow:(.*)'
			p_tel=re.compile(re_t)
			list_option=p_tel.findall(self.content)
			if len(list_option)>0:
				self.list.append(self.name)   #网站名称
				self.list.append(self.urls) #网站url
				self.list.append('null')   #漏洞具体连接
				self.dict['webDav']=self.list #漏洞字典

				print u'[INFO]: %s 网站存在WebDav漏洞'  % self.urls

				return self.dict          #最终结果是需要返回一个字典，包含了测试的结果信息
		else:
			for i in self.list_all:
				self.webDav(i)
				if self.status=='200':
					self.list.append('null')
					self.list.append(self.urls)
					self.list.append('null')
					self.dict['webDav']=self.list

					print u'[INFO]: %s 网站存在WebDav漏洞'  % self.urls

					return self.dict

					break
				else:
					pass