#!coding=utf-8

# 多线程程序，负责以一个线程一个url的方式启动漏洞检测脚本

import threading
import sys
from scan_storage import storage
sys.path.append("..")
from script.WebDav import webDav  #导入父级同级目录下的模块
from script.SlowHttp import slowhttp
from script.Hb import Hb_run


maxs=20  #线程最大上限
threadLimiter=threading.BoundedSemaphore(maxs)

class scan_threading(threading.Thread):
	def  __init__(self,t_name,url):
		threading.Thread.__init__(self,name=t_name)
		self.domain=url[0].encode('utf-8').replace('\n','').replace('\r','')  #url:[domain,port,name]
		self.port=str(url[1])
		if len(url)>2:
			self.name=url[2].encode('utf-8')
		else:
			self.name=""
		
	def run(self):
		threadLimiter.acquire()
		try:
			if self.port==443:
				self.dict=Hb_run(self.domain,self.name)                       #执行心脏出血漏洞检测
				storage(self.dict)											  #将结果进行存储
			else:
				self.dict=webDav(self.domain,self.port,self.name).run()       #执行webdav漏洞检测
				storage(self.dict)                     		     			  #将结果进行储存

				self.dict=slowhttp(self.domain,self.port,self.name).run()     #执行slowhttp漏洞检测
				storage(self.dict)

			pass
			#
			#
			#
			#
		except:
			#print e
			pass

		finally:
			threadLimiter.release()

def thread_start(url):
	for i in url:
		try:
			a=scan_threading('mask',i)  #传递url
			a.start()
		except:
			pass
	for i in url:
		try:
			a.join()
		except:
			pass

	

