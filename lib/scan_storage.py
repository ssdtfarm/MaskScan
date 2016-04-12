#!coding=utf-8

#用作数据的存储
# import xlwt
# import time

class storage():
	def __init__(self,dicts):
		self.dict=dicts
		self.content=""
		self.run()

	def run(self):

		#主运行程序，用来筛选数据

		if self.dict is not None:

			loudong=self.dict.keys()[0]
			name=self.dict[loudong][0]
			url=self.dict[loudong][1]
			code=self.dict[loudong][2]
			try:
				self.content=loudong+' '+name.decode('utf-8')+' '+url+' '+code+'\n'
				self.s_txt()
			except Exception,e:
				print e

	def s_txt(self):
		#存储到txt文本中
		f=open('./result/result.txt','a')
		f.write(self.content.encode('gbk'))
		f.close()

	def excel(self):
		#存储到excel
		pass

	def db(self):
		#存储到数据库
		pass
