
# Python 3
# Windows
# AVScan.py
# By: LawlietJH
#      v.1.1.2

# Para python 2 el módulo es '_winreg'.
# Para python 3 el módulo es 'winreg'.
import winreg
import os


avs = [
		'a2adguard.exe',	'a2adwizard.exe',		'a2antidialer.exe',		'a2cfg.exe',		'a2cmd.exe',
		'a2free.exe',		'a2guard.exe',			'a2hijackfree.exe',		'a2scan.exe',		'a2service.exe',
		'a2start.exe',		'a2sys.exe',			'a2upd.exe',			'aavgapi.exe',		'aawservice.exe',
		'aawtray.exe',		'ad-aware.exe',			'ad-watch.exe',			'alescan.exe',		'anvir.exe',
		'ashdisp.exe',		'ashmaisv.exe',			'ashserv.exe',			'ashwebsv.exe',		'aswupdsv.exe',
		'atrack.exe',		'avgagent.exe',			'avgamsvr.exe',			'avgcc.exe',		'avgctrl.exe',
		'avgemc.exe',		'avgnt.exe',			'avgtcpsv.exe',			'avguard.exe',		'avgupsvc.exe',
		'avgw.exe',			'avkbar.exe',			'avk.exe',				'avkpop.exe',		'avkproxy.exe',
		'avkservice.exe',	'avktray',				'avktray.exe',			'avkwctl',			'avkwctl.exe',
		'avmailc.exe',		'avp.exe',				'avpm.exe',				'avpmwrap.exe',		'avsched32.exe',
		'avwebgrd.exe',		'avwin.exe',			'avwupsrv.exe',			'avz.exe',			'bdagent.exe',
		'bdmcon.exe',		'bdnagent.exe',			'bdss.exe',				'bdswitch.exe',		'blackd.exe',
		'blackice.exe',		'blink.exe',			'boc412.exe',			'boc425.exe',		'bocore.exe',
		'bootwarn.exe',		'cavrid.exe',			'cavtray.exe',			'ccapp.exe',		'ccevtmgr.exe',
		'ccimscan.exe',		'ccproxy.exe',			'ccpwdsvc.exe',			'ccpxysvc.exe',		'ccsetmgr.exe',
		'cfgwiz.exe',		'cfp.exe',				'clamd.exe',			'clamservice.exe',	'clamtray.exe',
		'cmdagent.exe',		'cpd.exe',				'cpf.exe',				'csinsmnt.exe',		'dcsuserprot.exe',
		'defensewall.exe',	'defensewall_serv.exe',	'defwatch.exe',			'f-agnt95.exe',		'fpavupdm.exe',
		'f-prot95.exe',		'f-prot.exe',			'fprot.exe',			'fsaua.exe',		'fsav32.exe',
		'f-sched.exe',		'fsdfwd.exe',			'fsm32.exe',			'fsma32.exe',		'fssm32.exe',
		'f-stopw.exe',		'f-stopw.exe',			'fwservice.exe',		'fwsrv.exe',		'iamstats.exe',
		'iao.exe',			'icload95.exe',			'icmon.exe',			'idsinst.exe',		'idslu.exe',
		'inetupd.exe',		'irsetup.exe',			'isafe.exe',			'isignup.exe',		'issvc.exe',
		'kav.exe',			'kavss.exe',			'kavsvc.exe',			'klswd.exe',		'kpf4gui.exe',
		'kpf4ss.exe',		'livesrv.exe',			'lpfw.exe',				'mcagent.exe',		'mcdetect.exe',
		'mcmnhdlr.exe',		'mcrdsvc.exe',			'mcshield.exe',			'mctskshd.exe',		'mcvsshld.exe',
		'mghtml.exe',		'mpftray.exe',			'msascui.exe',			'mscifapp.exe',		'msfwsvc.exe',
		'msgsys.exe',		'msssrv.exe',			'navapsvc.exe',			'navapw32.exe',		'navlogon.dll',
		'navstub.exe',		'navw32.exe',			'nisemsvr.exe',			'nisum.exe',		'nmain.exe',
		'noads.exe',		'nod32krn.exe',			'nod32kui.exe',			'nod32ra.exe',		'npfmntor.exe',
		'nprotect.exe',		'nsmdtr.exe',			'oasclnt.exe',			'ofcdog.exe',		'opscan.exe',
		'ossec-agent.exe',	'outpost.exe',			'paamsrv.exe',			'pavfnsvr.exe',		'pcclient.exe',
		'pccpfw.exe',		'pccwin98.exe',			'persfw.exe',			'protector.exe',	'qconsole.exe',
		'qdcsfs.exe',		'rtvscan.exe',			'sadblock.exe',			'safe.exe',			'sandboxieserver.exe',
		'savscan.exe',		'sbiectrl.exe',			'sbiesvc.exe',			'sbserv.exe',		'scfservice.exe',
		'sched.exe',		'schedm.exe',			'scheduler daemon.exe',	'sdhelp.exe',		'serv95.exe',
		'sgbhp.exe',		'sgmain.exe',			'slee503.exe',			'smartfix.exe',		'smc.exe',
		'snoopfreesvc.exe',	'snoopfreeui.exe',		'spbbcsvc.exe',			'sp_rsser.exe',		'spyblocker.exe',
		'spybotsd.exe',		'spysweeper.exe',		'spysweeperui.exe',		'spywareguard.dll',	'spywareterminatorshield.exe',
		'ssu.exe',			'steganos5.exe',		'stinger.exe',			'swdoctor.exe',		'swupdate.exe',
		'symlcsvc.exe',		'symundo.exe',			'symwsc.exe',			'symwscno.exe',		'tcguard.exe',
		'tds2-98.exe',		'tds-3.exe',			'teatimer.exe',			'tgbbob.exe',		'tgbstarter.exe',
		'tsatudt.exe',		'umxagent.exe',			'umxcfg.exe',			'umxfwhlp.exe',		'umxlu.exe',
		'umxpol.exe',		'umxtray.exe',			'usrprmpt.exe',			'vetmsg9x.exe',		'vetmsg.exe',
		'vptray.exe',		'vsaccess.exe',			'vsserv.exe',			'wcantispy.exe',	'win-bugsfix.exe',
		'winpatrol.exe',	'winpa'"'"'rolex.exe',	'wrsssdk.exe',			'xcommsvr.exe',		'xfr.exe',
		'xp-antispy.exe',	'zegarynka.exe',		'zlclient.exe',
		
		# Agregados posteriormente:
		'mbamtray.exe',		'mbamservice.exe', 
]


class AvScan():
	
	HKLM = winreg.HKEY_LOCAL_MACHINE
	HKCU = winreg.HKEY_CURRENT_USER
	
	run_command = lambda self, Comando: os.popen(Comando).read()
	
	def __init__(self): pass
	
	def scanReg(self, antivirus):
		
		regs = [
			'SOFTWARE\\{}',
			'SYSTEM\\{} AntiVirus',
			'SOFTWARE\\Wow6432Node\\{}',
			'SYSTEM\\CurrentControlSet\\Services\\{} AntiVirus',
			'SOFTWARE\\Microsoft\\Security Center\\Monitoring\\{}AntiVirus'
		]
		
		for HK in [self.HKCU, self.HKLM]:
			for reg in regs:
				if self.regExists(HK, reg.format(antivirus)):
					return True
		
		return False
	
	def getStatusWinDef(self):
		
		key = False
		regs = ['SOFTWARE\\Microsoft\\{}', 'SOFTWARE\\Policies\\Microsoft\\{}']
		
		for HK in [self.HKCU, self.HKLM]:
			for reg in regs:
				if self.regExists(HK, reg.format('Windows Defender')):
					key = True
		
		cad = '    [*] '
		
		if key:
			try:
				if winreg.QueryValueEx(key, "DisableAntiSpyware")[0] == 1:
					cad += 'Deshabilitado'
				else:
					cad += 'Corriendo'
			except:
				cad += 'Corriendo'
		else:
			cad += 'No Instalado'
		
		return cad + '\n'
	
	def regExists(self, HKEY, SubKey):
		try:
			winreg.OpenKey(HKEY, SubKey, 0, winreg.KEY_READ)
			return True
		except: return False
	
	def getAVsDetected(self):
		
		exists = False
		log = ''
		
		if self.scanReg('AhnLab'):			log += '    [*] AhnLab V3\n';		exists = True
		if self.scanReg('Avast'):			log += '    [*] Avast\n';			exists = True
		if self.scanReg('AVG'):				log += '    [*] AVG\n';				exists = True
		if self.scanReg('Avira'):			log += '    [*] Avira\n';			exists = True
		if self.scanReg('BitDefender'):		log += '    [*] BitDefender\n';		exists = True
		if self.scanReg('BullGuard'):		log += '    [*] BullGuard\n';		exists = True
		if self.scanReg('ClamAV'):			log += '    [*] ClamAV\n';			exists = True
		if self.scanReg('Comodo'):			log += '    [*] Comodo\n';			exists = True
		if self.scanReg('Cyren'):			log += '    [*] Cyren\n';			exists = True
		if self.scanReg('DrWeb'):			log += '    [*] DrWeb\n';			exists = True
		if self.scanReg('eScan'):			log += '    [*] escan Micro\n';		exists = True
		if self.scanReg('ESET'):			log += '    [*] ESET\n';			exists = True
		if self.scanReg('F-Prot'):			log += '    [*] F-Prot\n';			exists = True
		if self.scanReg('F-Secure'):		log += '    [*] F-Secure\n';		exists = True
		if self.scanReg('Ikarus'):			log += '    [*] Ikarus\n';			exists = True
		if self.scanReg('Kaspersky'):		log += '    [*] Kaspersky\n';		exists = True
		if self.scanReg('Malwarebytes'):	log += '    [*] Malwarebytes\n';	exists = True
		if self.scanReg('McAfee'):			log += '    [*] McAfee\n';			exists = True
		if self.scanReg('MicroWorld'):		log += '    [*] MicroWorld\n';		exists = True
		if self.scanReg('Panda'):			log += '    [*] Panda\n';			exists = True
		if self.scanReg('QuickHeal'):		log += '    [*] QuickHeal\n';		exists = True
		if self.scanReg('Sophos'):			log += '    [*] Sophos\n';			exists = True
		if self.scanReg('Symantec'):		log += '    [*] Symantec\n';		exists = True
		if self.scanReg('Trend Micro'):		log += '    [*] Trend Micro\n';		exists = True
		if self.scanReg('Zoner Antivirus'):	log += '    [*] Zoner Antivirus\n';	exists = True
		
		if not exists: log += '    [-] No se detectaron AVs, HIPS y/o Firewalls de terceros.'
		
		return log
	
	def getPossibleProcess(self):
		
		log = ''
		lista_procesos = []
		
		procesos = self.run_command('wmic process get name, ProcessId').split('\n')
		
		for proc in procesos:
		
			proc = proc.strip().split(' ')
			name = proc[0]
			pid  = proc[-1]
			
			if name.endswith('.exe') and (name.lower() in avs):
				lista_procesos.append((pid, name))
		
		if len(lista_procesos) > 0:
			
			lista_procesos.sort()
			
			for pid, nombre in lista_procesos:
				log += '    ' + pid
				log += '\t\t' if len(pid) < 4 else '\t'
				log += '  ' + nombre + '\n'
		
		else: log += '\n [-] No se detectaron otros posibles AVs, HIPS y/o Firewalls de terceros.\n'
		
		return log
		




if __name__ == '__main__':
	
	AvS = AvScan()
	
	log = '\n\n\n Información de Escaneo de AVs, HIPS y/o Firewalls:\n\n\n\n'
	log += ' [+] Estado de Windows Defender:\n\n'
	log += AvS.getStatusWinDef()
	log += '\n\n\n'
	log += ' [+] Antivirus y/o Antimalwares Detectados:\n\n'
	log += AvS.getAVsDetected()
	log += '\n\n\n'
	log += ' [+] Escaneo de procesos:\n\n'
	log += '    PID \t  Nombre de la Imagen\n'
	log += '   ______\t ________________________________\n\n'
	log += AvS.getPossibleProcess()
	
	print(log)


