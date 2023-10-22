import os
import subprocess
import base64
import time
import pyuac
from multiprocessing import Process
from pwinput import pwinput
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

uName = os.environ["username"]
bit9_id = r'C:\Program Files (x86)\Bit9\Parity Agent'
bit9_st = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\logs\\bit9.log'
bit9_uninstall = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\logs\\uninstall.log'
bit9_install = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\logs\\install.log'
bit9_proxy = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\logs\\proxy.log'
d3s_fx0 = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance'

#limpa tela
def cl3_Ax0():
    os.system("cls")
#Encrypt   
def g3n_Ax0(Nill):
    salt = b'<salt>'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256,
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(Nill))
    return key

def d3c_Ax0(M3nc_Mx0, Nill):
    key = g3n_Ax0(Nill)
    fernet = Fernet(key)
    d3C_Mx0 = fernet.decrypt(M3nc_Mx0)
    return d3C_Mx0.decode()

def rFF_Mx0(f_Mx0):
    with open(f_Mx0, "rb") as f_M:
        f3nc_Mx0 = f_M.read()
        f_M.close()
    return f3nc_Mx0

def s3P_Ax0():
    Nill = b'<Sua senha aqui>'
    return Nill

def g3t_Ax0():
    Nill = s3P_Ax0()
    fP_Ax0 = d3s_fx0 + '\\<arquivo>'
    e3n_Ax0 = rFF_Mx0(fP_Ax0)
    d3C_Ax0 = d3c_Ax0(e3n_Ax0, Nill)
    return d3C_Ax0
#verifica versão
def ch_x0():
    ar_fx9()
    with open(bit9_st, "r") as f_x0:
        f_x0.seek(0)
        lines = f_x0.read()
        f_x0.close()
        if '    Agent:      8.9' in lines:
            return '{AC01D403-EAD0-436E-9DB9-BFEE34DF2492}'
        elif '    Agent:      8.8' in lines:
            return '{49E143F1-8B61-45A9-A6C2-7C106CC8E325}'
        elif '    Agent:      8.7.8' in lines:
            return '{253ED65C-993F-452D-A441-10481DFCFD9A}'
        elif '    Agent:      8.7.6' in lines:
            return '{38333681-B06D-499A-824F-B94E34CC8197}' 
        elif '    Agent:      8.7.5' in lines:
            return '{38333681-B06D-499A-824F-B94E34CC8197}' 
        elif '    Agent:      8.7.4' in lines:
            return '{38333681-B06D-499A-824F-B94E34CC8197}' 
        elif '    Agent:      8.7.2' in lines:
            return '{80947C61-D901-486F-89E2-296D6CFE8AAC}' 
        elif '    Agent:      8.7.0' in lines:
            return '{1C327257-4E0D-4AEC-9230-4E1A2A7D04A5}'
        elif '    Agent:      8.6' in lines:
            return '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}'
        elif '    Agent:      8.5' in lines:
            return '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}'
        elif '    Agent:      8.4' in lines:
            return '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}'
        elif '    Agent:      8.3' in lines:
            return '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}'
        elif '    Agent:      8.2' in lines:
            return '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}'
        elif '    Agent:      8.1' in lines:
            return '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}'
        elif '    Agent:      8.0' in lines:
            return '{DA971CA3-73AA-4A57-AFB4-8155E72CEB96}'
        else:
            return "Versão desconhecida"
#remove bit9   
def r_Ax0():
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print(' == == == == == REMOVER BIT9 == == == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    try:
        os.chdir(bit9_id)
    except OSError:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
        return 0
    if os.path.exists(bit9_id+'\\DasCLI.exe'):
        #evita que qualquer um desisntale 
        sh_tx56=pwinput(prompt="Por favor, insira a senha Master para realizar a desinstalação: ", mask='*')
        if sh_tx56 == g3t_Ax0():
            print("Iniciando Processo...")
            t3m_fx0()
            swe_fx0 = ch_x0()
            os.chdir(d3s_fx0+'\\agents')
            subprocess.run(['AgentUninstallUtility.exe', '-password', g3t_Ax0(), "-uninstall", '/s', '/y'],stdout=open(bit9_uninstall, "a"))
            subprocess.run(["cmd.exe", "/C", "del", "C:\\Program Files (x86)\\Bit9", "/f", "/Q"],stdout=open(bit9_uninstall, "a"),stderr=open(bit9_uninstall,"a"))
            subprocess.run(["cmd.exe", "/C", "del", "C:\\Windows\\System32\\drivers\\Parity.sys", '/f'],stdout=open(bit9_uninstall, "a"),stderr=open(bit9_uninstall,"a"))
            subprocess.run(["cmd.exe", "/C", "del", "C:\\Windows\\System32\\DRVSTORE\\Parity*.*", '/f'],stdout=open(bit9_uninstall, "a"),stderr=open(bit9_uninstall,"a"))
            print('')
            print('Aguarde, estamos finalizando a desinstalação')
            print('')
            subprocess.run(['msiexec.exe', '/x', swe_fx0, '/qn', 'FORCE=1'],stdout=open(bit9_uninstall, "a"))
            print('')
            print('Mais alguns instantes...')
            print('')
            subprocess.run(['AgentUninstallUtility.exe', '-password', g3t_Ax0(), "-uninstall", '/s', '/y'],stdout=open(bit9_uninstall, "a"))
            print("Finalizando processos msiexec")
            subprocess.run(['taskkill', '/IM', 'msiexec.exe', '/F'],stdout=open(bit9_uninstall, "a"),stderr=open(bit9_uninstall,"a"))
            print("\n\nNão é necessário o reinicio do servidor...")
            restart = input("Gostaria de reiniciar o servidor agora ? ( S / N (Enter)):")
            if restart == 's' or restart == 'S':
                os.system("shutdown /r /t 1")
        else:
            cl3_Ax0()
            input("Senha incorreta! Aperte enter para voltar ao Menu.")
    else:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
    return 0
#instala bit9
def in5_Ax0():
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print('== == == == == INSTALAR BIT9 == == == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    try:
        if os.path.exists(bit9_id+'\\DasCLI.exe'):
            print("Bit9 já está instalado!")
            input("Pressione Enter para continuar...") 
        else:
            print("Finalizando processos msiexec abertos...")
            subprocess.run(['taskkill', '/IM', 'msiexec.exe', '/F'], stdout=open(bit9_install, "a"),stderr=open(bit9_install,"a"))
            print('Executando instalador, por favor aguarde...')
            subprocess.run(['msiexec.exe', '/i', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\fisbr-monitor.msi', '/qn'],stdout=open(bit9_install, "a"))
            g4T_Ax0()
            print("Executado com sucesso.")
            input("Pressione Enter para continuar...")
    except OSError:
        print("Houve um problema ao tentar instalar, tente novamente.")
        input("Pressione Enter para continuar...")
    return 0
#coletar status
def r3P_Fx0():
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print('== == == == COLETAR STATUS BIT9 == == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    try:
        os.chdir(bit9_id)
        subprocess.run(['DasCLI.exe', 'status'], stdout=open(bit9_st, "w"))
        with open(bit9_st, "r") as f_x2:
            f_x2.seek(0)
            lines = f_x2.read()
            f_x2.close()
            print(lines)
    except FileNotFoundError:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
        return 0
    except OSError:
        print("O Dascli não pode ser encontrado, tente novamente.")
        input("Pressione Enter para continuar...")
        return 0
    print('')
    print("Executado com sucesso.")
    input("Pressione Enter para continuar...")
    return 0
#retorna versão
def r3P_Fx1():
    cl3_Ax0()
    try:
        os.chdir(bit9_id)
    except OSError:
        return 'Versão do Carbon Black não disponível'
    try:
        subprocess.run(['DasCLI.exe', 'status'], stdout=open(bit9_st, "w"))
        with open(bit9_st, "r") as f_x0:
            f_x0.seek(0)
            lines = f_x0.read()
            f_x0.close()
            if '    Agent:      8.9' in lines:
                return '8.9'
            elif '    Agent:      8.8' in lines:
                return '8.8'
            elif '    Agent:      8.7.8' in lines:
                return '8.7.8'
            elif '    Agent:      8.7.6' in lines:
                return '8.7.6' 
            elif '    Agent:      8.7.5' in lines:
                return '8.7.5' 
            elif '    Agent:      8.7.4' in lines:
                return '8.7.4' 
            elif '    Agent:      8.7.2' in lines:
                return '8.7.2' 
            elif '    Agent:      8.7.0' in lines:
                return '8.7.0'
            elif '    Agent:      8.6' in lines:
                return '8.6'
            elif '    Agent:      8.5' in lines:
                return '8.5'
            elif '    Agent:      8.4' in lines:
                return '8.4'
            elif '    Agent:      8.3' in lines:
                return '8.3'
            elif '    Agent:      8.2' in lines:
                return '8.2'
            elif '    Agent:      8.1' in lines:
                return '8.1'
            elif '    Agent:      8.0' in lines:
                return '8.0'
            else:  
                return 'Versão do Carbon Black não disponível'
    except OSError:
        return 'Versão do Carbon Black não disponível'
#configura dascli
def g4T_Ax0():
    print('Configurando Dascli')
    countdown(15)
    t3m_fx1()
    print('Esperando client se conectar...')
    countdown(45)
    return 0
#tira tamper
def t3m_fx0():
    try:
        os.chdir(bit9_id)
        subprocess.run(['DasCLI.exe', 'password', g3t_Ax0()],stdout=open(bit9_uninstall, "a"))
        subprocess.run(['DasCLI.exe', 'tamperprotect', '0'],stdout=open(bit9_uninstall, "a"))
        subprocess.run(['DasCLI.exe', 'allowuninstall', '1'],stdout=open(bit9_uninstall, "a"))
    except OSError:
        print("Houve um problema ao tentar remover o AntiTamper")
        input("Pressione Enter para continuar...")
    return 0
#coloca tamper
def t3m_fx1():
    try:
        os.chdir(bit9_id)
        subprocess.run(['DasCLI.exe', 'password', g3t_Ax0()],stdout=open(bit9_install, "a"))
        subprocess.run(['DasCLI.exe', 'tamperprotect', '1'],stdout=open(bit9_install, "a"))
        subprocess.run(['DasCLI.exe', 'allowuninstall', '0'],stdout=open(bit9_install, "a"))
    except OSError:
        print("Houve um problema com o Dascli, tente novamente após instalar")
        input("Pressione Enter para continuar...")
    return 0
#seta password
def ar_fx9():
    try:
        os.chdir(bit9_id)
    except OSError:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
    try:
        subprocess.run(['DasCLI.exe', 'password', g3t_Ax0()])
    except OSError:
        print("Houve um problema com o Dascli, tente novamente após instalar")
        input("Pressione Enter para continuar...")
    return 0
#verifica proxy
def sh_prox():
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print('== == == == == Verificando Proxy == == == == == ==')
    print('== == == == == == == == == == == == == == == == ==')
    print("Verificando proxy...")
    subprocess.run(['netsh.exe', 'winhttp', 'show', 'proxy'], stdout=open(bit9_proxy, "w"))
    with open(bit9_proxy, "r") as f_x0:
        f_x0.seek(0)
        lines = f_x0.read()
        f_x0.close()
        if 'Direct access (no proxy server).' in lines:
            print('')
            print("O proxy está configurado!")
            print('Continuando em: ')
            countdown(5)
            return 0
        print("Proxy não configurado")
        print("Configurando proxy...")
        subprocess.run(['netsh.exe', 'winhttp', 'reset', 'proxy'])
        input('Proxy configurado! Aperte ENTER para voltar ao menu')
        return 0      
#faz o countdown
def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1
    return 0
#banner
def inf_Ax0(version):
    print('=========================================================================')
    print("Computador:", os.environ["computername"],
        " Usuario:", os.environ["username"], " cdw:", os.getcwd())
    print("\nVersão do Bit9:", version)
    print('=========================================================================')
#verifica se é adm
if not pyuac.isUserAdmin():
    print("Abrindo nova instância como Admin!")
    print("Caso isso não resolva, executar como administrador a partir de um CMD!")
    pyuac.runAsAdmin()
    #for f in os.listdir(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\'):
    #    if 'Maintenance.exe' in f:
    #       subprocess.run(['cmd.exe', '/C', 'del', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\Maintenance.exe'])
#menu
else:
    os.chdir(d3s_fx0)
    menu = {}
    menu['1'] = "Validação/Correção proxy"
    menu['2'] = "Remover Bit9"
    menu['3'] = "Instalar Bit9"
    menu['4'] = "Coletar Status Bit9"
    menu['7'] = "Sair"
    while True:
        options = menu.keys()
        vers = r3P_Fx1()
        cl3_Ax0()
        inf_Ax0(vers)
        for entry in options:
            print(entry, menu[entry])
        selection = input("Selecione:")
        if selection == '1':
            sh_prox()
        elif selection == '2':
            sh_prox()
            print("Executando desinstalação...")
            countdown(5)
            r_Ax0()
        elif selection == '3':
            in5_Ax0()
        elif selection == '4':
            r3P_Fx0()
        elif selection == '7':
            break
        else:
            input("Opção inexistente! Aperte qualquer tecla para voltar ao menu")
cl3_Ax0()
