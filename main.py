import os
import subprocess
import base64
import time
import glob
import pyuac
import shutil
from getpass import getpass
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

uName = os.environ["username"]
bit9_st = 'C:\\Users\\Public\\bit9.txt'
bit9_id = 'C:\\Program Files (x86)\\Bit9\\Parity Agent'

#limpa tela
def cl3_Ax0():
    os.system("cls")
#Encrypt   
def g3n_Ax0(Nill):
    salt = b'<salt aqui>'
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
    Nill = b'<secret aqui>'
    return Nill

def g3t_Ax0(fP_Ax0):
    Nill = s3P_Ax0()
    fP_Ax0 = fP_Ax0 + '\\<nome do arquivo contendo a senha criptografada>.dll'
    e3n_Ax0 = rFF_Mx0(fP_Ax0)
    d3C_Ax0 = d3c_Ax0(e3n_Ax0, Nill)
    return d3C_Ax0
#verifica versão
def ch_x0(p4x_fx0):
    ar_fx9(p4x_fx0)
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
    
def r_Ax0(p4x_fx0):
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print(' == == == == == REMOVER BIT9 == == == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    try:
        os.chdir(bit9_id)
    except FileNotFoundError:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
        return 0
    sh_tx56=getpass("Por favor, insira a senha Master para realizar a desinstalação: ",'*')
    if sh_tx56 == p4x_fx0:
        os.chdir(bit9_id)
        t3m_fx0(p4x_fx0)
        swe_fx0 = ch_x0(p4x_fx0)
        os.chdir(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents')
        subprocess.run(['AgentUninstallUtility.exe', '-password', p4x_fx0, '-logfile', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\uninstallLog.txt', "-uninstall", '/s', '/y'])
        subprocess.run(["cmd.exe", "/C", "del", "C:\\Program Files (x86)\\Bit9", "/f", "/Q"])
        subprocess.run(["cmd.exe", "/C", "del", "C:\\Windows\\System32\\drivers\\Parity.sys", '/f'])
        subprocess.run(["cmd.exe", "/C", "del", "C:\\Windows\\System32\\DRVSTORE\\Parity*.*", '/f'])
        print('')
        print('Aguarde, estamos finalizando a desinstalação')
        subprocess.run(['msiexec.exe', '/x', swe_fx0, '/qn', 'FORCE=1'])
        subprocess.run(['AgentUninstallUtility.exe', '-password', p4x_fx0, "-uninstall", '/s', '/y'])
        try:
            print("Finalizando processos msiexec")
            subprocess.run(['taskkill', '/IM', 'msiexec.exe', '/F'])
        except:
            print("Continuando desinstalação...")
        print("\n\nNão é necessário o reinicio do servidor...")
        restart = input("Gostaria de reiniciar o servidor agora ? ( S / N (Enter)):")
        if restart == 's' or restart == 'S':
            os.system("shutdown /r /t 1")
        else:
            return 0
    else:
        input("Senha incorreta! Aperte enter para voltar ao Menu")
    return 0


def in5_Ax0(p4x_fx0):
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print('== == == == == INSTALAR BIT9 == == == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    if os.path.exists(r"C:\Program Files (x86)\Bit9\Parity Agent"):
        print("Bit9 já está instalado!")
        input("Pressione Enter para continuar...") 
    else:
        #os.chdir(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents')
        print("Finalizando processos msiexec abertos")
        try:
            subprocess.run(['taskkill', '/IM', 'msiexec.exe', '/F'])
        except ValueError:
            print("Continuando instalação...")
        print('Executando instalador, por favor aguarde...')
        subprocess.run(['msiexec.exe', '/i', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\fisbr-monitor.msi', '/qn', '/L*V', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\monitor_install.log'])
        g4T_Ax0(p4x_fx0)
        print("Executado com sucesso.")
        input("Pressione Enter para continuar...")

    return 0


def r3P_Fx0():
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print('== == == == COLETAR STATUS BIT9 == == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    try:
        os.chdir(bit9_id)
    except FileNotFoundError:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
        return 0
    os.chdir(bit9_id)
    subprocess.run(['DasCLI.exe', 'status'], stdout=open(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\bit9.txt', "w"))
    with open(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\bit9.txt', "r") as f_x2:
        f_x2.seek(0)
        lines = f_x2.read()
        f_x2.close()
        print(lines)
    print('')
    print("Executado com sucesso.")
    input("Pressione Enter para continuar...")
    return 0

def r3P_Fx1():
    cl3_Ax0()
    try:
        os.chdir(bit9_id)
    except FileNotFoundError:
        return 'Versão do Carbon Black não disponível'
    os.chdir(bit9_id)
    subprocess.run(['DasCLI.exe', 'status'], stdout=open(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\bit9.txt', "w"))
    with open(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\bit9.txt', "r") as f_x0:
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
            return 'Versão do Carbon Black não suportada'
   
def g4T_Ax0(p4x_fx0):
    print('== == == == == == == == == == == == == == == == ==')
    print('== == == == == CONFIGURAÇÃO DASCLI == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    print('Liberando Tamper...')
    countdown(15)
    print('Esperando client se conectar...')
    countdown(45)
    os.chdir(bit9_id)
    subprocess.run(['DasCLI.exe', 'password', p4x_fx0])
    subprocess.run(['DasCLI.exe', 'tamperprotect', '1'])
    subprocess.run(['DasCLI.exe', 'allowuninstall', '0'])
    return 0
    
def t3m_fx0(p4x_fx0):
    os.chdir(bit9_id)
    subprocess.run(['DasCLI.exe', 'password', p4x_fx0])
    subprocess.run(['DasCLI.exe', 'tamperprotect', '0'])
    subprocess.run(['DasCLI.exe', 'allowuninstall', '1'])
    return 0

def ar_fx9(p4x_fx0):
    try:
        os.chdir(bit9_id)
    except:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
        return 0
    os.chdir(bit9_id)
    wd_fx0 = os.getcwd()
    if wd_fx0 != bit9_id:
        os.chdir(bit9_id)
    subprocess.run(['DasCLI.exe', 'status'], stdout=open(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\bit9.txt', "w"))
    subprocess.run(['DasCLI.exe', 'password', p4x_fx0])
    return 0

def sh_prox():
    cl3_Ax0()
    print("Verificando proxy...")
    subprocess.run(['netsh.exe', 'winhttp', 'show', 'proxy'], stdout=open(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\proxy.txt', "w"))
    with open(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\proxy.txt', "r") as f_x0:
        f_x0.seek(0)
        lines = f_x0.read()
        f_x0.close()
        if 'Direct access (no proxy server).' in lines:
            print('')
            input("O proxy está configurado! Aperte ENTER para voltar ao menu")
            return 0
        print("Proxy não configurado")
        print("Configurando proxy...")
        subprocess.run(['netsh.exe', 'winhttp', 'reset', 'proxy'])
        input('Proxy configurado! Aperte ENTER para voltar ao menu')
        return 0      

def countdown(t):
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print(timer, end="\r")
        time.sleep(1)
        t -= 1
    return 0

def inf_Ax0(version):
    print('=========================================================================')

    print("Computador:", os.environ["computername"],
        " Usuario:", os.environ["username"], " cdw:", os.getcwd())
    print(" Versão do Bit9:", version)

    print('=========================================================================')

if not pyuac.isUserAdmin():
    print("Abrindo nova instância como Admin!")
    pyuac.runAsAdmin()
    #for f in os.listdir(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\'):
    #    if 'Maintenance.exe' in f:
    #       subprocess.run(['cmd.exe', '/C', 'del', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\Maintenance.exe'])
else:
    d3s_fx0 = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance'
    os.chdir(d3s_fx0)
    p4x_fx0 = g3t_Ax0(d3s_fx0)
    menu = {}
    menu['1'] = "Validação/Correção proxy"
    menu['2'] = "Remover Bit9"
    menu['3'] = "Instalar Bit9"
    menu['4'] = "Coletar Status Bit9"
    menu['7'] = "Sair"
    while True:
        options = menu.keys()
        #options.sort()
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
            r_Ax0(p4x_fx0)
        elif selection == '3':
            in5_Ax0(p4x_fx0)
        elif selection == '4':
            r3P_Fx0()
        elif selection == '7':
            break
        else:
            input("Opção inexistente! Aperte qualquer tecla para voltar ao menu")

#for f in os.listdir(os.environ["userprofile"]+'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'):
#        if 'Maintenance.exe' in f:
#            subprocess.run(['cmd.exe', '/C', 'del', os.environ["userprofile"]+'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Maintenance.exe'])
