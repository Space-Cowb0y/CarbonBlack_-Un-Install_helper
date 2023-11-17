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
dascli_auth = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\logs\\dascli.log'
bit9_install = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\logs\\install.log'
bit9_proxy = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\logs\\proxy.log'
d3s_fx0 = os.environ["userprofile"]+'\\Desktop\\CB_Maintenance'
v_D1t = {
    '    Agent:      8.9' : '{AC01D403-EAD0-436E-9DB9-BFEE34DF2492}',
    '    Agent:      8.8' : '{49E143F1-8B61-45A9-A6C2-7C106CC8E325}',
    '    Agent:      8.7.8' : '{253ED65C-993F-452D-A441-10481DFCFD9A}',
    '    Agent:      8.7.6' : '{38333681-B06D-499A-824F-B94E34CC8197}', 
    '    Agent:      8.7.5' : '{38333681-B06D-499A-824F-B94E34CC8197}', 
    '    Agent:      8.7.4' : '{38333681-B06D-499A-824F-B94E34CC8197}', 
    '    Agent:      8.7.2' : '{80947C61-D901-486F-89E2-296D6CFE8AAC}', 
    '    Agent:      8.7.0' : '{1C327257-4E0D-4AEC-9230-4E1A2A7D04A5}',
    '    Agent:      8.6' : '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}',
    '    Agent:      8.5' : '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}',
    '    Agent:      8.4' : '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}',
    '    Agent:      8.3' : '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}',
    '    Agent:      8.2' : '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}',
    '    Agent:      8.1' : '{9F2D4E59-0528-4B22-B664-A6B0B8B482EE}',
    '    Agent:      8.0' : '{DA971CA3-73AA-4A57-AFB4-8155E72CEB96}'
}
v_D2t ={
    '    Agent:      8.9' : '8.9',
    '    Agent:      8.8' : '8.8',
    '    Agent:      8.7.8' : '8.7.8',
    '    Agent:      8.7.6' : '8.7.6', 
    '    Agent:      8.7.5' : '8.7.5', 
    '    Agent:      8.7.4' : '8.7.4', 
    '    Agent:      8.7.2' : '8.7.2', 
    '    Agent:      8.7.0' : '8.7.0',
    '    Agent:      8.6' : '8.6',
    '    Agent:      8.5' : '8.5',
    '    Agent:      8.4' : '8.4',
    '    Agent:      8.3' : '8.3',
    '    Agent:      8.2' : '8.2',
    '    Agent:      8.1' : ' 8.1',
    '    Agent:      8.0' : '8.0'
    
}

#limpa tela
def cl3_Ax0():
    os.system("cls")
#dEncrypt   
def g3n_Ax0(Nill):
    salt = b'<salt auqi>'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
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
def g3t_Ax0():
    Nill = s3P_Ax0()
    fP_Ax0 = d3s_fx0 + '\\overdue.dll'
    e3n_Ax0 = rFF_Mx0(fP_Ax0)
    d3C_Ax0 = d3c_Ax0(e3n_Ax0, Nill)
    return d3C_Ax0
#verifica versão
def ch_x0():
    ar_fx9()
    with open(bit9_st, "r") as f_x0:
        f_x0.seek(0)
        lines = f_x0.readline()
        f_x0.close()
        for i in v_D1t:
            if i in lines:
                return v_D1t[i]
            else:
                return "Versão do Carbon Black não disponível"     
#verifica se a senha digitada é correta e inicia a desinstalação
def v3f_S3h():
    try:
        os.chdir(bit9_id)
    except OSError:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
        return 0
    if os.path.exists(bit9_id+'\\DasCLI.exe'):
        sh_tx56=pwinput(prompt="Por favor, insira a senha Master para realizar a desinstalação: ", mask='*')
        if sh_tx56 == g3t_Ax0():
            r_Ax0()
        else:
            cl3_Ax0()
            input("Senha incorreta! Aperte enter para voltar ao Menu.")
    else:
        print("O DasCli não foi encontrado.")
        input("Pressione Enter para continuar...")
    return 0    
#remove bit9   
def r_Ax0():
    cl3_Ax0()
    print('== == == == == == == == == == == == == == == == ==')
    print(' == == == == == REMOVER BIT9 == == == == == == == ')
    print('== == == == == == == == == == == == == == == == ==')
    print("Iniciando Processo...")
    t3m_fx0()
    swe_fx0 = ch_x0()
    os.chdir(d3s_fx0+'\\agents')
    subprocess.run(['AgentUninstallUtility.exe', '-password', g3t_Ax0(), "-uninstall", '/s', '/y'],stdout=open(bit9_uninstall, "a"))
    subprocess.run(["cmd.exe", "/C", "del", "C:\\Program Files (x86)\\Bit9", "/f", "/Q"],stdout=open(bit9_uninstall, "a"),stderr=open(bit9_uninstall,"a"))
    print('')
    print('Aguarde...')
    print('')
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
    print('')
    subprocess.run(['taskkill', '/IM', 'msiexec.exe', '/F'],stdout=open(bit9_uninstall, "a"),stderr=open(bit9_uninstall,"a"))
    print("\n\nNa maioria dos casos não é necessário o reinicio do servidor...")
    restart = input("Gostaria de reiniciar o servidor agora ? ( S / N (Enter)):")
    if restart == 's' or restart == 'S':
        os.system("shutdown /r /t 1")
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
            print('Executando instalador, por favor aguarde, Este processo pode demorar um pouco...')
            subprocess.run(['msiexec.exe', '/i', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\fisbr-monitor.msi', '/qn'],stdout=open(bit9_install, "a"),stderr=open(bit9_install, "a"))
            g4T_Ax0()
            print("Executado com sucesso.")
            input("Pressione Enter para continuar...")
    except OSError:
        print("Houve um problema ao tentar instalar, tente novamente.")
        input("Pressione Enter para continuar...")
    return 0
#reinstalar bit9
def r3v_In5():
    r_Ax0()
    in5_Ax0()
    input("processo de reinstalação concluido... pressione enter para continuar...")
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
            lines = f_x0.readline()
            f_x0.close()
            for i in v_D2t:
                if i in lines:
                    return v_D2t[i]
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
        subprocess.run(['DasCLI.exe', 'password', g3t_Ax0()],stdout=open(dascli_auth, "w"))
        with open(dascli_auth, "r") as f_x3:
            f_x3.seek(0)
            lines = f_x3.read()
            f_x3.close()
            if "Authentication Failed" not in lines:
                subprocess.run(['DasCLI.exe', 'tamperprotect', '0'],stdout=open(dascli_auth, "a"))
                subprocess.run(['DasCLI.exe', 'allowuninstall', '1'],stdout=open(dascli_auth, "a"))
            else:
                print("Senha desatualizada no agent. voltando ao menu...")
                countdown(5)
    except OSError:
        print("Houve um problema com o Dascli, tente novamente.")
        input("Pressione Enter para continuar...")
        return m3_n7()
    return 0
#coloca tamper
def t3m_fx1():
    try:
        os.chdir(bit9_id)
        subprocess.run(['DasCLI.exe', 'password', g3t_Ax0()],stdout=open(dascli_auth, "w"))
        with open(dascli_auth, "r") as f_x3:
            f_x3.seek(0)
            lines = f_x3.read()
            f_x3.close()
            if "Authentication Failed" not in lines:
                subprocess.run(['DasCLI.exe', 'tamperprotect', '0'],stdout=open(dascli_auth, "a"))
                subprocess.run(['DasCLI.exe', 'allowuninstall', '1'],stdout=open(dascli_auth, "a"))
            else:
                print("Senha desatualizada no agent. voltando ao menu...")
                countdown(5)
    except OSError:
        print("Houve um problema com o Dascli, tente novamente.")
        input("Pressione Enter para continuar...")
    return 0
#seta password
def ar_fx9():
    try:
        os.chdir(bit9_id)
    except OSError:
        print("O Bit9 não está instalado.")
        input("Pressione Enter para continuar...")
        return m3_n7()
    try:
        subprocess.run(['DasCLI.exe', 'password', g3t_Ax0()],stdout=open(dascli_auth, "w"))
        with open(dascli_auth, "r") as f_x3:
            f_x3.seek(0)
            lines = f_x3.read()
            f_x3.close()
            if "Authentication Failed" in lines:
                input("Problema durante a autenticação... Aperte qualquer tecla para voltar ao menu.")
    except OSError:
        print("Houve um problema com o Dascli, tente novamente.")
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
#menu
def m3_n7():
    #os.chdir(d3s_fx0)
    menu = {}
    menu['1'] = "Validação/Correção proxy"
    menu['2'] = "Remover Bit9"
    menu['3'] = "Instalar Bit9"
    menu['4'] = "Coletar Status Bit9"
    menu['7'] = "Sair"
    menu['8'] = "Reinstall"
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
            countdown(3)
            v3f_S3h()
        elif selection == '3':
            in5_Ax0()
        elif selection == '4':
            r3P_Fx0()
        elif selection == '7':
            break
        elif selection == '8':
            r3v_In5()
        else:
            input("Opção inexistente! Aperte qualquer tecla para voltar ao menu")
            cl3_Ax0()

#verifica se é adm e chama menu
if not pyuac.isUserAdmin():
    print("Abrindo nova instância como Admin!")
    print("Caso isso não resolva, executar como administrador a partir de um CMD!")
    pyuac.runAsAdmin()
    #for f in os.listdir(os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\'):
    #    if 'Maintenance.exe' in f:
    #       subprocess.run(['cmd.exe', '/C', 'del', os.environ["userprofile"]+'\\Desktop\\CB_Maintenance\\agents\\Maintenance.exe'])
else:
    m3_n7()
