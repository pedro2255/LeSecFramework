import os

def titulo():
    print(
"""
╭╮╱╱╭━━━╮╱╭━━━┳━━━┳━━━╮╱╱╭━━━┳━━━┳━━━┳━╮╭━┳━━━┳╮╭╮╭┳━━━┳━━━┳╮╭━╮
┃┃╱╱┃╭━━╯╱┃╭━╮┃╭━━┫╭━╮┃╱╱┃╭━━┫╭━╮┃╭━╮┃┃╰╯┃┃╭━━┫┃┃┃┃┃╭━╮┃╭━╮┃┃┃╭╯
┃┃╱╱┃╰━━╮╱┃╰━━┫╰━━┫┃╱╰╯╱╱┃╰━━┫╰━╯┃┃╱┃┃╭╮╭╮┃╰━━┫┃┃┃┃┃┃╱┃┃╰━╯┃╰╯╯
┃┃╱╭┫╭━┳┻━╋━━╮┃╭━━┫┃╱╭┳━━┫╭━━┫╭╮╭┫╰━╯┃┃┃┃┃┃╭━━┫╰╯╰╯┃┃╱┃┃╭╮╭┫╭╮┃
┃╰━╯┃╰━┻┳━┫╰━╯┃╰━━┫╰━╯┣━━┫┃╱╱┃┃┃╰┫╭━╮┃┃┃┃┃┃╰━━╋╮╭╮╭┫╰━╯┃┃┃╰┫┃┃╰╮
╰━━━┻━━━╯╱╰━━━┻━━━┻━━━╯╱╱╰╯╱╱╰╯╰━┻╯╱╰┻╯╰╯╰┻━━━╯╰╯╰╯╰━━━┻╯╰━┻╯╰━╯

░░░░░░░░░░░▄▄▀▀▀▀▀▀▀▀▄▄
░░░░░░░░▄▀▀░░░░░░░░░░░░▀▄▄
░░░░░░▄▀░░░░░░░░░░░░░░░░░░▀▄
░░░░░▌░░░░░░░░░░░░░▀▄░░░░░░░▀▀▄
░░░░▌░░░░░░░░░░░░░░░░▀▌░░░░░░░░▌
░░░▐░░░░░░░░░░░░▒░░░░░▌░░░░░░░░▐
░░░▌▐░░░░▐░░░░▐▒▒░░░░░▌░░░░░░░░░▌
░░▐░▌░░░░▌░░▐░▌▒▒▒░░░▐░░░░░▒░▌▐░▐
░░▐░▌▒░░░▌▄▄▀▀▌▌▒▒░▒░▐▀▌▀▌▄▒░▐▒▌░▌
░░░▌▌░▒░░▐▀▄▌▌▐▐▒▒▒▒▐▐▐▒▐▒▌▌░▐▒▌▄▐  - - "Olá eu sou sua assistente virtual, me chamo Ordália"
░▄▀▄▐▒▒▒░▌▌▄▀▄▐░▌▌▒▐░▌▄▀▄░▐▒░▐▒▌░▀▄
▀▄▀▒▒▌▒▒▄▀░▌█▐░░▐▐▀░░░▌█▐░▀▄▐▒▌▌░░░▀
░▀▀▄▄▐▒▀▄▀░▀▄▀░░░░░░░░▀▄▀▄▀▒▌░▐
░░░░▀▐▀▄▒▀▄░░░░░░░░▐░░░░░░▀▌▐
░░░░░░▌▒▌▐▒▀░░░░░░░░░░░░░░▐▒▐
░░░░░░▐░▐▒▌░░░░▄▄▀▀▀▀▄░░░░▌▒▐
░░░░░░░▌▐▒▐▄░░░▐▒▒▒▒▒▌░░▄▀▒░▐
░░░░░░▐░░▌▐▐▀▄░░▀▄▄▄▀░▄▀▐▒░░▐
░░░░░░▌▌░▌▐░▌▒▀▄▄░░░░▄▌▐░▌▒░▐
░░░░░▐▒▐░▐▐░▌▒▒▒▒▀▀▄▀▌▐░░▌▒░▌
░░░░░▌▒▒▌▐▒▌▒▒▒▒▒▒▒▒▐▀▄▌░▐▒▒
"""
)

#-------------------------------Funções e Codigos do Nmap-----------------------------------#

def menu_nmap():
    print("\n=== Nmap ===\n")
    print("Escolha uma opção:\n")
    print("1 - Especificação do Alvo")
    print("2 - Descoberta de Hosts") 
    print("3 - Técnicas de Escaneamento") 
    print("4 - Especificação de Portas e Ordem de Escaneamento") 
    print("5 - Detecção de Serviço e Versão") 
    print("6 - Varredura de Scripts (NSE)") 
    print("7 - Detecção de Sistema Operacional")
    print("8 - Temporização e Desempenho")
    print("9 - Evasão de Firewall/IDS e Falsificação")
    print("10 - Saída e Relatórios")
    print("11 - Voltar ao Menu Principal\n")
    
def escolher_categoria_nmap():
    opcao_nmap = int(input("Escolha uma Categoria:"))
    os.system("clear")

    if opcao_nmap == 1:
        alvo = input("Digite o alvo (IP, domínio ou rede, ex: 192.168.0.1 ou scanme.nmap.org): ")
        comando = f"nmap {alvo}"
        os.system(comando)
        input("Aperte enter para voltar:")
        os.system("clear")
        main()

    elif opcao_nmap == 2:
        alvo = (input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24):"))
        
        print("\nEscolha o tipo de descoberta de hosts:")
        print("1 - Varredura de lista")
        print("2 - Varredura de Ping")
        print("3 - Ignorar descoberta de hosts")
        print("4 - Descoberta TCP SYN")
        print("5 - Descoberta TCP ACK")
        print("6 - Descoberta UDP")
        print("7 - ICMP Echo Request")
        print("8 - ICMP Timestamp Request")
        print("9 - ICMP Address Mask Request")
        print("10 - Traçar rota dos pacotes \n")

        opcao_descoberta = input("\nEscolha uma opção de descoberta de hosts: ")
        
        if opcao_descoberta == "1":
            comando = f"nmap -sL {alvo}"
        elif opcao_descoberta == "2":
            comando = f"nmap -sn {alvo}"
        elif opcao_descoberta == "3":
            comando = f"nmap -Pn {alvo}"
        elif opcao_descoberta == "4":
            portas = input("Digite as portas específicas para a descoberta (ex: 22,80): ")
            comando = f"nmap -PS{portas} {alvo}"
        elif opcao_descoberta == "5":
            portas = input("Digite as portas específicas para a descoberta (ex: 22,80): ")
            comando = f"nmap -PA{portas} {alvo}"
        elif opcao_descoberta == "6":
            portas = input("Digite as portas específicas para a descoberta (ex: 53,67): ")
            comando = f"nmap -PU{portas} {alvo}"
        elif opcao_descoberta == "7":
            comando = f"nmap -PE {alvo}"
        elif opcao_descoberta == "8":
            comando = f"nmap -PP {alvo}"
        elif opcao_descoberta == "9":
            comando = f"nmap -PM {alvo}"
        elif opcao_descoberta == "10":
            comando = f"nmap --traceroute {alvo}"
        else:
            print("Opção inválida.")
            comando = None
        
        if comando:
            print(f"\nExecutando comando: {comando}")

        
        input("Aperte enter para voltar:")
        os.system("clear")
        main()

    elif opcao_nmap == 3:
        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")
        
        # Menu de tipos de escaneamento com descrições simples

        print("\nEscolha o tipo de escaneamento: \n")
        print("1 - SYN Scan (-sS)          (Varredura rápida e silenciosa, requer root)")
        print("2 - TCP Connect Scan (-sT)  (Completa a conexão TCP, não requer root)")
        print("3 - ACK Scan (-sA)          (Verifica se portas estão filtradas)")
        print("4 - Window Scan (-sW)       (Similar ao ACK Scan, mas verifica o tamanho da janela)")
        print("5 - Maimon Scan (-sM)       (Usa flags FIN/ACK para detectar portas abertas)")
        print("6 - UDP Scan (-sU)          (Varredura de portas UDP, mais lenta)")
        print("7 - NULL Scan (-sN)         (Sem flags TCP, útil para evitar firewalls)")
        print("8 - FIN Scan (-sF)          (Usa pacotes FIN, pode evitar algumas proteções)")
        print("9 - Xmas Scan (-sX)         (Pacotes com múltiplos flags, tenta evadir firewalls)\n")
        
        opcao_escaneamento = input("Escolha uma opção de escaneamento: ")

        os.system("clear")

        # Montagem do comando com base na escolha

        if opcao_escaneamento == "1":
            comando = f"nmap -sS {alvo}"
        elif opcao_escaneamento == "2":
            comando = f"nmap -sT {alvo}"
        elif opcao_escaneamento == "3":
            comando = f"nmap -sA {alvo}"
        elif opcao_escaneamento == "4":
            comando = f"nmap -sW {alvo}"
        elif opcao_escaneamento == "5":
            comando = f"nmap -sM {alvo}"
        elif opcao_escaneamento == "6":
            comando = f"nmap -sU {alvo}"
        elif opcao_escaneamento == "7":
            comando = f"nmap -sN {alvo}"
        elif opcao_escaneamento == "8":
            comando = f"nmap -sF {alvo}"
        elif opcao_escaneamento == "9":
            comando = f"nmap -sX {alvo}"
        else:
            print("Opção inválida.")
            comando = None
        
        # Executa o comando, se válido

        if comando:
            print(f"\nExecutando comando: {comando}")
            os.system(comando)
        
        input("Aperte enter para voltar:")
        os.system("clear")
        main()
          
    elif opcao_nmap == 4:
        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")
        
        # Menu para especificação de portas

        print("\nEscolha uma opção para especificação de portas: \n")
        print("1 - Escanear portas específicas (-p)")
        print("2 - Excluir portas do escaneamento (--exclude-ports)")
        print("3 - Escaneamento rápido (-F)")
        print("4 - Escanear todas as portas (-p-)")
        print("5 - Escanear portas sequencialmente (-r)")
        print("6 - Escanear as portas mais comuns (--top-ports)")
        print("7 - Escanear portas com base em proporção (--port-ratio)\n")
        
        opcao_portas = input("Escolha uma opção de escaneamento de portas:")

        # Montagem do comando com base na escolha do usuário

        if opcao_portas == "1":
            portas = input("Digite as portas (ex: 22,80,443 ou 1-1000): ")
            comando = f"nmap -p {portas} {alvo}"
        elif opcao_portas == "2":
            portas = input("Digite as portas a serem excluídas (ex: 22,80): ")
            comando = f"nmap --exclude-ports {portas} {alvo}"
        elif opcao_portas == "3":
            comando = f"nmap -F {alvo}"
        elif opcao_portas == "4":
            comando = f"nmap -p- {alvo}"
        elif opcao_portas == "5":
            portas = input("Digite as portas (ex: 1-1000): ")
            comando = f"nmap -p {portas} -r {alvo}"
        elif opcao_portas == "6":
            top_n = input("Digite o número de portas mais comuns (ex: 100): ")
            comando = f"nmap --top-ports {top_n} {alvo}"
        elif opcao_portas == "7":
            proporcao = input("Digite a proporção de portas (ex: 0.01): ")
            comando = f"nmap --port-ratio {proporcao} {alvo}"
        else:
            print("Opção inválida.")
            comando = None

        # Executa o comando, se válido
        if comando:
            print(f"\nExecutando comando: {comando}")
            os.system(comando)

        input("Aperte enter para voltar:")
        os.system("clear")
        main()

    elif opcao_nmap == 5:
        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")

        # Menu de opções para Detecção de Serviço e Versão

        print("\nEscolha uma opção de detecção de serviço e versão:\n")
        print("1 - Detecção de Serviço e Versão (-sV)")
        print("2 - Definir intensidade de detecção (--version-intensity)")
        print("3 - Detecção Leve de Versão (--version-light)")
        print("4 - Detecção Completa de Versão (--version-all)")
        print("5 - Rastreamento Detalhado da Detecção (--version-trace)\n")

        opcao_versao = input("Escolha uma opção: ")

        # Montagem do comando com base na escolha do usuário
        if opcao_versao == "1":
            comando = f"nmap -sV {alvo}"
        elif opcao_versao == "2":
            intensidade = input("Digite a intensidade (0-9): ")
            comando = f"nmap -sV --version-intensity {intensidade} {alvo}"
        elif opcao_versao == "3":
            comando = f"nmap -sV --version-light {alvo}"
        elif opcao_versao == "4":
            comando = f"nmap -sV --version-all {alvo}"
        elif opcao_versao == "5":
            comando = f"nmap -sV --version-trace {alvo}"
        else:
            print("Opção inválida.")
            comando = None

        # Executa o comando, se válido
        if comando:
            print(f"\nExecutando comando: {comando}")
            os.system(comando)
        
        input("Aperte enter para voltar:")
        os.system("clear")
        main()

    elif opcao_nmap == 6:
        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")

        # Menu de opções para Varredura de Scripts (NSE)
        print("\nEscolha o tipo de varredura de scripts (NSE):")
        print("1 - Executar scripts padrão (-sC)")
        print("2 - Executar scripts específicos (--script)")
        print("3 - Executar scripts de uma categoria (--script <categoria>)")
        print("4 - Listar scripts disponíveis (--script-help)")
        print("5 - Combinar múltiplos scripts (--script <script1,script2>)\n")

        opcao_script = input("\nEscolha uma opção: ")

        # Montagem do comando com base na escolha do usuário
        if opcao_script == "1":
            # Executar scripts padrão (-sC)
            comando = f"nmap -sC {alvo}"
        
        elif opcao_script == "2":
            # Executar scripts específicos
            script_especifico = input("Digite o nome do script ou scripts (ex: http-vuln*,ftp-*): ")
            comando = f"nmap --script {script_especifico} {alvo}"
        
        elif opcao_script == "3":
            # Executar scripts de uma categoria
            categoria = input("Digite a categoria de scripts (ex: vuln, auth, discovery, exploit): ")
            comando = f"nmap --script {categoria} {alvo}"

        elif opcao_script == "4":
            # Listar scripts disponíveis
            script_info = input("Digite o nome do script para ajuda ou deixe em branco para listar todos: ")
            if script_info:
                comando = f"nmap --script-help {script_info}"
            else:
                comando = f"nmap --script-help"

        elif opcao_script == "5":
            # Combinar múltiplos scripts
            scripts = input("Digite os scripts separados por vírgula (ex: http-vuln*,ssl-*): ")
            comando = f"nmap --script {scripts} {alvo}"
        
        else:
            print("Opção inválida.")
            comando = None

        # Executa o comando, se válido
        if comando:
            print(f"\nExecutando comando: {comando}")
            os.system(comando)

        input("Aperte enter para voltar:")
        os.system("clear")
        main()
    
    elif opcao_nmap == 7:
        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")

        # Menu de opções para Detecção de Sistema Operacional
        print("\nEscolha o tipo de detecção de sistema operacional:\n")
        print("1 - Detecção de Sistema Operacional (-O)")
        print("2 - Detecção Agressiva de Sistema Operacional (-O --osscan-guess)")
        print("3 - Combinar com Detecção de Versão e Serviços (-A)\n")

        opcao_os = input("\nEscolha uma opção: ")

        # Montagem do comando com base na escolha do usuário
        if opcao_os == "1":
            # Detecção de Sistema Operacional (-O)
            comando = f"nmap -O {alvo}"
        
        elif opcao_os == "2":
            # Detecção Agressiva de Sistema Operacional (-O --osscan-guess)
            comando = f"nmap -O --osscan-guess {alvo}"
        
        elif opcao_os == "3":
            # Combinar Detecção de Sistema Operacional com Versão e Serviços (-A)
            comando = f"nmap -A {alvo}"
        
        else:
            print("Opção inválida.")
            comando = None

        # Executa o comando, se válido
        if comando:
            print(f"\nExecutando comando: {comando}")
            os.system(comando)

        input("Aperte enter para voltar:")
        os.system("clear")
        main()

    elif opcao_nmap == 8:

        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")

        # Menu de opções para ajustar temporização e desempenho
        print("\nEscolha uma opção de ajuste de temporização e desempenho:")
        print("\n1 - Ajuste de Temporização (-T0 a -T5)")
        print("2 - Limitar a taxa de pacotes por segundo (--max-rate)")
        print("3 - Limitar a quantidade de hosts escaneados simultaneamente (--max-hostgroup)")
        print("4 - Limitar número de tentativas de retransmissão (--max-retries)")
        print("5 - Definir tempo limite por host (--host-timeout)\n")

        opcao_temporizacao = input("\nEscolha uma opção: ")

        # Montagem do comando com base na escolha do usuário
        if opcao_temporizacao == "1":
            # Ajuste de Temporização (-T0 a -T5)
            tempo = input("Escolha o nível de temporização (0 a 5, ex: T4): ")
            comando = f"nmap -{tempo} {alvo}"
        
        elif opcao_temporizacao == "2":
            # Limitar a taxa de pacotes por segundo (--max-rate)
            rate = input("Digite a taxa máxima de pacotes por segundo (ex: 100): ")
            comando = f"nmap --max-rate {rate} {alvo}"
        
        elif opcao_temporizacao == "3":
            # Limitar a quantidade de hosts escaneados simultaneamente (--max-hostgroup)
            max_hostgroup = input("Digite o tamanho máximo do grupo de hosts (ex: 16): ")
            comando = f"nmap --max-hostgroup {max_hostgroup} {alvo}"
        
        elif opcao_temporizacao == "4":
            # Limitar número de tentativas de retransmissão (--max-retries)
            retries = input("Digite o número máximo de tentativas de retransmissão (ex: 2): ")
            comando = f"nmap --max-retries {retries} {alvo}"
        
        elif opcao_temporizacao == "5":
            # Definir tempo limite por host (--host-timeout)
            timeout = input("Digite o tempo limite por host (ex: 60s, 1m): ")
            comando = f"nmap --host-timeout {timeout} {alvo}"
        
        else:
            print("Opção inválida.")
            comando = None

        # Executa o comando, se válido
        if comando:
            print(f"\nExecutando comando: {comando}")
            os.system(comando)

        input("Aperte enter para voltar:")
        os.system("clear")
        main()

    elif opcao_nmap == 9:
        print("Comando")
    
    elif opcao_nmap == 10:
        print("Comando")
    
    elif opcao_nmap == 11:
        print("Comando")

#-----------------------------------------------------------------------------------#

def menu_principal():
    print("1 - Nmap")

def escolher_opcao():
    opcao_escolhida = int(input("\n 𝙴𝚂𝙲𝙾𝙻𝙷𝙰 𝙰 𝙿𝙸́𝚁𝚄𝙻𝙰 𝚀𝚄𝙴 𝚅𝙾𝙲𝙴̂ 𝚀𝚄𝙴𝚁 𝚃𝙾𝙼𝙰𝚁:"))

    if opcao_escolhida == 1:
        menu_nmap()
        escolher_categoria_nmap()

def main():
    titulo()
    menu_principal()
    escolher_opcao()

if __name__ == '__main__':
    main()