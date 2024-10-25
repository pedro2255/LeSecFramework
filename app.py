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
░░░▌▌░▒░░▐▀▄▌▌▐▐▒▒▒▒▐▐▐▒▐▒▌▌░▐▒▌▄▐  
░▄▀▄▐▒▒▒░▌▌▄▀▄▐░▌▌▒▐░▌▄▀▄░▐▒░▐▒▌░▀▄
▀▄▀▒▒▌▒▒▄▀░▌█▐░░▐▐▀░░░▌█▐░▀▄▐▒▌▌░░░▀
░▀▀▄▄▐▒▀▄▀░▀▄▀░░░░░░░░▀▄▀▄▀▒▌░▐
░░░░▀▐▀▄▒▀▄░░░░░░░░▐░░░░░░▀▌▐            
░░░░░░▌▒▌▐▒▀░░░░░░░░░░░░░░▐▒▐     
░░░░░░▐░▐▒▌░░░░▄▄▀▀▀▀▄░░░░▌▒▐   - - "Olá eu sou sua assistente virtual, me chamo Ordália"
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
        os.system("clear")

        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")

        # Menu de opções para Varredura de Scripts (NSE)
        print("\nEscolha o tipo de varredura de scripts (NSE):\n")
        print("1 - Executar scripts padrão (-sC)")
        print("2 - Executar scripts específicos (--script)")
        print("3 - Executar scripts de uma categoria (--script <categoria>)")
        print("4 - Listar todos os scripts disponíveis")
        print("5 - Combinar múltiplos scripts (--script <script1,script2>)")
        print("6 - Execução massiva de scripts")

        opcao_script = input("\nEscolha uma opção: ")

        # Opções de varredura baseadas na escolha do usuário
        if opcao_script == "1":
            # Executar scripts padrão (-sC)
            comando = f"nmap -sC {alvo}"

        elif opcao_script == "2":
            # Executar scripts específicos (--script)
            script_especifico = input("Digite o nome do script ou scripts (ex: http-vuln*,ftp-*): ")
            comando = f"nmap --script {script_especifico} {alvo}"

        elif opcao_script == "3":
            os.system("clear")
            # Executar scripts de uma categoria (--script <categoria>)
            print("\nCategorias de Scripts Disponíveis:\n")
            print("1 - auth (Autenticação)")
            print("2 - broadcast (Descoberta via Broadcast)")
            print("3 - brute (Força Bruta)")
            print("4 - default (Scripts Padrão)")
            print("5 - discovery (Descoberta)")
            print("6 - dos (Negação de Serviço)")
            print("7 - exploit (Exploração de Vulnerabilidades)")
            print("8 - external (Dependências Externas)")
            print("9 - fuzzer (Fuzzing)")
            print("10 - intrusive (Scripts Invasivos)")
            print("11 - malware (Detecção de Malware)")
            print("12 - safe (Scripts Seguros)")
            print("13 - version (Identificação de Versão)")
            print("14 - vuln (Vulnerabilidades)")

            categoria_opcao = input("Escolha a categoria: ")

            categorias = {
                "1": "auth",
                "2": "broadcast",
                "3": "brute",
                "4": "default",
                "5": "discovery",
                "6": "dos",
                "7": "exploit",
                "8": "external",
                "9": "fuzzer",
                "10": "intrusive",
                "11": "malware",
                "12": "safe",
                "13": "version",
                "14": "vuln"
            }

            if categoria_opcao in categorias:
                categoria = categorias[categoria_opcao]
                comando = f"nmap --script {categoria} {alvo}"
            else:
                print("Categoria inválida.")
                comando = None

        elif opcao_script == "4":
            # Listar todos os scripts disponíveis no diretório padrão do Nmap
            print("\nListando todos os scripts disponíveis no diretório padrão do Nmap...\n")
            os.system("ls /usr/share/nmap/scripts/")
            input("\nAperte enter para voltar.")

        elif opcao_script == "5":
            # Combinar múltiplos scripts (--script <script1,script2>)
            scripts = input("Digite os scripts separados por vírgula (ex: http-vuln*,ssl-*): ")
            comando = f"nmap --script {scripts} {alvo}"

        elif opcao_script == "6":
            # Submenu de execução massiva de scripts
            print("\nEscolha o tipo de execução massiva:\n")
            print("1 - Executar todos os scripts de uma categoria específica")
            print("2 - Executar todos os scripts disponíveis no sistema")

            opcao_massiva = input("Escolha uma opção (1 ou 2): ")

            if opcao_massiva == "1":
                os.system("clear")

                # Executar todos os scripts de uma categoria específica
                print("\nCategorias de Scripts Disponíveis:\n")
                print("1 - auth (Autenticação)")
                print("2 - broadcast (Descoberta via Broadcast)")
                print("3 - brute (Força Bruta)")
                print("4 - default (Scripts Padrão)")
                print("5 - discovery (Descoberta)")
                print("6 - dos (Negação de Serviço)")
                print("7 - exploit (Exploração de Vulnerabilidades)")
                print("8 - external (Dependências Externas)")
                print("9 - fuzzer (Fuzzing)")
                print("10 - intrusive (Scripts Invasivos)")
                print("11 - malware (Detecção de Malware)")
                print("12 - safe (Scripts Seguros)")
                print("13 - version (Identificação de Versão)")
                print("14 - vuln (Vulnerabilidades)")

                categoria_opcao = input("Escolha a categoria: ")

                if categoria_opcao in categorias:
                    categoria = categorias[categoria_opcao]
                    comando = f"nmap --script {categoria} {alvo}"
                else:
                    print("Categoria inválida.")
                    comando = None

            elif opcao_massiva == "2":
                # Executar todos os scripts disponíveis no sistema
                print("\nExecutando todos os scripts disponíveis no sistema!")
                comando = f"nmap --script 'all' {alvo}"

            else:
                print("Opção inválida.")
                comando = None

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
        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")

        # Menu de opções para evasão e falsificação

        print("\nEscolha a técnica de evasão ou falsificação:\n")
        print("1 - Fragmentar pacotes (-f)")
        print("2 - Falsificar MAC de origem (--spoof-mac)")
        print("3 - Adicionar dados randômicos aos pacotes (--data-length)")
        print("4 - Alterar a porta de origem (--source-port)")
        print("5 - Usar pacotes decoy (-D)")
        print("6 - Desabilitar consultas de DNS reverso (--disable-dns)\n")

        opcao_evasao = input("\nEscolha uma opção: ")

        # Montagem do comando com base na escolha do usuário
        if opcao_evasao == "1":
            # Fragmentar pacotes (-f)
            comando = f"nmap -f {alvo}"
        
        elif opcao_evasao == "2":
            # Falsificar MAC de origem (--spoof-mac)
            mac = input("Digite o endereço MAC falso (ex: 00:11:22:33:44:55): ")
            comando = f"nmap --spoof-mac {mac} {alvo}"
        
        elif opcao_evasao == "3":
            # Adicionar dados randômicos aos pacotes (--data-length)
            data_length = input("Digite o comprimento dos dados adicionais (ex: 50): ")
            comando = f"nmap --data-length {data_length} {alvo}"
        
        elif opcao_evasao == "4":
            # Alterar a porta de origem (--source-port)
            porta_origem = input("Digite a porta de origem (ex: 80, 443): ")
            comando = f"nmap --source-port {porta_origem} {alvo}"
        
        elif opcao_evasao == "5":
            # Usar pacotes decoy (-D)
            decoy = input("Digite o número de decoys ou IPs falsos (ex: RND:10 ou 192.168.0.1,192.168.0.2): ")
            comando = f"nmap -D {decoy} {alvo}"
        
        elif opcao_evasao == "6":
            # Desabilitar consultas de DNS reverso (--disable-dns)
            comando = f"nmap --disable-dns {alvo}"
        
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

    elif opcao_nmap == 10:
        alvo = input("Digite o alvo (IP ou rede, ex: 192.168.0.0/24): ")

        # Menu de opções para saída e relatórios
        print("\nEscolha o formato de saída:\n")
        print("1 - Saída em formato normal (-oN)")
        print("2 - Saída em formato XML (-oX)")
        print("3 - Saída em formato grepable (-oG)")
        print("4 - Saída em todos os formatos (-oA)")
        print("5 - Anexar à saída existente (--append-output)")

        opcao_saida = input("\nEscolha uma opção: ")

        if opcao_saida == "1":
            # Saída em formato normal (-oN)
            arquivo = input("Digite o nome do arquivo de saída (ex: resultado.txt): ")
            comando = f"nmap -oN {arquivo} {alvo}"
        
        elif opcao_saida == "2":
            # Saída em formato XML (-oX)
            arquivo = input("Digite o nome do arquivo de saída (ex: resultado.xml): ")
            comando = f"nmap -oX {arquivo} {alvo}"
        
        elif opcao_saida == "3":
            # Saída em formato grepable (-oG)
            arquivo = input("Digite o nome do arquivo de saída (ex: resultado.grep): ")
            comando = f"nmap -oG {arquivo} {alvo}"
        
        elif opcao_saida == "4":
            # Saída em todos os formatos (-oA)
            arquivo = input("Digite o nome base do arquivo de saída (ex: resultado): ")
            comando = f"nmap -oA {arquivo} {alvo}"
        
        elif opcao_saida == "5":
            # Anexar à saída existente (--append-output)
            arquivo = input("Digite o nome do arquivo de saída existente (ex: resultado.txt): ")
            comando = f"nmap --append-output -oN {arquivo} {alvo}"
        
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

    elif opcao_nmap == 11:
        main()

#-----------------------------------------------------------------------------------#

def dados_dev():
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'  # Resetar para a cor padrão

    print(f"{CYAN}Desenvolvedor: Pedro Ramos{RESET}")
    print(f"{BLUE}Linkedin: https://www.linkedin.com/in/pedro-ramos-02a905193/{RESET}")
    print(f"{MAGENTA}Instagram: pedroti255{RESET}")
    print(f"{GREEN}Github: pedro2255{RESET}\n")


def menu_principal():
    print("1 - Nmap")
    print("2 - Hydra (em desenvolvimento)")

def escolher_opcao():
    opcao_escolhida = int(input("\n 𝙴𝚂𝙲𝙾𝙻𝙷𝙰 𝙰 𝙿𝙸́𝚁𝚄𝙻𝙰 𝚀𝚄𝙴 𝚅𝙾𝙲𝙴̂ 𝚀𝚄𝙴𝚁 𝚃𝙾𝙼𝙰𝚁:"))

    if opcao_escolhida == 1:
        menu_nmap()
        escolher_categoria_nmap()

    if opcao_escolhida == 2:
        menu_sqlmap()
        escolher_categoria_sqlmap()
        

def main():
    os.system("clear")
    titulo()
    dados_dev()
    menu_principal()
    escolher_opcao()

if __name__ == '__main__':
    main()