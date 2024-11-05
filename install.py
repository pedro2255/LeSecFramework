import os

def dependencias():
    os.system("clear")
    instalar = input("Você deseja instalar as dependências do Framework?(y/n):")
    if instalar == "y":
        os.system("apt update -y")
        os.system("apt install python3 -y")
        os.system("apt install nmap -y")
        os.system("apt install hydra -y")

dependencias()    