import os
import hashlib
import requests
import re

# Dicionário de Cores ANSI para o terminal
VERMELHO = '\033[91m'
VERDE = '\033[92m'
AMARELO = '\033[93m'
AZUL = '\033[94m'
RESET = '\033[0m'

MAGIC_BYTES = {
    # Imagens
    b'\xFF\xD8\xFF': 'JPEG',
    b'\x89PNG\r\n\x1A\n': 'PNG',
    b'GIF87a': 'GIF',
    b'GIF89a': 'GIF',
    b'BM': 'BMP',
    b'\x00\x00\x01\x00': 'ICO',

    # Documentos
    b'%PDF-': 'PDF',
    b'\xD0\xCF\x11\xE0': 'DOC/XLS (Antigo formato MS Office)',
    b'PK\x03\x04': 'ZIP / DOCX / XLSX / JAR / APK / ODT',

    # Compactação
    b'Rar!\x1A\x07\x00': 'RAR',
    b'\x1F\x8B': 'GZIP',
    b'7z\xBC\xAF\x27\x1C': '7-Zip',

    # Executáveis
    b'MZ': 'Executável Windows (PE)',
    b'\x7FELF': 'Executável Linux (ELF)',
    b'\xCA\xFE\xBA\xBE': 'Java Class',
    
    # Banco de dados
    b'SQLite format 3\x00': 'SQLite',

    # Áudio / Vídeo
    b'ID3': 'MP3 (com ID3)',
    b'\xFF\xFB': 'MP3',
    b'fLaC': 'FLAC',
    b'OggS': 'OGG',
    b'\x00\x00\x00\x18ftyp': 'MP4',
    b'RIFF': 'AVI / WAV',
}

def identificar_tipo(caminho):
    """Lê os primeiros bytes do arquivo para identificar sua assinatura e retorna (Tipo, Hex)."""
    try:
        with open(caminho, 'rb') as f:
            header = f.read(8)
            for magic, tipo in MAGIC_BYTES.items():
                if header.startswith(magic):
                    # Formata os bytes encontrados para hexadecimal legível (ex: FF D8 FF)
                    hex_sig = ' '.join([f'{b:02X}' for b in magic])
                    return tipo, hex_sig
            
            # Se não encontrou no dicionário, retorna os primeiros 4 bytes reais do arquivo como referência
            hex_desconhecido = ' '.join([f'{b:02X}' for b in header[:4]]) if header else "Vazio"
            return "Desconhecido ou Texto Plano", hex_desconhecido
    except Exception as e:
        return f"Erro ao ler arquivo: {e}", None

def analisar_heuristica(caminho):
    # Regex aprimorado para reduzir falsos positivos devido à entropia de binários
    padroes_suspeitos = {
        # Exige um espaço/quebra de linha após <?php, ou exige que <?= seja seguido por $, _ ou uma letra
        'Tags PHP embutidas': rb'<\?php\s|<\?=\s*[$_a-zA-Z]',
        # Exige que haja algum conteúdo (não apenas parênteses vazios) logo após a chamada da função
        'Execução dinâmica (eval)': rb'eval\s*\([^)]',
        'Execução de comandos no SO': rb'(system|shell_exec|exec|passthru)\s*\([^)]',
        'Decodificação suspeita': rb'base64_decode\s*\([^)]'
    }
    
    alertas = []
    try:
        with open(caminho, 'rb') as f:
            conteudo = f.read()
            
            for nome_alerta, padrao in padroes_suspeitos.items():
                # A flag re.IGNORECASE garante que peguemos ofuscações como 'SyStEm('
                if re.search(padrao, conteudo, re.IGNORECASE):
                    alertas.append(nome_alerta)
                    
        return alertas
    except Exception as e:
        print(f"{VERMELHO}[!] Erro na análise heurística: {e}{RESET}")
        return []

def calcular_sha256(caminho):
    sha256 = hashlib.sha256()
    try:
        with open(caminho, "rb") as f:
            for bloco in iter(lambda: f.read(4096), b""):
                sha256.update(bloco)
        return sha256.hexdigest()
    except Exception as e:
        print(f"{VERMELHO}[!] Erro ao calcular hash: {e}{RESET}")
        return None

def consultar_virustotal(hash_arquivo, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_arquivo}"
    headers = {"x-apikey": api_key}
    
    try:
        print(f"\n{AZUL}[*] Consultando VirusTotal para o hash: {hash_arquivo}...{RESET}")
        resposta = requests.get(url, headers=headers)
        
        if resposta.status_code == 200:
            dados = resposta.json()
            stats = dados['data']['attributes']['last_analysis_stats']
            maliciosos = stats['malicious']
            suspeitos = stats['suspicious']
            
            if maliciosos > 0 or suspeitos > 0:
                print(f"{VERMELHO}[!] ALERTA VIRUSTOTAL: Detectado como malicioso por {maliciosos} motores e suspeito por {suspeitos}.{RESET}")
            else:
                print(f"{VERDE}[+] VirusTotal: 0 motores detectaram ameaças neste hash.{RESET}")
        elif resposta.status_code == 404:
            print(f"{AMARELO}[?] VirusTotal: O hash não foi encontrado na base.{RESET}")
        elif resposta.status_code == 401:
            print(f"{VERMELHO}[!] Erro de Autenticação: Verifique se sua API Key é válida.{RESET}")
        else:
            print(f"{VERMELHO}[!] Erro na API. Código de status: {resposta.status_code}{RESET}")
    except requests.exceptions.RequestException as e:
        print(f"{VERMELHO}[!] Erro de conexão com a API: {e}{RESET}")

def principal():
    if os.name == 'nt':
        os.system('color')

    print(f"{AZUL}="*55)
    print("       FILE ANALYSER v1.0       ")
    print("       Analisador heurístico de arquivos       ")
    print("="*55 + f"{RESET}\n")
    
    caminho = input(f"{AMARELO}1. Digite o caminho completo do arquivo para análise:{RESET} ").strip()
    
    if not os.path.isfile(caminho):
        print(f"{VERMELHO}[!] Arquivo não encontrado.{RESET}")
        return

    # Passo 2: Magic Bytes e Extensão
    print(f"\n{AZUL}[*] Analisando estrutura do arquivo (Magic Bytes)...{RESET}")
    tipo_arquivo, assinatura_hex = identificar_tipo(caminho)
    
    # Extrai a extensão do arquivo fornecido pelo usuário
    nome_arquivo, extensao = os.path.splitext(caminho)
    extensao_display = extensao if extensao else "Nenhuma extensão"
    
    print(f"{VERDE}[+] Extensão original do arquivo: {extensao_display}{RESET}")
    print(f"{VERDE}[+] Formato identificado: {tipo_arquivo}{RESET}")
    if assinatura_hex:
        print(f"{VERDE}[+] Assinatura Hexadecimal (Magic Bytes): {assinatura_hex}{RESET}")
    
    # Passo 3: Análise Heurística
    print(f"\n{AZUL}[*] Realizando varredura heurística por padrões suspeitos...{RESET}")
    alertas_heuristica = analisar_heuristica(caminho)
    
    if alertas_heuristica:
        print(f"{VERMELHO}[!] ALERTA HEURÍSTICO: Possível código malicioso encontrado!{RESET}")
        for alerta in alertas_heuristica:
            print(f"    - {VERMELHO}{alerta}{RESET}")
    else:
        print(f"{VERDE}[+] Heurística: Nenhum padrão malicioso óbvio detectado no conteúdo.{RESET}")
    
    # Passo 4: Consulta VirusTotal
    opcao_vt = input(f"\n{AMARELO}Deseja consultar o hash deste arquivo no VirusTotal? (S/N):{RESET} ").strip().upper()
    
    if opcao_vt == 'S':
        api_key = input(f"{AMARELO}Insira sua API Key do VirusTotal:{RESET} ").strip()
        if api_key:
            hash_arquivo = calcular_sha256(caminho)
            if hash_arquivo:
                consultar_virustotal(hash_arquivo, api_key)
        else:
            print(f"{VERMELHO}[!] API Key não fornecida.{RESET}")
    else:
        print(f"{AZUL}[*] Consulta ao VirusTotal ignorada.{RESET}")
        
    print(f"\n{AZUL}[*] Análise finalizada.{RESET}")

if __name__ == "__main__":
    principal()
