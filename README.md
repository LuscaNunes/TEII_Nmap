# pyscan — Clone Simplificado do Nmap

**Disciplina:** Tópicos Especiais II
**Trabalho:** A2 — NMAP - Desenvolvimento

Scanner de portas TCP e UDP desenvolvido em Python, utilizando técnicas básicas de
varredura (SYN scan para TCP e sondagem para UDP), inspirado no funcionamento do Nmap.

---

## Índice

- [O que a ferramenta faz](#o-que-a-ferramenta-faz)
- [Como funciona (técnicas utilizadas)](#como-funciona-técnicas-utilizadas)
- [Requisitos](#requisitos)
- [Instalação — Passo a Passo](#instalação--passo-a-passo)
- [Como descobrir o IP para escanear](#como-descobrir-o-ip-para-escanear)
- [Como usar](#como-usar)
- [Exemplos práticos](#exemplos-práticos)
- [Parâmetros disponíveis](#parâmetros-disponíveis)
- [Interpretando os resultados](#interpretando-os-resultados)
- [Rodando em VirtualBox (Kali Live)](#rodando-em-virtualbox-kali-live)
- [Limitações conhecidas](#limitações-conhecidas)
- [Aviso legal / uso responsável](#aviso-legal--uso-responsável)

---

## O que a ferramenta faz

- Varre portas **TCP** e **UDP** em um ou mais endereços IP.
- Classifica cada porta como **aberta**, **fechada** ou **filtrada**.
- Suporta varredura de um único IP, lista de IPs, ou uma rede inteira (notação CIDR).
- Usa múltiplas threads para acelerar a varredura de várias portas ao mesmo tempo.

---

## Como funciona (técnicas utilizadas)

### TCP SYN Scan (half-open scan)

Envia um pacote TCP com a flag **SYN** para a porta alvo e analisa a resposta:

| Resposta recebida | Estado da porta |
|---|---|
| SYN/ACK | **open** (aberta) — a ferramenta envia um RST em seguida para não completar o handshake |
| RST | **closed** (fechada) |
| Nenhuma resposta | **filtered** (provavelmente bloqueada por firewall) |
| ICMP "destination unreachable" | **filtered** |

### UDP Scan

Envia um datagrama UDP vazio para a porta alvo:

| Resposta recebida | Estado da porta |
|---|---|
| Resposta UDP qualquer | **open** (aberta) |
| ICMP "port unreachable" (tipo 3, código 3) | **closed** (fechada) |
| Nenhuma resposta | **open\|filtered** (ambíguo — comportamento padrão do protocolo UDP) |

> **Por que UDP dá tanto resultado ambíguo?** O UDP não tem handshake nem confirmação
> de entrega. A única forma de identificar uma porta fechada é receber um ICMP de erro —
> e muitos firewalls/roteadores não enviam esse ICMP ou limitam a taxa de envio dele
> (rate limiting), fazendo a porta parecer "aberta ou filtrada" mesmo estando só filtrada.
> Esse é um comportamento esperado e documentado — o próprio Nmap real tem essa mesma limitação.

---

## Requisitos

- **Sistema operacional:** Linux (obrigatório — usa raw sockets)
- **Python:** 3.8 ou superior
- **Biblioteca:** [Scapy](https://scapy.net/)
- **Privilégios:** root/sudo (necessário para montar pacotes TCP/UDP/ICMP crus)

---

## Instalação — Passo a Passo

### 1. Clonar o repositório

```bash
git clone <URL_DO_SEU_REPOSITORIO>
cd <nome-da-pasta>
```

### 2. Verificar se o Python 3 está instalado

```bash
python3 --version
```

Se não tiver Python 3 instalado (raro em distros como Kali/Ubuntu):

```bash
sudo apt update
sudo apt install python3 -y
```

### 3. Instalar o Scapy

No **Kali Linux** (geralmente já vem instalado):

```bash
python3 -c "import scapy; print('Scapy OK')"
```

Se der erro, instale com:

```bash
sudo apt update
sudo apt install python3-scapy -y
```

Em outras distros (Ubuntu/Debian genérico), se o pacote acima não existir, use pip:

```bash
pip install scapy --break-system-packages
```

---

## Como descobrir o IP para escanear

### Descobrir o IP da sua própria máquina

```bash
ip a
```

Procure a interface de rede ativa (geralmente `eth0` ou `wlan0`) e veja a linha `inet`,
por exemplo: `inet 192.168.100.151/24`.

### Descobrir o IP do roteador (gateway)

```bash
ip route
```

A linha `default via X.X.X.X` mostra o IP do roteador — é um ótimo alvo de teste porque
normalmente tem portas 80/443 abertas (painel de administração).

### Descobrir outros dispositivos na rede

Uma forma simples é instalar o `arp-scan`:

```bash
sudo apt install arp-scan -y
sudo arp-scan --localnet
```

Isso lista todos os dispositivos ativos na sua rede local com seus respectivos IPs.

---

## Como usar

Sintaxe básica:

```bash
sudo python3 pyscan.py -t <ALVO> -p <PORTAS> [--tcp] [--udp]
```

> **Sempre use `sudo`** — o script precisa de privilégios de root para criar pacotes raw.

---

## Exemplos práticos

**Varredura TCP simples em um host, portas 1 a 1000:**
```bash
sudo python3 pyscan.py -t 192.168.100.1 -p 1-1000 --tcp
```

**TCP + UDP, portas específicas:**
```bash
sudo python3 pyscan.py -t 192.168.100.1 -p 22,80,443 --tcp --udp
```

**Múltiplos hosts ao mesmo tempo:**
```bash
sudo python3 pyscan.py -t 192.168.100.1,192.168.100.151 -p 1-100 --tcp
```

**Rede inteira (notação CIDR):**
```bash
sudo python3 pyscan.py -t 192.168.100.0/24 -p 80 --tcp --timeout 0.5
```
> Dica: ao escanear uma rede inteira, reduza o `--timeout` (ex: `0.5`) para os hosts
> inexistentes não travarem a varredura por muito tempo.

**Teste rápido no próprio localhost (sempre funciona, bom para validar a instalação):**
```bash
sudo python3 pyscan.py -t 127.0.0.1 -p 1-100 --tcp
```

---

## Parâmetros disponíveis

| Flag | Descrição | Padrão |
|---|---|---|
| `-t / --targets` | IP, lista de IPs (separados por vírgula) ou rede em CIDR | *obrigatório* |
| `-p / --ports` | Porta única, lista (`22,80,443`), ou faixa (`1-1000`) | `1-1024` |
| `--tcp` | Ativa a varredura TCP (SYN scan) | desativado |
| `--udp` | Ativa a varredura UDP | desativado |
| `--threads` | Número de threads simultâneas por protocolo | `50` |
| `--timeout` | Tempo de espera por resposta, em segundos | `1.5` |

> É necessário informar pelo menos um dos dois: `--tcp` ou `--udp` (ou ambos).

---

## Interpretando os resultados

Exemplo de saída real (varredura contra um roteador doméstico):

```
== Resultado da varredura para 192.168.100.1 ==

PROTOCOLO: TCP
PORTA     ESTADO
-------------------------
21        filtered
22        filtered
23        filtered
80        open
443       open

Resumo TCP: 2 aberta(s), 995 fechada(s), 3 filtrada(s)/ambígua(s)
```

Nesse exemplo: as portas 80 e 443 abertas indicam o painel web de administração do
roteador; as portas 21 (FTP), 22 (SSH) e 23 (Telnet) aparecem filtradas porque o
firmware do roteador bloqueia proativamente esses serviços de acesso remoto por
segurança — comportamento típico de equipamentos domésticos.

---

## Rodando em VirtualBox (Kali Live)

Caso você use o Kali em modo **Live** dentro do VirtualBox (sem instalação em disco),
siga este roteiro extra:

### 1. Configurar pasta compartilhada (para não perder o arquivo ao reiniciar)

No VirtualBox: **Dispositivos → Pastas Compartilhadas → Configurações**, adicione a
pasta do projeto no seu PC host, marcando **Montagem Automática** e
**Make Machine Permanent**.

Instale o Guest Additions no Kali (perde-se ao reiniciar em modo live, reinstale se
necessário):
```bash
sudo apt install virtualbox-guest-utils -y
```

A pasta aparecerá em `/media/sf_<nome-da-pasta>`. Rode o script direto de lá, sem
precisar copiar para a home (assim nunca se perde ao reiniciar):
```bash
cd /media/sf_<nome-da-pasta>
sudo python3 pyscan.py -t 127.0.0.1 -p 1-100 --tcp
```

### 2. Configurar a rede como "Bridge" (para escanear a rede real)

Por padrão o VirtualBox usa **NAT**, que isola a VM da sua rede local. Para escanear
outros dispositivos da sua rede (ex: o roteador de casa), troque para modo **Bridge**:

1. Desligue a VM completamente.
2. **Configurações → Rede → Adaptador 1 → Ligado a:** `Placa em modo Bridge`.
3. No campo **Nome**, escolha o adaptador de rede que está **realmente conectado à
   internet** no seu PC (Wi-Fi ou Ethernet — se usar Wi-Fi, funciona na maioria dos
   casos, mas alguns chips Wi-Fi têm limitações em modo bridge).
4. Ligue a VM e confirme o IP recebido:
```bash
ip a
```
Se a interface `eth0` mostrar um IP no formato `192.168.x.x` (igual aos outros
dispositivos da sua rede), a configuração deu certo.

---

## Limitações conhecidas

- Não realiza detecção de sistema operacional nem de versão de serviço (recursos
  avançados do Nmap real, fora do escopo deste trabalho).
- A varredura UDP sofre da ambiguidade inerente ao protocolo — muitos resultados
  aparecem como `open|filtered` por causa do rate-limiting de ICMP em firewalls.
- Testado apenas em Linux (Kali). Windows e macOS não são suportados nesta versão.
- Não realiza descoberta de hosts automaticamente (não escaneia sozinho quais IPs
  estão ativos — recomenda-se usar `arp-scan` ou `ping` antes para identificar alvos).

---

## Aviso legal / uso responsável

Esta ferramenta foi desenvolvida **exclusivamente para fins educacionais**, como parte
de uma atividade acadêmica. Utilize-a **apenas** em:

- Máquinas e redes de sua propriedade;
- Ambientes de laboratório/VMs próprias;
- Redes com autorização explícita para testes de segurança.

Escanear redes ou dispositivos de terceiros sem autorização pode configurar crime,
conforme a legislação vigente. O autor não se responsabiliza pelo uso indevido desta
ferramenta.

---

## Estrutura do código

| Função | Responsabilidade |
|---|---|
| `parse_targets()` | Converte a entrada de alvos (IP único, lista ou CIDR) em uma lista de IPs |
| `parse_ports()` | Converte a entrada de portas (única, lista ou faixa) em uma lista de inteiros |
| `tcp_syn_scan()` | Executa o SYN scan em uma única porta TCP |
| `udp_scan()` | Executa a sondagem UDP em uma única porta |
| `scan_target()` | Orquestra a varredura de múltiplas portas usando threads |
| `print_results()` | Formata e exibe os resultados no terminal |
| `main()` | Interpreta os argumentos da linha de comando e inicia a execução |

---

## Autor

Desenvolvido por **(seu nome aqui)** — Tópicos Especiais II, 2026.
