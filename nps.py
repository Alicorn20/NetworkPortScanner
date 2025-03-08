import socket
import asyncio
import sys
import time
import os
import psutil

# Costanti
MIN_PORT = 1
MAX_PORT = 65535
BASE_TIMEOUT = 0.5  # Timeout di base per le connessioni
MAX_THREADS = 1000  # Numero massimo di thread
SCAN_FOLDER = "scan_results"  # Cartella per salvare i risultati

# Contatore globale per il numero di scansione
scan_counter = 0

def resolve_ip(domain):
    """Risolve un dominio in un indirizzo IP."""
    try:
        return socket.gethostbyname(domain)
    except socket.error as e:
        print(f"Errore durante la risoluzione del dominio: {e}")
        return None

async def scan_tcp_port(ip, port, timeout):
    """Scansiona una singola porta TCP in modo asincrono."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port, "TCP", True  # Porta aperta
    except (asyncio.TimeoutError, socket.error, ConnectionRefusedError):
        return port, "TCP", False  # Porta chiusa o errore

async def scan_udp_port(ip, port, timeout):
    """Scansiona una singola porta UDP in modo asincrono."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (ip, port))  # Invia un pacchetto vuoto
        sock.recvfrom(1024)  # Prova a ricevere una risposta
        sock.close()
        return port, "UDP", True  # Porta aperta
    except socket.error:
        return port, "UDP", False  # Porta chiusa o errore

def print_progress_bar(iteration, total, length=50):
    """Stampa una barra di caricamento."""
    percent = f"{100 * (iteration / total):.1f}%"
    filled_length = int(length * iteration // total)
    bar = "█" * filled_length + "-" * (length - filled_length)
    sys.stdout.write(f"\rScansione in corso: |{bar}| {percent}")
    sys.stdout.flush()

def save_results(open_ports, elapsed_time, scan_number):
    """Salva i risultati in un file."""
    if not os.path.exists(SCAN_FOLDER):
        os.makedirs(SCAN_FOLDER)
    filename = os.path.join(SCAN_FOLDER, f"scan{scan_number}.txt")
    with open(filename, "w") as file:
        file.write(f"Risultati della scansione #{scan_number}\n")
        file.write(f"Tempo impiegato: {elapsed_time:.2f} secondi\n")
        file.write("Porte aperte:\n")
        for port, protocol, _ in sorted(open_ports, key=lambda x: (x[0], x[1])):
            file.write(f"Porta {port} ({protocol}): APERTA\n")
    print(f"\nRisultati salvati in {filename}")

def get_system_load():
    """Restituisce il carico del sistema (CPU e memoria)."""
    cpu_load = psutil.cpu_percent(interval=0.1)
    mem_load = psutil.virtual_memory().percent
    return cpu_load, mem_load

async def scan_ports(ip, start_port, end_port, scan_number):
    """Scansiona un range di porte TCP e UDP in modo asincrono."""
    open_ports = []
    total_ports = (end_port - start_port + 1) * 2  # TCP + UDP
    print(f"Scansione delle porte {start_port}-{end_port} (TCP e UDP) su {ip}...")

    tasks = []
    for port in range(start_port, end_port + 1):
        # Aggiungi task per TCP e UDP
        tasks.append(scan_tcp_port(ip, port, BASE_TIMEOUT))
        tasks.append(scan_udp_port(ip, port, BASE_TIMEOUT))

    # Esegui i task in batch per bilanciare il carico
    batch_size = MAX_THREADS
    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        results = await asyncio.gather(*batch)

        # Monitora il carico del sistema
        cpu_load, mem_load = get_system_load()
        if cpu_load > 80 or mem_load > 80:
            print("\nCarico del sistema elevato. Riduzione del numero di thread...")
            batch_size = max(batch_size // 2, 100)  # Riduci il batch size

        # Aggiungi i risultati delle porte aperte
        for result in results:
            port, protocol, is_open = result
            if is_open:
                open_ports.append((port, protocol, is_open))
        print_progress_bar(i + len(batch), total_ports)

    print("\nScansione completata!")
    return open_ports

def main():
    global scan_counter
    # Input dell'utente
    target = input("Inserisci l'indirizzo IP o il dominio da scansionare: ")
    start_port = int(input(f"Inserisci la porta di inizio (es. {MIN_PORT}): ") or MIN_PORT)
    end_port = int(input(f"Inserisci la porta di fine (es. {MAX_PORT}): ") or MAX_PORT)

    # Risolvi l'indirizzo IP se è un dominio
    ip = resolve_ip(target)
    if not ip:
        return

    # Esegui la scansione delle porte
    scan_counter += 1
    start_time = time.time()
    open_ports = asyncio.run(scan_ports(ip, start_port, end_port, scan_counter))
    elapsed_time = time.time() - start_time

    # Salva i risultati
    save_results(open_ports, elapsed_time, scan_counter)

    # Stampa i risultati
    if open_ports:
        print("\nPorte aperte trovate:")
        for port, protocol, _ in sorted(open_ports, key=lambda x: (x[0], x[1])):
            print(f"Porta {port} ({protocol}): APERTA")
    else:
        print("\nNessuna porta aperta trovata.")

    print(f"\nTempo impiegato: {elapsed_time:.2f} secondi")

if __name__ == "__main__":
    main()
