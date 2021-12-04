import binascii
import ipaddress
import socket
import struct
import sys
import time
from enum import Enum
import const


class TypSpravy(Enum):
    ack = ord('A')
    nack = ord('N')
    syn = ord('S')
    sprava = ord('P')
    subor = ord('U')
    data = ord('D')
    koniec = ord('K')


buff: int = 1024

# -------------------------------------------------------------------------
# SPOLOCNE


def zabal_hlavicku(typ_spravy, crc: int):
    # return struct.pack('bH', typ_spravy, crc16)
    return struct.pack('bI', typ_spravy, crc)


def rozbal_hlavicku(data):
    return struct.unpack('bI', data)


def zabal_hlavicku_n(typ_spravy, cislo: int, crc: int):
    # return struct.pack('bH', typ_spravy, crc16)
    return struct.pack('bII', typ_spravy, cislo, crc)


def rozbal_hlavicku_n(data):
    return struct.unpack('bII', data)


def ukonci_spojenie(sock, ip, port):
    hlavicka = zabal_hlavicku(TypSpravy.koniec.value, 0)
    sock.sendto(hlavicka, (ip, port))


# -------------------------------------------------------------------------
# KLIENT


def odoslanie_suboru(sock, host, port: int, velkost_fragmentu: int):
    file_name = 'kokociny.txt'
    sock.sendto(file_name.encode(), (host, port))
    print("Sending %s ..." % file_name)

    f = open(file_name, "r")
    data = f.read(buff)
    while data:
        if sock.sendto(data.encode(), (host, port)):
            data = f.read(buff)
            time.sleep(0.02)  # Give receiver a bit time to save

    sock.close()
    f.close()


def odoslanie_spravy(sock, host, port: int, velkost_fragmentu: int):
    print("\nOdosielanie spravy je mozne zrusit prazdnou spravou.")

    # odoslanie informacii serveru, ze budu posielane spravy
    hlavicka = zabal_hlavicku(TypSpravy.sprava.value, 0)
    sock.sendto(hlavicka, (host, port))

    while True:
        sprava = input("Klient (ja): ")

        # ukoncenie odosielania sprav prazdnou spravou, vrati sa do menu v Klient()
        if len(sprava) == 0 or sprava == ' ':
            ukonci_spojenie(sock, host, port)
            print("UKONCUJEM ODOSIELANIE SPRAV")
            return

        potrebne_fragmenty = int(len(sprava) / velkost_fragmentu) + 1

        # odoslanie spravy serveru
        hlavicka = zabal_hlavicku(TypSpravy.data.value, binascii.crc32(sprava.encode()))
        sock.sendto(hlavicka + sprava.encode(), (host, port))

        # prijatie ACK / NACK
        data, addr = sock.recvfrom(buff)
        prijata_hlavicka = rozbal_hlavicku(data[:const.HLAVICKA])
        typ_spravy = prijata_hlavicka[0]

        # posiela spravu kym nedostane ACK
        while typ_spravy == TypSpravy.nack.value:
            print('Sprava nebola uspesne odoslana, posielam znovu')
            sock.sendto(hlavicka + sprava.encode(), (host, port))

            # prijatie ACK / NACK
            data, addr = sock.recvfrom(buff)
            prijata_hlavicka = rozbal_hlavicku(data[:const.HLAVICKA])
            typ_spravy = prijata_hlavicka[0]

        print("sprava bola uspesne dorucena")

        # prijatie odpovede
        data, addr = sock.recvfrom(buff)
        prijata_hlavicka = rozbal_hlavicku(data[:const.HLAVICKA])
        typ_spravy = prijata_hlavicka[0]

        # ukoncenie odosielania sprav zo strany servera
        if typ_spravy == TypSpravy.koniec.value:
            print("SERVER UKONCIL ODOSIELANIE SPRAV")
            return

        print("Server: ", data[const.HLAVICKA:].decode())


# ZDROJ - https://codefather.tech/blog/validate-ip-address-python/
def validuj_ip(address):
    try:
        ipaddress.ip_address(address)
        # print("IP address {} is valid. The object returned is {}".format(address, ip))
        return True
    except ValueError:
        # print("IP address {} is not valid".format(address))
        return False


def klient_nadviaz_spojenie(sock, ip, port):
    # odosle serveru SYN
    hlavicka = zabal_hlavicku(TypSpravy.syn.value, 0)
    sock.sendto(hlavicka, (ip, port))

    # prijatie spravy od servera, osetrenie ineho portu
    try:
        data, addr = sock.recvfrom(buff)
        hlavicka = rozbal_hlavicku(data)
        typ_spravy = hlavicka[0]
    except:
        print('pripojenie sa nepodarilo')
        return False

    # dostane od servera SYN
    if typ_spravy == TypSpravy.syn.value:
        # posle serveru ACK - uspesne pripojenie
        hlavicka = zabal_hlavicku(TypSpravy.ack.value, 0)
        sock.sendto(hlavicka, (ip, port))
        return True

    else:
        print('neprislo mi potvrdenie')
        return False


def klient():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ip = input("Zadajte IP adresu: ")
    while validuj_ip(ip) is False:
        ip = input("Zadajte platnu IP adresu: ")

    port = input("Zadajte port: ")
    while port.isnumeric() is False or int(port) < 10000:
        port = input("Zadajte spravny port: ")
    port = int(port)

    velkost_fragmentu = input("Zadajte velkost fragmentu: ")
    while velkost_fragmentu.isnumeric() is False or int(velkost_fragmentu) <= 0:
        velkost_fragmentu = input("Zadajte platnu velkost: ")
    velkost_fragmentu = int(velkost_fragmentu)

    if klient_nadviaz_spojenie(sock, ip, port) is False:
        print("Nepodarilo sa nadviazat spojenie so serverom")
        return

    while True:
        volba = input("\n1 - Odoslanie spravy \n2 - Odoslanie suboru \n0 - Ukoncenie spojenia \nVolba: ")

        if volba == '1':
            odoslanie_spravy(sock, ip, port, velkost_fragmentu)

        elif volba == '2':
            print("odosielanie suboru")
            odoslanie_suboru(sock, ip, port, velkost_fragmentu)

        elif volba == '0':
            print('UKONCENIE SPOJENIA\n')
            ukonci_spojenie(sock, ip, port)
            return
        else:
            continue

    ukonci_spojenie(sock, ip, port)

    return


# -------------------------------------------------------------------------
# SERVER


def neposkodene_data(data, checksum):
    kontrolny_checksum = binascii.crc32(data[const.HLAVICKA:])

    if kontrolny_checksum == checksum:
        return True

    return False


def neuspesne_prijata(sock, addr):
    hlavicka = zabal_hlavicku(TypSpravy.nack.value, 0)
    sock.sendto(hlavicka, addr)


def uspesne_prijata(sock, addr):
    hlavicka = zabal_hlavicku(TypSpravy.ack.value, 0)
    sock.sendto(hlavicka, addr)


def server_spravy(sock):
    while True:
        data, addr = sock.recvfrom(buff)

        hlavicka = rozbal_hlavicku(data[:const.HLAVICKA])
        typ_spravy = hlavicka[0]
        checksum = hlavicka[1]

        # ukoncenie zo strany klienta
        if typ_spravy == TypSpravy.koniec.value:
            print("KLIENT UKONCIL ODOSIELANIE SPRAV")
            return

        # kym nedostane spravu bez chyb posiela NACK a caka na novu
        while neposkodene_data(data, checksum) is False:
            print("CHYBNA ", data[const.HLAVICKA:].decode())
            neuspesne_prijata(sock, addr)
            data, addr = sock.recvfrom(buff)
            hlavicka = rozbal_hlavicku(data[:const.HLAVICKA])
            checksum = hlavicka[1]

        uspesne_prijata(sock, addr)

        print("Klient: ", data[const.HLAVICKA:].decode())
        sprava = input("Server (ja): ")

        # ukoncenie spojenia prazdnou spravou
        if len(sprava) == 0 or sprava == ' ':
            ukonci_spojenie(sock, addr[0], addr[1])
            print("UKONCUJEM ODOSIELANIE SPRAV")
            return

        hlavicka = zabal_hlavicku(TypSpravy.data.value, binascii.crc32(sprava.encode()))
        sock.sendto(hlavicka + sprava.encode(), addr)


def server_pripojenie(sock):
    data, addr = sock.recvfrom(buff)

    hlavicka = rozbal_hlavicku(data)
    #print(hlavicka, char(hlavicka[0]))
    typ_spravy = hlavicka[0]

    # dostane od klienta SYN
    if typ_spravy == TypSpravy.syn.value:
        # posle klientovi tiez SYN
        hlavicka = zabal_hlavicku(TypSpravy.syn.value, 0)

        sock.sendto(hlavicka, addr)

        data, addr = sock.recvfrom(buff)

        hlavicka = rozbal_hlavicku(data)
        typ_spravy = hlavicka[0]

        # dostane od klienta ACK
        if typ_spravy == TypSpravy.ack.value:
            print("Mam spojenie z: ", addr)
            return addr

    else:
        print("prijal som inu spravu, spojenie sa nepodarilo nadviazat")
        return -1


def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(socket.gethostname(), socket.gethostbyname(socket.gethostname()))

    ip = socket.gethostbyname(socket.gethostname())

    port = input("Zadajte port: ")
    while port.isnumeric() is False or int(port) < 10000:
        port = input("Zadajte spravny port: ")

    sock.bind((ip, int(port)))

    print("---Server je pripraveny---")

    # DOROBIT 3 way handshake
    addr = server_pripojenie(sock)
    if addr == -1:
        print("nepodarilo sa pripojit")
        ukonci_spojenie(sock, addr[0], addr[1])

    while True:
        data, addr = sock.recvfrom(buff)

        hlavicka = rozbal_hlavicku(data)
        typ_spravy = hlavicka[0]

        # odosielanie sprav
        if typ_spravy == TypSpravy.sprava.value:
            server_spravy(sock)
        # odosielanie suborov

        if typ_spravy == TypSpravy.koniec.value:
            print("\nKLIENT UKONCIL SPOJENIE")
            return


# 192.168.1.15
if __name__ == '__main__':
    volba: str = '1'

    while volba != '0':
        volba = input("-------------------------------------------------------\n"
                      "1 - Klient \n2 - Server\n0 - Ukoncenie programu\nVolba: ")

        if volba == '0':
            exit()
        elif volba == '1':
            klient()
        elif volba == '2':
            server()
        else:
            print("neznamy vstup")
            continue
