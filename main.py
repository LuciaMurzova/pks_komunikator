import binascii
import ipaddress
import socket
import struct
import sys
import time
import const
import typy_sprav
from binascii import crc32

velkost_fragmentu: int
# typ: int

# -------------------------------------------------------------------------
# SPOLOCNE


def zabal_hlavicku(typ_spravy: int):
    return struct.pack('b', typ_spravy)


def zabal_hlavicku_n(typ_spravy: int, crc: int):
    #return struct.pack('bH', typ_spravy, crc16)
    return struct.pack('bI', typ_spravy, crc)


def rozbal_hlavicku(data):
    return struct.unpack('b', data[:const.HLAVICKA])


def rozbal_hlavicku_n(data):
    return struct.unpack('bI', data)


def ukonci_spojenie(sock, ip, port):
    hlavicka = zabal_hlavicku_n(ord(typy_sprav.koniec), 0)
    #hlavicka = struct.pack('b', ord(typy_sprav.koniec))
    sock.sendto(hlavicka, (ip, port))


# -------------------------------------------------------------------------
# KLIENT


def odoslanie_suboru(sock, host, port: int):
    file_name = 'kokociny.txt'
    sock.sendto(file_name.encode(), (host, port))
    print("Sending %s ..." % file_name)

    f = open(file_name, "r")
    data = f.read(1024)
    while data:
        if sock.sendto(data.encode(), (host, port)):
            data = f.read(1024)
            time.sleep(0.02)  # Give receiver a bit time to save

    sock.close()
    f.close()


def odoslanie_spravy(sock, host, port: int):
    print("\nOdosielanie spravy je mozne zrusit prazdnou spravou.")

    # odoslanie informacii serveru, ze budu posielane spravy
    hlavicka = zabal_hlavicku(ord(typy_sprav.sprava))
    sock.sendto(hlavicka, (host, port))

    while True:
        sprava = input("Klient (ja): ")
        # ukoncenie odosielania sprav prazdnou spravou
        if len(sprava) == 0 or sprava == ' ':
            ukonci_spojenie(sock, host, port)
            print("UKONCUJEM ODOSIELANIE SPRAV")
            return

        hlavicka = zabal_hlavicku_n(ord(typy_sprav.data), binascii.crc32(sprava.encode()))
        #print(sys.getsizeof(hlavicka), hlavicka[1], sys.getsizeof(hlavicka[1]))
        sock.sendto(hlavicka + sprava.encode(), (host, port))
        data, addr = sock.recvfrom(1024)

        hlavicka = rozbal_hlavicku(data)
        typ_spravy = chr(hlavicka[0])

        # ukoncenie odosielania sprav zo strany servera
        if typ_spravy == typy_sprav.koniec:
            print("SERVER UKONCIL ODOSIELANIE SPRAV")
            return

        print("Server: ", data.decode())


# ZDROJ - https://codefather.tech/blog/validate-ip-address-python/
def validuj_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        #print("IP address {} is valid. The object returned is {}".format(address, ip))
        return True
    except ValueError:
        #print("IP address {} is not valid".format(address))
        return False


def klient_nadviaz_spojenie(sock, ip, port):
    # odosle serveru SYN
    hlavicka = zabal_hlavicku(ord(typy_sprav.syn))
    sock.sendto(hlavicka, (ip, port))

    data, addr = sock.recvfrom(1024)
    hlavicka = rozbal_hlavicku(data)
    typ_spravy = chr(hlavicka[0])

    # dostane SYN od serveru
    if typ_spravy == typy_sprav.syn:
        # posle serveru ACK
        hlavicka = zabal_hlavicku(ord(typy_sprav.ack))
        sock.sendto(hlavicka, (ip, port))
        return True

    else:
        print('neprislo mi potvrdenie')
        return False


#def vypocitaj_checksum():


def klient():
    global velkost_fragmentu
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

    if klient_nadviaz_spojenie(sock, ip, port) is False:
        print("Nepodarilo sa nadviazat spojenie so serverom")
        return

    while True:
        volba = input("\n1 - Odoslanie spravy \n2 - Odoslanie suboru \n0 - Ukoncenie spojenia \nVolba: ")

        if volba == '1':
            odoslanie_spravy(sock, ip, port)

        elif volba == '2':
            print("odosielanie suboru")
            odoslanie_suboru(sock, ip, port)

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


def server_spravy(sock):
    while True:
        data, addr = sock.recvfrom(1024)

        #hlavicka = rozbal_hlavicku(data)
        hlavicka = rozbal_hlavicku_n(data[:const.HLAVICKA_N])
        typ_spravy = chr(hlavicka[0])

        # ukoncenie zo strany klienta
        if typ_spravy == typy_sprav.koniec:
            print("KLIENT UKONCIL ODOSIELANIE SPRAV")
            return

        print("Klient: ", data[const.HLAVICKA_N:].decode())
        sprava = input("Server (ja): ")

        # ukoncenie spojenia prazdnou spravou
        if len(sprava) == 0 or sprava == ' ':
            ukonci_spojenie(sock, addr[0], addr[1])
            print("UKONCUJEM ODOSIELANIE SPRAV")
            return

        sock.sendto(sprava.encode(), addr)


#def skontroluj_checksum():


def server_pripojenie(sock):
    data, addr = sock.recvfrom(1024)

    hlavicka = rozbal_hlavicku(data)
    typ_spravy = chr(hlavicka[0])

    # dostane od klienta SYN
    if typ_spravy == typy_sprav.syn:
        # posle klientovi tiez SYN
        # syn = struct.pack('b', ord(typy_sprav.syn))
        hlavicka = zabal_hlavicku(ord(typy_sprav.syn))
        sock.sendto(hlavicka, addr)

        data, addr = sock.recvfrom(1024)

        hlavicka = rozbal_hlavicku(data)
        typ_spravy = chr(hlavicka[0])

        # dostane od klienta ACK
        if typ_spravy == typy_sprav.ack:
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
        data, addr = sock.recvfrom(1024)

        hlavicka = rozbal_hlavicku(data)
        typ_spravy = chr(hlavicka[0])

        # odosielanie sprav
        if typ_spravy == typy_sprav.sprava:
            server_spravy(sock)
        # odosielanie suborov

        if typ_spravy == typy_sprav.koniec:
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
