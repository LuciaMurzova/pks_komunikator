import ipaddress
import select
import socket
import struct
import sys
import time
import const
import typ


velkost_fragmentu: int
typ: int


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

    hlavicka = struct.pack('b', ord('U'))
    sprava = 'AHOJ TY KOKOT SERVER'
    sock.sendto(hlavicka + sprava.encode(), (host, port))

    while True:
        sprava = input("Klient (ja): ")
        # ukoncenie odosielania sprav prazdnou spravou
        if len(sprava) == 0 or sprava == ' ':
           # sock.sendto(sprava.encode(), (host, port))
            ukonci_spojenie(sock, host, port)
            print("UKONCUJEM ODOSIELANIE SPRAV")
            return

        sock.sendto(sprava.encode(), (host, port))
        data, addr = sock.recvfrom(1024)

        # ukoncenie odosielania sprav zo strany servera
        if len(data.decode()) == 0 or data.decode() == ' ':
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


def nadviaz_spojenie(sock, ip, port):
    hlavicka = struct.pack('b', ord('A'))
    sprava = 'ahoj server'
    sock.sendto(hlavicka + sprava.encode(), (ip, port))


def ukonci_spojenie(sock, ip, port):
    hlavicka = struct.pack('b', ord(typ.koniec))
    sock.sendto(hlavicka, (ip, port))


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

    nadviaz_spojenie(sock, ip, port)

    while True:
        volba = input("\n1 - Odoslanie spravy \n2 - Odoslanie suboru \n0 - Ukoncenie spojenia \nVolba: ")

        if volba == '1':
            odoslanie_spravy(sock, ip, port)

        elif volba == '2':
            print("odosielanie suboru")
            odoslanie_suboru(sock, ip, port)

        elif volba == '0':
            print('UKONCENIE SPOJENIA\n')
            sprava = ''
            sock.sendto(sprava.encode(), (ip, port))
            return
        else:
            continue

    ukonci_spojenie(sock, ip, port)

    return


def server_spravy(sock, ip, port):
    while True:
        # ukoncenie zo strany klienta
        data, addr = sock.recvfrom(1024)
        if len(data.decode()) == 0 or data.decode() == ' ':
            print("KLIENT UKONCIL ODOSIELANIE SPRAV")
            return

        print("Klient: ", str(data.decode()))
        sprava = input("Server (ja): ")

        # ukoncenie spojenia prazdnou spravou
        if len(sprava) == 0 or sprava == ' ':
            sock.sendto(sprava.encode(), addr)
            print("UKONCUJEM ODOSIELANIE SPRAV")
            return

        sock.sendto(sprava.encode(), addr)


#def skontroluj_checksum():

def server_pripojenie(sock):
    data, addr = sock.recvfrom(1024)

    a = struct.unpack('b', data[:const.HLAVICKA])
    typ_spravy = chr(a[0])

    if typ == 'S':
        print('mam ACK, posielam svoje')
        syn = struct.pack(ord(typ.syn))
        sock.sendto(syn, addr)

    else:
        print("prijal som inu spravu, spojenie sa nepodarilo nadviazat")
        return -1

    print("Mam spojenie z: ", addr)
    return addr


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

    #data, addr = sock.recvfrom(1024)
    #print("Mam spojenie z: ", addr)

    # ked posielam iba hlavicku potrebujem nieco z tohoto
    #print(data.decode(), data.decode()[0])
    #hlavicka = struct.unpack('b', data)
    #print('Hl ', chr(hlavicka[0]) )

    while True:
        data, addr = sock.recvfrom(1024)
        print(len(data), sys.getsizeof(data[:const.HLAVICKA]), len(data.decode()))

        a = struct.unpack('b', data[:const.HLAVICKA])
        typ = chr(a[0])
        sprava = data.decode()[const.HLAVICKA:]

        print(typ, sprava)

        # odosielanie sprav
        if typ == 'U':
            server_spravy(sock, ip, port)
        # odosielanie suborov


        #if data:
        #    print("File name:", data)
        #    file_name = data.strip()

        #f = open(file_name, 'wb')

        #while True:
        #    ready = select.select([sock], [], [], timeout)
        #    if ready[0]:
        #        data, addr = sock.recvfrom(1024)
        ##        f.write(data)
        #    else:
        #        print("%s Finish!" % file_name)
        #        f.close()
        #        break


# 192.168.1.15
if __name__ == '__main__':
    typ: str = '1'

    while typ != '0':
        typ = input("-------------------------------------------------------\n"
                    "1 - Klient \n2 - Server\n0 - Ukoncenie programu\nVolba: ")

        if typ == '0':
            print('ukoncenie aplikacie')
            exit()
        elif typ == '1':
            klient()
        elif typ == '2':
            server()
        else:
            print("neznamy vstup")
            continue
