import binascii
import ipaddress
import os
import socket
import struct
from enum import Enum


# C:\Users\Lucia\Desktop\5. semester\PKS\2. Zadanie\ML.pdf

class TypSpravy(Enum):
    ack = ord('A')
    nack = ord('N')
    syn = ord('S')
    sprava = ord('P')
    subor = ord('U')
    data = ord('D')
    koniec = ord('K')


buff: int = 1472  # najvacisa mozna velkost fragmentu - datova cast fragmentu: buff-hlavicka
N: int = 12  # pocet fragmentov na jedno odoslanie, max 255
HLAVICKA = 4


# -------------------------------------------------------------------------
# SPOLOCNE


def zabal_hlavicku(typ_spravy: int, cislo: int, data):
    # funkcia pouzivana pri odosielani suboru - postupnost bytov - nemoze uz pouzit encode, aj pri spravach - string
    if type(data) != bytes:
        return struct.pack('bbH', typ_spravy, cislo, binascii.crc_hqx(data.encode(), 0))
    else:
        return struct.pack('bbH', typ_spravy, cislo, binascii.crc_hqx(data, 0))


def rozbal_hlavicku(data):
    return struct.unpack('bbH', data)


def ukonci_spojenie(sock, ip, port):
    hlavicka = zabal_hlavicku(TypSpravy.koniec.value, 0, '')
    sock.sendto(hlavicka, (ip, port))


# vypocet potrebnych skupin po N fragmentov na prenos celej spravy / suboru
def vypocitaj_potrebne_skupiny(potrebne_fragmenty: int):
    if potrebne_fragmenty / N != int(potrebne_fragmenty / N):
        return int(potrebne_fragmenty / N) + 1
    else:
        return int(potrebne_fragmenty / N)


# -------------------------------------------------------------------------
# KLIENT


def odoslanie_suboru(sock, host, port: int, velkost_fragmentu: int):
    # zvolenie absolutnej cesty k suboru
    absolutna_cesta: str = ' '
    while os.path.isfile(absolutna_cesta) is False:
        absolutna_cesta = input("Subor s absolutnou cestou: ")

    # ulozenie samotneho nazvu suboru
    nazov_odosielaneho_suboru = os.path.basename(absolutna_cesta)

    simulovanie_chyby = ' '
    while simulovanie_chyby != 'A' and simulovanie_chyby != 'a' and \
            simulovanie_chyby != 'N' and simulovanie_chyby != 'n':
        simulovanie_chyby = input("Simulovanie chyby A / N: ")

    if simulovanie_chyby == 'A' or simulovanie_chyby == 'a':
        simulovanie_chyby = True
    elif simulovanie_chyby == 'N' or simulovanie_chyby == 'n':
        simulovanie_chyby = False

    # nacitanie celeho suboru
    subor = open(absolutna_cesta, 'rb')
    cely_subor = subor.read()
    subor.close()

    velkost_suboru: int = len(cely_subor)
    potrebne_fragmenty: int = vypocitaj_potrebne_fragmenty(cely_subor, velkost_fragmentu)
    pocet_skupin: int = vypocitaj_potrebne_skupiny(potrebne_fragmenty)
    neodoslane: int = potrebne_fragmenty

    # odoslanie informacii serveru - bude posielany subor, jeho nazov, velkost fragmentov a potrebny pocet fragmentov
    # server sa dostane do funkcie server_subor()
    data = str(nazov_odosielaneho_suboru) + " " + str(velkost_suboru) + " " + str(potrebne_fragmenty)
    hlavicka = zabal_hlavicku(TypSpravy.subor.value, 0, data)

    typ_spravy = TypSpravy.nack.value

    # posiela spravu s info kym nedostane ACK
    while typ_spravy == TypSpravy.nack.value:
        sock.sendto(hlavicka + data.encode(), (host, port))
        # prijatie ACK / NACK
        data, addr = sock.recvfrom(buff)
        prijata_hlavicka = rozbal_hlavicku(data[:HLAVICKA])
        typ_spravy = prijata_hlavicka[0]

    for skupiny in range(pocet_skupin):
        # ak N-neodoslane > 0 posielame N fragmentov, inak iba zvysne neodoslane
        if N - neodoslane > 0:
            na_odoslanie = neodoslane
        else:
            na_odoslanie = N

        fragmenty_na_odoslanie = []

        for fragment in range(na_odoslanie):
            # cislo_fragmentu = (skupiny * N) + fragment + 1
            fragmenty_na_odoslanie.append(cely_subor[:velkost_fragmentu])
            hlavicka = zabal_hlavicku(TypSpravy.data.value, fragment, fragmenty_na_odoslanie[fragment])

            # simulovanie chyby skratenim odoslaneho fragmentu
            if simulovanie_chyby and (fragment == 1 or fragment == 5):
                sprava = fragmenty_na_odoslanie[fragment]
                sock.sendto(hlavicka + sprava[:len(sprava) - 2], (host, port))
            else:
                sock.sendto(hlavicka + fragmenty_na_odoslanie[fragment], (host, port))

            cely_subor = cely_subor[velkost_fragmentu:]

        # prijatie ACK / NACK
        data, addr = sock.recvfrom(buff)
        prijata_hlavicka = rozbal_hlavicku(data[:HLAVICKA])
        typ_spravy = prijata_hlavicka[0]

        # posiela spravu kym nedostane ACK
        while typ_spravy == TypSpravy.nack.value:
            # print('Niektory fragment nebol odoslany uspesne - ', data[const.HLAVICKA:].decode())
            # treba zistit ktore neboli uspesne a poslat zas z pola spravy
            data = data[HLAVICKA:].decode()
            data = [int(s) for s in data.split() if s.isdigit()]

            for neuspesny in data:
                hlavicka = zabal_hlavicku(TypSpravy.data.value, neuspesny, fragmenty_na_odoslanie[neuspesny])
                sock.sendto(hlavicka + fragmenty_na_odoslanie[neuspesny], (host, port))

            # prijatie ACK / NACK / ukoncenie spojenia pri 3 neuspesnych pokusoch
            data, addr = sock.recvfrom(buff)
            prijata_hlavicka = rozbal_hlavicku(data[:HLAVICKA])
            typ_spravy = prijata_hlavicka[0]

            if typ_spravy == TypSpravy.koniec.value:
                print("nepodarilo sa odoslat spravu, ukoncujem odosielanie")
                return

        neodoslane -= na_odoslanie

    print("Subor bol uspesne odoslany \n"
          "Absolutna cesta: ", absolutna_cesta, "\nVelkost suboru: %.3f" % (velkost_suboru / (1024 * 1024)), "MB\n"
          "Odoslane fragmenty: ", potrebne_fragmenty)


def vypocitaj_potrebne_fragmenty(sprava_na_odoslanie, velkost_jedneho_fragmentu):
    if len(sprava_na_odoslanie) / velkost_jedneho_fragmentu != int(
            len(sprava_na_odoslanie) / velkost_jedneho_fragmentu):
        return int(len(sprava_na_odoslanie) / velkost_jedneho_fragmentu) + 1
    else:
        return int(len(sprava_na_odoslanie) / velkost_jedneho_fragmentu)


def odoslanie_spravy(sock, host, port: int, velkost_fragmentu: int):
    print("\nOdosielanie spravy je mozne zrusit prazdnou spravou.")

    # odoslanie informacii serveru, ze budu posielane spravy - server sa dostane do funkcie server_spravy()
    hlavicka = zabal_hlavicku(TypSpravy.sprava.value, 0, '')
    sock.sendto(hlavicka, (host, port))

    while True:
        sprava = input("Klient (ja): ")

        # ukoncenie odosielania sprav prazdnou spravou, vrati sa do menu v Klient()
        if len(sprava) == 0 or sprava == ' ':
            ukonci_spojenie(sock, host, port)
            print("UKONCUJEM ODOSIELANIE SPRAV - cakam na server")
            return

        # vypocet potrebnych fragmentov
        potrebne_fragmenty: int = vypocitaj_potrebne_fragmenty(sprava, velkost_fragmentu)
        neodoslane: int = potrebne_fragmenty

        # odoslanie informacii serveru o pocte a velkosti fragmentov
        data = str(velkost_fragmentu) + " " + str(potrebne_fragmenty)
        hlavicka = zabal_hlavicku(TypSpravy.sprava.value, 0, data)

        # vypocet potrebnych skupin - pocet vsetkych fragmentov / pocet f na 1 odoslanie
        pocet_skupin: int = vypocitaj_potrebne_skupiny(potrebne_fragmenty)

        typ_spravy = TypSpravy.nack.value

        # posiela spravu s info kym nedostane ACK
        while typ_spravy == TypSpravy.nack.value:
            sock.sendto(hlavicka + data.encode(), (host, port))
            # prijatie ACK / NACK
            data, addr = sock.recvfrom(buff)
            prijata_hlavicka = rozbal_hlavicku(data[:HLAVICKA])
            typ_spravy = prijata_hlavicka[0]

        # odosielanie fragmentov po skupinach N fragmentov
        for skupiny in range(pocet_skupin):
            # ak N-neodoslane > 0 posielame N fragmentov, inak iba zvysne neodoslane
            if N - neodoslane > 0:
                na_odoslanie = neodoslane
            else:
                na_odoslanie = N

            # ulozenie a odoslanie N sprav - keby dostal NACK a musel by ich poslat znovu
            spravy = []
            for fragment in range(na_odoslanie):
                spravy.append(sprava[:velkost_fragmentu])
                hlavicka = zabal_hlavicku(TypSpravy.data.value, fragment, spravy[fragment])
                if fragment == 1 or fragment == 2 or fragment == N + 1:
                    sock.sendto(hlavicka + spravy[fragment].encode() + 'ch'.encode(), (host, port))
                else:
                    sock.sendto(hlavicka + spravy[fragment].encode(), (host, port))

                sprava = sprava[velkost_fragmentu:]

            # prijatie ACK / NACK
            data, addr = sock.recvfrom(buff)
            prijata_hlavicka = rozbal_hlavicku(data[:HLAVICKA])
            typ_spravy = prijata_hlavicka[0]

            # posiela spravu kym nedostane ACK
            while typ_spravy == TypSpravy.nack.value:
                # print('Niektory fragment nebol odoslany uspesne - ', data[const.HLAVICKA:].decode())
                # treba zistit ktore neboli uspesne a poslat zas z pola spravy
                data = data[HLAVICKA:].decode()
                data = [int(s) for s in data.split() if s.isdigit()]

                for neuspesny in data:
                    hlavicka = zabal_hlavicku(TypSpravy.data.value, neuspesny, spravy[neuspesny])
                    sock.sendto(hlavicka + spravy[neuspesny].encode(), (host, port))

                # prijatie ACK / NACK / ukoncenie spojenia pri 3 neuspesnych pokusoch
                data, addr = sock.recvfrom(buff)
                prijata_hlavicka = rozbal_hlavicku(data[:HLAVICKA])
                typ_spravy = prijata_hlavicka[0]

                if typ_spravy == TypSpravy.koniec.value:
                    print("nepodarilo sa odoslat spravu, ukoncujem odosielanie")
                    return

            neodoslane -= na_odoslanie

        print("sprava bola uspesne dorucena")

        # prijatie odpovede
        data, addr = sock.recvfrom(buff)
        prijata_hlavicka = rozbal_hlavicku(data[:HLAVICKA])
        typ_spravy = prijata_hlavicka[0]

        # ukoncenie odosielania sprav zo strany servera
        if typ_spravy == TypSpravy.koniec.value:
            print("SERVER UKONCIL ODOSIELANIE SPRAV")
            return

        print("Server: ", data[HLAVICKA:].decode())


# funkcia pre overenie IP adresy, prevzata z - https://codefather.tech/blog/validate-ip-address-python/
def validuj_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def klient_nadviaz_spojenie(sock, ip, port):
    # odosle serveru SYN
    hlavicka = zabal_hlavicku(TypSpravy.syn.value, 0, '')
    sock.sendto(hlavicka, (ip, port))

    # prijatie spravy od servera
    try:
        data, addr = sock.recvfrom(buff)
        hlavicka = rozbal_hlavicku(data)
        typ_spravy = hlavicka[0]

    # pripojenie na iny port
    except ConnectionResetError:
        return False

    # dostane od servera SYN
    if typ_spravy == TypSpravy.syn.value:
        # posle serveru ACK - uspesne pripojenie
        hlavicka = zabal_hlavicku(TypSpravy.ack.value, 0, '')
        sock.sendto(hlavicka, (ip, port))
        return True
    else:
        return False


def server_ukoncuje(sock):
    data, addr = sock.recvfrom(buff)
    hlavicka = rozbal_hlavicku(data)

    if hlavicka[0] == TypSpravy.koniec.value:
        print("server ukoncil spojenie")
        return True

    return False


def klient():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ip = ' '
    while validuj_ip(ip) is False:
        ip = input("Zadajte IP adresu: ")

    port = '0'
    while port.isnumeric() is False or int(port) < 1000 or int(port) > 65535:
        port = input("Zadajte port 1.000 - 65.535: ")
    port = int(port)

    velkost_fragmentu = '0'
    while velkost_fragmentu.isnumeric() is False or \
            int(velkost_fragmentu) <= 0 or int(velkost_fragmentu) > buff - HLAVICKA:
        velkost_fragmentu = input("Zadajte velkost fragmentu 1 - %d: " % (buff - HLAVICKA))
    velkost_fragmentu = int(velkost_fragmentu)

    # spojenie so serverom cez # way handshake
    if klient_nadviaz_spojenie(sock, ip, port) is False:
        print("Nepodarilo sa nadviazat spojenie so serverom")
        return

    # hlavne menu klienta
    while True:
        menu_klient = input("\n1 - Odoslanie spravy \n2 - Odoslanie suboru \n0 - Ukoncenie spojenia \nVolba: ")

        if menu_klient == '1':
            odoslanie_spravy(sock, ip, port, velkost_fragmentu)
            # po ukonceni odosielania sprav dostane od servera info ci chce skoncit / pokracovat
            if server_ukoncuje(sock):
                return

        elif menu_klient == '2':
            odoslanie_suboru(sock, ip, port, velkost_fragmentu)
            # po ukonceni odosielania suboru dostane od servera info ci chce skoncit / pokracovat
            if server_ukoncuje(sock):
                return

        elif menu_klient == '0':
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
    kontrolny_checksum = binascii.crc_hqx(data[HLAVICKA:], 0)

    if kontrolny_checksum == checksum:
        return True

    return False


def neuspesne_prijata(sock, addr, sprava):
    hlavicka = zabal_hlavicku(TypSpravy.nack.value, 0, '0')
    sock.sendto(hlavicka + sprava.encode(), addr)


def uspesne_prijata(sock, addr):
    hlavicka = zabal_hlavicku(TypSpravy.ack.value, 0, '')
    sock.sendto(hlavicka, addr)


def pokracuj_v_spojeni(sock, ip, port):
    hlavicka = zabal_hlavicku(TypSpravy.ack.value, 0, '')
    sock.sendto(hlavicka, (ip, port))


def vyziadaj_neuspesne(sock, addr, neuspesne, sprava, skupiny):
    pocet_neuspesnych_pokusov = 1
    # cyklus pre vyziadanie zle dorucenych fragmentov - ide max 3.krat
    while pocet_neuspesnych_pokusov <= 3:
        neuspesne_dorucene = ' '.join(neuspesne)

        # odosle spravu s info ktore fragmenty boli zle prijate, nasledne ich zaradi na miesto pdola cisla
        neuspesne_prijata(sock, addr, neuspesne_dorucene)
        neuspesne_dorucene = []

        for neuspesny in neuspesne:
            data, addr = sock.recvfrom(buff)
            hlavicka = rozbal_hlavicku(data[:HLAVICKA])
            cislo = (skupiny * N) + hlavicka[1] + 1
            checksum = hlavicka[2]

            # ak je vo fragmente chyba, ulozi jeho cislo pre nasledne vyziadanie, inak ulozi prijatu spravu
            if neposkodene_data(data, checksum) is False:
                print("Fragment c. ", cislo, "nebol uspene doruceny, c. pokusu: ", pocet_neuspesnych_pokusov)
                neuspesne_dorucene.append(str(cislo - 1))
            else:
                print("Fragment c.", cislo, "bol doruceny uspesne, velkost: ", len(data[HLAVICKA:]))
                if type(data) == bytes:
                    sprava.insert(cislo - 1, data[HLAVICKA:])
                else:
                    sprava.insert(cislo - 1, data[HLAVICKA:].decode())

        neuspesne = neuspesne_dorucene
        if len(neuspesne_dorucene) == 0:
            uspesne_prijata(sock, addr)
            break

        pocet_neuspesnych_pokusov += 1

    if pocet_neuspesnych_pokusov >= 3:
        print("nepodarilo sa spravne prijat spravu, ukoncujem odosielanie")
        ukonci_spojenie(sock, addr[0], addr[1])
        return ''

    return sprava


def server_spravy(sock: socket):
    print("\nOdosielanie spravy je mozne zrusit prazdnou spravou.")

    while True:
        # prijatie spravy s uvodnymi info
        data, addr = sock.recvfrom(buff)
        hlavicka = rozbal_hlavicku(data[:HLAVICKA])
        typ_spravy = hlavicka[0]

        # ukoncenie zo strany klienta
        if typ_spravy == TypSpravy.koniec.value:
            print("KLIENT UKONCIL ODOSIELANIE SPRAV")
            return

        # kontrola spravy s info o odosielani
        while neposkodene_data(data, hlavicka[2]) is False:
            neuspesne_prijata(sock, addr, '')
            data, addr = sock.recvfrom(buff)
            hlavicka = rozbal_hlavicku(data[:HLAVICKA])

        uspesne_prijata(sock, addr)

        # z prvej spravy ulozi velkost a pocet fragmentov
        data = data[HLAVICKA:].decode()
        data = [int(s) for s in data.split() if s.isdigit()]
        potrebne_fragmenty = nedorucene = data[1]

        # vypocet potrebnych skupin - pocet vsetkych fragmentov / pocet f na 1 odoslanie
        pocet_skupin: int = vypocitaj_potrebne_skupiny(potrebne_fragmenty)

        sprava = []

        # prijimanie fragmentov po skupinach N fragmentov
        for skupiny in range(pocet_skupin):
            # ak ostava nedorucenych menej ako N fragmentov, bude ocakavat prijatie iba tolkych
            if nedorucene >= N:
                na_dorucenie = N
            else:
                na_dorucenie = nedorucene

            neuspesne = []  # odkladanie cisiel neuspesne dorucenych fragmentov pre opatovne vyziadanie

            # prijimanie jednej skupinu N fragmentov
            for fragment in range(na_dorucenie):
                data, addr = sock.recvfrom(buff)
                hlavicka = rozbal_hlavicku(data[:HLAVICKA])

                # vypocitanie cisla odosielaneho fragmentu podla poradia v danej skupine - hlavicka[1]
                cislo = (skupiny * N) + hlavicka[1] + 1
                checksum = hlavicka[2]

                # ak je vo fragmente chyba, ulozi si jeho cislo pre nasledne vyziadanie, inak ulozi prijatu spravu
                if neposkodene_data(data, checksum) is False:
                    # print("Fragment c. ", cislo, "nebol uspene doruceny", hlavicka[1])
                    neuspesne.append(str(hlavicka[1]))
                else:
                    # print("Fragment c.", cislo, "bol doruceny uspesne, velkost: ", len(data[const.HLAVICKA:]))
                    sprava.append(data[HLAVICKA:].decode())

            # vsetky boli prijate uspesne, odosleme ACK
            if len(neuspesne) == 0:
                uspesne_prijata(sock, addr)

            # znovuvyziadanie zle prijatych fragmentov po kazdej skupine N fragmentov
            else:
                sprava = vyziadaj_neuspesne(sock, addr, neuspesne, sprava, skupiny)
                # vrati '' ak sprava nebola spravne dorucena ani na 3 krat
                if sprava == '':
                    return

            nedorucene -= na_dorucenie

        # vypisanie celej spravy po jej uspesnom doruceni a zadanie odpovede
        print("Klient: ", ''.join(sprava))
        sprava = input("Server (ja): ")

        # ukoncenie spojenia prazdnou spravou
        if len(sprava) == 0 or sprava == ' ':
            ukonci_spojenie(sock, addr[0], addr[1])
            print("UKONCUJEM ODOSIELANIE SPRAV")
            return

        hlavicka = zabal_hlavicku(TypSpravy.data.value, 0, sprava)
        sock.sendto(hlavicka + sprava.encode(), addr)


def server_subor(sock, addr, hlavicka, data):
    print("hlavicka ", hlavicka, data[HLAVICKA:].decode())

    # zadanie adresara na ulozenie
    absolutna_cesta_ulozenia: str = ''
    while os.path.isdir(absolutna_cesta_ulozenia) is False:
        absolutna_cesta_ulozenia = input("Absolutna cesta pre ulozenie: ")

    # kontrola spravnosti info o subore
    while neposkodene_data(data, hlavicka[2]) is False:
        neuspesne_prijata(sock, addr, '')
        data, addr = sock.recvfrom(buff)
        hlavicka = rozbal_hlavicku(data[:HLAVICKA])

    uspesne_prijata(sock, addr)
    data = data[HLAVICKA:].decode()

    data = data.split()
    nazov_prijimaneho_suboru = data[0]
    velkost_suboru = int(data[1])
    potrebne_fragmenty = nedorucene = int(data[2])
    pocet_skupin: int = vypocitaj_potrebne_skupiny(potrebne_fragmenty)
    prijata_velkost: int = 0

    obsah = []
    for skupiny in range(pocet_skupin):
        # ak ostava nedorucenych menej ako N fragmentov, bude ocakavat prijatie iba tolkych
        if nedorucene >= N:
            na_dorucenie = N
        else:
            na_dorucenie = nedorucene

        neuspesne = []
        for fragment in range(na_dorucenie):
            data, addr = sock.recvfrom(buff)
            hlavicka = rozbal_hlavicku(data[:HLAVICKA])

            cislo = (skupiny * N) + hlavicka[1] + 1
            checksum = hlavicka[2]

            # ak je vo fragmente chyba, ulozi si jeho cislo pre nasledne vyziadanie, inak ulozi prijatu spravu
            if neposkodene_data(data, checksum) is False:
                print("Fragment c.", cislo, "nebol uspene doruceny")
                neuspesne.append(str(hlavicka[1]))
            else:
                print("Fragment c.", cislo, "bol doruceny uspesne, velkost: ", len(data[HLAVICKA:]))
                obsah.append(data[HLAVICKA:])

            prijata_velkost += len(data[HLAVICKA:])

        # vsetky boli prijate uspesne, odosleme ACK
        if len(neuspesne) == 0:
            uspesne_prijata(sock, addr)

        # znovuvyziadanie zle prijatych fragmentov po kazdej skupine N fragmentov
        else:
            obsah = vyziadaj_neuspesne(sock, addr, neuspesne, obsah, skupiny)
            # vrati '' ak sprava nebola spravne dorucena ani na 3 krat
            if obsah == '':
                return

        nedorucene -= na_dorucenie

    ciel = absolutna_cesta_ulozenia + "/" + nazov_prijimaneho_suboru
    cielovy_subor = open(ciel, "wb")

    for o in obsah:
        cielovy_subor.write(o)

    cielovy_subor.close()

    print("Prijaty subor: ", nazov_prijimaneho_suboru, "\nCesta k suboru: ", absolutna_cesta_ulozenia,
          "\nPrijal som %d fragmentov o celkovej velkosti %.3f" %
          (potrebne_fragmenty, velkost_suboru / (1024 * 1024)), "MB")


def server_pripojenie(sock):
    # dprijatie prvej spravy od klienta
    data, addr = sock.recvfrom(buff)
    hlavicka = rozbal_hlavicku(data)
    typ_spravy = hlavicka[0]

    # dostal SYN
    if typ_spravy == TypSpravy.syn.value:
        # posle klientovi tiez SYN
        hlavicka = zabal_hlavicku(TypSpravy.syn.value, 0, '')
        sock.sendto(hlavicka, addr)

        # prijatie odpovede
        data, addr = sock.recvfrom(buff)
        hlavicka = rozbal_hlavicku(data)
        typ_spravy = hlavicka[0]

        # dostal od klienta ACK
        if typ_spravy == TypSpravy.ack.value:
            print("Mam spojenie z: ", addr[0], "\nna porte: ", addr[1])
            return addr

    else:
        return -1


def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ip = socket.gethostbyname(socket.gethostname())

    port = '0'
    while port.isnumeric() is False or int(port) < 1000 or int(port) > 65535:
        port = input("Zadajte port 1.000 - 65.535: ")
    port = int(port)

    sock.bind((ip, port))
    print("IP: ", ip, "\nPort: ", port)
    print("----Server je pripraveny----")

    # nadviazanie spojenia cez 3 - way hadshake
    addr = server_pripojenie(sock)
    if addr == -1:
        print("Nepodarilo sa nadviazat spojenie")
        return

    while True:
        # dostane uvodnu info ci budu dorucovane spravy alebo subor
        data, addr = sock.recvfrom(buff)

        hlavicka = rozbal_hlavicku(data[:HLAVICKA])
        typ_spravy = hlavicka[0]

        # odosielanie sprav
        if typ_spravy == TypSpravy.sprava.value:
            server_spravy(sock)
        # odosielanie suborov
        if typ_spravy == TypSpravy.subor.value:
            server_subor(sock, addr, hlavicka, data)

        if typ_spravy == TypSpravy.koniec.value:
            print("\nKLIENT UKONCIL SPOJENIE")
            return

        ukoncenie = input('Prajete si pokracovat v spojeni? A/N: ')
        if ukoncenie == 'A' or ukoncenie == 'a' or ukoncenie == '':
            pokracuj_v_spojeni(sock, addr[0], addr[1])
        else:
            ukonci_spojenie(sock, addr[0], addr[1])
            return


# 192.168.1.15
# 192.168.1.13
if __name__ == '__main__':
    hlavne_menu: str = '1'

    while hlavne_menu != '0':
        hlavne_menu = input("-------------------------------------------------------\n"
                            "1 - Klient \n2 - Server\n0 - Ukoncenie programu\nVolba: ")

        if hlavne_menu == '0':
            exit()
        elif hlavne_menu == '1':
            klient()
        elif hlavne_menu == '2':
            server()
        else:
            print("Neznamy vstup")
            continue
