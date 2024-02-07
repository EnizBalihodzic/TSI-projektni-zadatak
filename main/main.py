
# imports
from tkinter import *
from datetime import datetime
from random import randint
from cryptography.fernet import Fernet
import os
import smtplib
import random
import string

from PIL import ImageTk, Image

def sadrzi_samo_slova(string):
    abeceda_bih = "abcdefghijklmnopqrstuvwxyzćčžšđ"

    for char in string:
        if char.lower() not in abeceda_bih:
            return False

    return True



def sifruj_poruku(poruka):
    originalni_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '
    permutirani_string = 'iLSaOeXrBCqDpYcVFlfhZTMyjzNJbwWxvQgUGmKkHuPnRdJtAIEo?'

    if len(originalni_string) != len(permutirani_string):
        raise ValueError("Stringovi za permutaciju moraju biti iste dužine.")

    sifra = str.maketrans(originalni_string, permutirani_string)
    return poruka.translate(sifra)


def desifruj_poruku(poruka):
    originalni_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '
    permutirani_string = 'iLSaOeXrBCqDpYcVFlfhZTMyjzNJbwWxvQgUGmKkHuPnRdJtAIEo?'

    if len(originalni_string) != len(permutirani_string):
        raise ValueError("Stringovi za permutaciju moraju biti iste dužine.")

    sifra = str.maketrans(permutirani_string, originalni_string)
    return poruka.translate(sifra)


# key = Fernet.generate_key()
global key
key = b'Uklonili smo kljuc zbog hakera, moze se naci u izvjestaju'
cipher_suite = Fernet(key)
global dugme
global alfabet
alfabet = "abcčćdđefghijklmnoprsštuvzžxywq"

def enkriptuj(ulaz):
    global key
    enkriptovan_tekst = cipher_suite.encrypt((ulaz).encode('utf-8'))
    return enkriptovan_tekst


def dekriptuj(ulaz):
    dekriptovano = cipher_suite.decrypt(ulaz)
    dekriptovano = dekriptovano.decode('utf-8')
    return dekriptovano


global broj_logiranja
broj_logiranja = 3
global pomocna
pomocna = 0
global putanja

# Main Screen
master = Tk()
master.title('ONLINE BANKA')
master.geometry("400x400")


# Functions
def finish_reg():
    global broj_racuna
    global stanje_racuna
    global pomocno_ime
    stanje_racuna = IntVar()
    stanje_racuna = 0
    name = temp_name.get()
    if name.isalpha() == False:
        notif.config(fg="red", text="Ime korisnika mora sadržavati isključivo slova!")
        return
    if len(name)>20:
        notif.config(fg="red", text="Ime korisnika mora biti kraće od 20 karaktera!")
        return
    lastname = temp_lastname.get()
    if lastname.isalpha() == False:
        notif.config(fg="red", text="Prezime korisnika mora sadržavati isključivo slova!")
        return
    if len(lastname)>20:
        notif.config(fg="red", text="Prezime korisnika mora biti kraće od 20 karaktera!")
        return
    age = temp_age.get()
    gender = temp_gender.get()
    password = temp_password.get()
    status = temp_status.get()
    email = temp_email.get()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    broj_racuna = generator_racuna()
    pomocno_ime = sifruj_poruku(name)
    if name == "" or age == "" or gender == "" or password == "" or status == "" or email == "":
        notif.config(fg="red", text="Sva polja morau biti popunjena!")
        return
    counter = 0
    for name_check in all_accounts:
        if name == desifruj_poruku(name_check):
            print(desifruj_poruku(name_check))
            notif.config(fg="red", text="Korisnički račun sa ovim imenom već postoji!")
            counter = 1
            break
    if (counter == 1):
        return

    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    new_file = open(pomocno_ime, "wb")
    new_file.write(enkriptuj(
        name + '\n' + lastname + '\n' + password + '\n' + age + '\n' + gender + '\n' + status + '\n' + email + '\n' + broj_racuna))
    test = enkriptuj(
        name + '\n' + lastname + '\n' + password + '\n' + age + '\n' + gender + '\n' + status + '\n' + email + '\n' + broj_racuna)
    print(dekriptuj(test))
    new_file.close()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Stanja racuna')
    new_file = open(pomocno_ime, "wb")
    new_file.write(enkriptuj(str(stanje_racuna)))
    new_file.close()
    
    notif.config(fg="green", text="Korisnicki racun je kreiran!")



def admin_finish_reg():
    global broj_racuna
    global stanje_racuna
    global kljuc
    kljuc = StringVar()
    stanje_racuna = IntVar()
    kljuc = 'abcdefg'
    name = temp_name.get()
    lastname = temp_lastname.get()
    age = temp_age.get()
    gender = temp_gender.get()
    password = temp_password.get()
    status = temp_status.get()
    email = temp_email.get()

    stanje_racuna = 0
    broj_racuna = generator_racuna()
    pomocno_ime = sifruj_poruku(name)
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Admin korisnici')
    all_accounts = os.listdir()
    if name == "" or age == "" or gender == "" or password == "":
        notif.config(fg="red", text="Sva polja moraju biti popunjena!")
        return

    for name_check in all_accounts:
        if name == name_check:
            notif.config(fg="red", text="Korisnički račun sa ovim imenom već postoji!")
            return
        else:

            new_file = open(sifruj_poruku(name), "wb")
            new_file.write(enkriptuj(
                kljuc + '\n' + name + '\n' + lastname + '\n' + password + '\n' + age + '\n' + gender + '\n' + status + '\n' + email))
            test = enkriptuj(
                kljuc + '\n' + name + '\n' + lastname + '\n' + password + '\n' + age + '\n' + gender + '\n' + status + '\n' + email)
            #print(dekriptuj(test))
            new_file.close()
            notif.config(fg="green", text="Korisnicki racun je kreiran!")


def odabir_register():
    global v
    global obicni_korisnik
    global admin_korisnik
    v = IntVar()
    v.set(3)
    register_screen = Toplevel(master)
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    register_screen.title('REGISTRACIJA')
    register_screen.geometry("500x200")
    register_screen.iconbitmap('secure1.ico')
    Label(register_screen, text="IZABERITE KOJU VRSTU REGISTRACIJE ZELITE:", font=('Segoe UI Semibold', 17),
          fg="orange").grid(row=0, sticky=N, pady=10)
    obicni_korisnik = PhotoImage(file="korisnik_banke_1.png")
    Radiobutton(register_screen, padx=25, variable=v, value=1, command=register, compound='right',image=obicni_korisnik).grid(row=1, column=0, sticky=W)
    admin_korisnik = PhotoImage(file="korisnik_banke_2.png")
    Radiobutton(register_screen, padx=25, variable=v, value=2, command=admin_register, compound='right',image=admin_korisnik).grid(row=2, column=0, sticky=W)


def odabir_login():
    global v
    v = IntVar()
    v.set(3)
    global obicni_korisnik_1
    global admin_korisnik_1
    odabir_login = Toplevel(master)
    odabir_login.title('PRIJAVA')
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')

    odabir_login.geometry("470x200")
    odabir_login.iconbitmap('secure1.ico')

    Label(odabir_login, text="IZABERITE KOJU VRSTU PRIJAVE ZELITE:", font=('Segoe UI Semibold', 17),fg="orange").grid(row=0, sticky=N,pady=10)
    obicni_korisnik_1 = PhotoImage(file="korisnik_banke_1.png")
    Radiobutton(odabir_login, padx=25, variable=v, value=1, command=login, compound='right',image=obicni_korisnik_1).grid(row=1, column=0, sticky=W)
    admin_korisnik_1 = PhotoImage(file="korisnik_banke_2.png")
    Radiobutton(odabir_login, padx=25, variable=v, value=2, command=admin_login, compound='right',image=admin_korisnik_1).grid(row=2, column=0, sticky=W)

def odabir():
    var = v.get()
    return


def register():
    # Vars
    global temp_name
    global temp_lastname
    global temp_age
    global temp_gender
    global temp_password
    global notif
    global temp_status
    global temp_email
    global admin_key
    global korisnik
    global key
    global temp_key
    global broj_racuna

    temp_status = StringVar()
    temp_name = StringVar()
    temp_lastname = StringVar()
    temp_age = StringVar()
    temp_gender = StringVar()
    temp_password = StringVar()
    temp_email = StringVar()
    temp_key = StringVar()
    admin_key = StringVar()
    korisnik = StringVar()
    broj_racuna = StringVar()
    # Register Screen
    register_screen = Toplevel(master)
    register_screen.title('REGISTRACIJA')
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')

    register_screen.iconbitmap('secure1.ico')
    register_screen.geometry("400x400")

    # Labels
    broj_racuna = generator_racuna()
    Label(register_screen, text="Popunite podatke potrebne za registraciju običnog računa: ",
          font=('Calibri', 12)).grid(row=0, sticky=N, pady=10)
    Label(register_screen, text="Ime :", font=('Calibri', 12)).grid(row=1, sticky=W)
    Label(register_screen, text="Prezime :", font=('Calibri', 12)).grid(row=2, sticky=W)
    Label(register_screen, text="Datum rođenja: ", font=('Calibri', 12)).grid(row=3, sticky=W)
    Label(register_screen, text="Spol: ", font=('Calibri', 12)).grid(row=4, sticky=W)
    Label(register_screen, text="PIN: ", font=('Calibri', 12)).grid(row=5, sticky=W)
    Label(register_screen, text="E-mail: ", font=('Calibri', 12)).grid(row=6, sticky=W)

    notif = Label(register_screen, font=('Calibri', 12))
    notif.grid(row=13, sticky=N, pady=10)
    # Entries
    Entry(register_screen, textvariable=temp_name).grid(row=1, column=0, padx=(135, 0))

    Entry(register_screen, textvariable=temp_lastname).grid(row=2, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_age).grid(row=3, column=0, padx=(135, 0))
    Radiobutton(register_screen, text="Muski", variable=temp_gender, value="Muski").grid(row=4, column=0,
                                                                                               sticky=W)
    Radiobutton(register_screen, text="Zenski", variable=temp_gender, value="Zenski").grid(row=4, column=0,
                                                                                                 sticky=N)
    Entry(register_screen, textvariable=temp_password, show="*").grid(row=5, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_email).grid(row=6, column=0, padx=(135, 0))
    Label(register_screen, text="Status: ").grid(row=10, column=0)
    Radiobutton(register_screen, text="Zaposlen", variable=temp_status, value="Zaposlen").grid(row=11, column=0,
                                                                                               sticky=W)
    Radiobutton(register_screen, text="Penzioner", variable=temp_status, value="Penzioner").grid(row=11, column=0,
                                                                                                 sticky=N)
    Radiobutton(register_screen, text="Student", variable=temp_status, value="Student").grid(row=11, column=0, sticky=E)
    Button(register_screen, text="Registruj me!", command=finish_reg, font=('Calibri', 12)).grid(row=7, sticky=N,
                                                                                                 pady=10)


def generator_racuna():
    # Generiranje žiro računa
    account_number = str(randint(1110000000000000000, 1119999999999999999))
    return account_number


def admin_register():
    # Vars
    global temp_name
    global temp_lastname
    global temp_age
    global temp_gender
    global temp_password
    global notif
    global temp_status
    global temp_email
    global admin_key
    global korisnik
    global key
    global temp_key
    temp_status = StringVar()
    temp_name = StringVar()
    temp_lastname = StringVar()
    temp_age = StringVar()
    temp_gender = StringVar()
    temp_password = StringVar()
    temp_email = StringVar()
    temp_key = StringVar()
    admin_key = StringVar()
    korisnik = StringVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    register_screen = Toplevel(master)
    register_screen.title('REGISTRACIJA')
    register_screen.iconbitmap('secure1.ico')
    register_screen.geometry("650x400")
    Label(register_screen, text="POPUNITE PODATKE POTREBNE ZA REGISTRACIJU ADMIN RAČUNA: ", font=('Calibri', 17),fg="orange").grid(
        row=0, sticky=N, pady=10)
    Label(register_screen, text="IME :", font=('Calibri', 14),fg="orange").grid(row=1, sticky=W)
    Label(register_screen, text="PREZIME :", font=('Calibri', 14),fg="orange").grid(row=2, sticky=W)
    Label(register_screen, text="GODINE: ", font=('Calibri', 14),fg="orange").grid(row=3, sticky=W)
    Label(register_screen, text="SPOL: ", font=('Calibri', 14),fg="orange").grid(row=4, sticky=W)
    Label(register_screen, text="PIN: ", font=('Calibri', 14),fg="orange").grid(row=5, sticky=W)
    Label(register_screen, text="E-MAIL: ", font=('Calibri', 14),fg="orange").grid(row=6, sticky=W)
    Label(register_screen, text="KLJUC ZA ADMIN KORISNIKE:", font=('Calibri', 14),fg="orange").grid(row=7, sticky=W)

    notif = Label(register_screen, font=('Calibri', 12))
    notif.grid(row=13, sticky=N, pady=10)

    Entry(register_screen, textvariable=temp_name).grid(row=1, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_lastname).grid(row=2, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_age).grid(row=3, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_gender).grid(row=4, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_password, show="*").grid(row=5, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_email).grid(row=6, column=0, padx=(135, 0))
    Entry(register_screen, textvariable=temp_key, show="*").grid(row=7, column=0, padx=(135, 0))
    Label(register_screen, text="Status: ").grid(row=10, column=0)
    Radiobutton(register_screen, text="Zaposlen", variable=temp_status, value="Zaposlen").grid(row=11, column=0,
                                                                                               sticky=W)
    Radiobutton(register_screen, text="Penzioner", variable=temp_status, value="Penzioner").grid(row=11, column=0,
                                                                                                 sticky=N)
    Radiobutton(register_screen, text="Student", variable=temp_status, value="Student").grid(row=11, column=0, sticky=E)
    Button(register_screen, text="Registruj me!", command=provjera_1, font=('Calibri', 12)).grid(row=8, sticky=N, pady=10)


def provjera_1():
    entered_key = temp_key.get()
    if entered_key == "abcdefg":
        # Kljuc je ispravan, dopusti registraciju
        admin_finish_reg()
    else:
        # Kljuc nije ispravan, prikaži poruku korisniku
        notif.config(text="Neispravan admin ključ. Registracija nije uspjela.", fg="red")


def login():
    global temp_login_name
    global temp_login_password
    global login_notif
    global login_notif1
    global login_screen
    temp_login_name = StringVar()
    temp_login_password = StringVar()
    login_screen = Toplevel(master)
    login_screen.title('PRIJAVA')
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    login_screen.iconbitmap('secure1.ico')
    Label(login_screen, text="Dobar dan!", font=('Calibri', 12)).grid(row=0, sticky=N, pady=10)
    Label(login_screen, text="Unesite ime: ", font=('Calibri', 12)).grid(row=1, sticky=W)
    Label(login_screen, text="Unesite PIN: ", font=('Calibri', 12)).grid(row=2, sticky=W)
    login_notif = Label(login_screen, font=('Calibri', 12))
    login_notif.grid(row=5, sticky=N)
    Entry(login_screen, textvariable=temp_login_name).grid(row=1, column=1, padx=5)
    Entry(login_screen, textvariable=temp_login_password, show="*").grid(row=2, column=1, padx=5)
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    Button(login_screen, text="Uloguj se!", command=login_sesija, width=15, font=('Calibri', 12)).grid(row=4, sticky=W,pady=5, padx=5)


def admin_login():
    global temp_login_name
    global temp_login_password
    global login_notif
    global login_notif1
    global login_screen
    temp_login_name = StringVar()
    temp_login_password = StringVar()
    login_screen = Toplevel(master)
    login_screen.title('ADMIN PRIJAVA')
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    login_screen.iconbitmap('secure1.ico')
    Label(login_screen, text="Dobar dan!", font=('Calibri', 12)).grid(row=0, sticky=N, pady=10)
    Label(login_screen, text="Unesite ime: ", font=('Calibri', 12)).grid(row=1, sticky=W)
    Label(login_screen, text="Unesite PIN: ", font=('Calibri', 12)).grid(row=2, sticky=W)
    login_notif = Label(login_screen, font=('Calibri', 12))
    login_notif.grid(row=5, sticky=N)
    Entry(login_screen, textvariable=temp_login_name).grid(row=1, column=1, padx=5)
    Entry(login_screen, textvariable=temp_login_password, show="*").grid(row=2, column=1, padx=5)
    Button(login_screen, text="Uloguj se!", command=admin_login_session, width=15, font=('Calibri', 12)).grid(row=4,sticky=W,pady=5,padx=5)


def prikazi_korsinike():
    global login_name
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    login_name = temp_login_name.get()
    prikazi_korisnike_screen = Toplevel(master)
    prikazi_korisnike_screen.geometry("270x170")
    prikazi_korisnike_screen.title('Svi korisnici')
    scrollbar = Scrollbar(prikazi_korisnike_screen)
    scrollbar.pack(side=RIGHT, fill=Y)
    mylist = Listbox(prikazi_korisnike_screen, yscrollcommand=scrollbar.set)
    Label(prikazi_korisnike_screen, text="Lista svih korisnika banke: ", font=('Calibri', 12))
    brojac = 1
    for name in all_accounts:
        if name == "NE BRISATI!":
            continue
        file = open(name, "r")
        file_data = file.read()
        file_data = dekriptuj(file_data)
        file_data = file_data.split('\n')
        ime_korisnika = file_data[0]
        prezime_korisnika = file_data[1]
        mylist.insert(END, "Korisnik " + str(brojac) + ": " + ime_korisnika + " " + prezime_korisnika + '\n')
        brojac += 1

    mylist.pack(side=TOP, fill=BOTH)
    scrollbar.config(command=mylist.yview)

def sigurnosni_kod_prozor():
    global kod
    global uneseni_kod
    global ime
    uneseni_kod = StringVar()
    ime = temp_login_name.get()
    kod = StringVar()
    sigurnosni_kod_prozor_screen = Toplevel(master)
    sigurnosni_kod_prozor_screen.geometry("650x300")
    Label(sigurnosni_kod_prozor_screen, text="Na Vas korisnicki racun je unesen pogresan PIN 3 puta", font=('Calibri', 12)).grid(row=0, sticky=N, pady=10)
    Label(sigurnosni_kod_prozor_screen, text="Unesite sigurnosni kod koji Vam je poslan na mail kako biste otključali račun: ", font=('Calibri', 12)).grid(row=1, sticky=N, pady=10)
    Entry(sigurnosni_kod_prozor_screen, textvariable=uneseni_kod).grid(row=4, column=1, padx=5,sticky=W)
    Button(sigurnosni_kod_prozor_screen, text="POTVRDI", command=provjera, width=15, font=('Calibri', 12)).grid(row=5,sticky=W,pady=5,padx=5)


def provjera():
    global ime
    global kod
    global kod_iz_fajla
    global uneseni_kod
    kod = uneseni_kod.get()
    ime = temp_login_name.get()
    kod_iz_fajla = StringVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Sigurnosni kod')
    fajl = open(sifruj_poruku(ime), "r")
    fajl = fajl.read()
    fajl = fajl.split('\n')
    kod_iz_fajla = fajl[0]
    print(kod)
    if kod == kod_iz_fajla:
        os.remove(sifruj_poruku(ime))
        login()


def login_sesija():
    global login_name
    global login_password
    brojac = 0
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Sigurnosni kod')
    all_accounts = os.listdir()
    login_name = temp_login_name.get()
    login_password = temp_login_password.get()
    for name in all_accounts:
        if desifruj_poruku(name) == login_name:
            brojac = brojac + 1
    if brojac>0:
        sigurnosni_kod_prozor()
    else:
        login_session()


def login_session():
    global login_name
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    login_name = temp_login_name.get()
    login_password = temp_login_password.get()

    for name_1 in all_accounts:
        print((name_1))
        if desifruj_poruku(name_1) == login_name:
            file = open((name_1), "r")
            file_data = file.read()
            file_data = dekriptuj(file_data)
            fajl = file_data.split('\n')
            password = fajl[2]
            broj_racuna = fajl[7]
            pol = fajl[4]
            file.close()
            if login_password == password:
                login_screen.destroy()
                account_dashboard = Toplevel(master)
                account_dashboard.title('Dashboard')
                account_dashboard.geometry("400x480")
                file = open((name_1), "r")
                file_data = file.read()
                file_data = dekriptuj(file_data)
                file_data = file_data.split('\n')
                file.close()
                os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Stanja racuna')
                file = open((name_1), "r")
                file_data = file.read()
                file_data = dekriptuj(file_data)
                file_data = file_data.split('\n')
                stanje_racuna = file_data[0]
                print(stanje_racuna)
                Label(account_dashboard, text="Account Dashboard", font=('Calibri', 12)).grid(row=0, sticky=N, pady=10)
                if (pol == "Muski"):
                    Label(account_dashboard, text="Dobro dosao, " + desifruj_poruku(name_1), font=('Calibri', 12)).grid(
                        row=1, sticky=W, pady=10)
                if (pol == "Zenski"):
                    Label(account_dashboard, text="Dobro dosla, " + desifruj_poruku(name_1), font=('Calibri', 12)).grid(
                        row=1, sticky=W, pady=10)
                current_date_time = datetime.now()
                danas = datetime.now()
                formatted_date_time = current_date_time.strftime("%d.%m.%Y %H:%M:%S")
                Label(account_dashboard, text="Trenutni datum i vrijeme: " + formatted_date_time,
                      font=('Calibri', 12)).grid(row=2, sticky=W, pady=10)
                Label(account_dashboard, text="Vas broj racuna: " + broj_racuna, font=('Calibri', 12)).grid(row=3, sticky=W,pady=10)
                if int(stanje_racuna) >= 0:
                    Label(account_dashboard, text="Stanje racuna: " + stanje_racuna, font=('Calibri', 12),
                          fg="green").grid(row=4, sticky=W, pady=10)
                else:
                    Label(account_dashboard, text="Stanje racuna: " + stanje_racuna, font=('Calibri', 12),
                          fg="red").grid(row=4, sticky=W, pady=10)
                Button(account_dashboard, text="Podaci o korisniku", font=('Calibri', 12), width=30,
                       command=personal_details).grid(row=5, sticky=N, padx=10)
                Button(account_dashboard, text="Placanje", font=('Calibri', 12), width=30, command=placanje).grid(row=6,sticky=N,padx=10)
                Button(account_dashboard, text="Promijeni lozinku", font=('Calibri', 12), width=30,
                       command=promjena_lozinke).grid(row=8, sticky=N, padx=10)
                Button(account_dashboard, text="Odjavi se!", font=('Calibri', 12), width=30,
                       command=account_dashboard.destroy).grid(row=13, sticky=N, padx=10)
                Label(account_dashboard).grid(row=9, sticky=N, pady=10)

            else:
                global broj_logiranja
                global pomocna
                broj_logiranja -= 1
                if (broj_logiranja == 0):
                    global email
                    global user_details
                    global random_string
                    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
                    file = open(sifruj_poruku(login_name), 'r')
                    file_data = file.read()
                    file_data = dekriptuj(file_data)
                    user_details = file_data.split('\n')
                    email = user_details[6]
                    slova = string.ascii_letters + string.digits  # Generiše string od slova i brojeva
                    random_string = ''.join(random.choice(slova) for i in range(5))
                    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Sigurnosni kod')
                    fajl_kod = open(name_1,"w")
                    fajl_kod.write(random_string)
                    global pomocna
                    smtp_server = 'smtp.gmail.com'
                    smtp_port = 587
                    smtp_username = 'Nothing for hackers'
                    smtp_password = 'Nothing for hackers'
                    from_email = email
                    to_email = email
                    subject = 'Neuspjeli pokusaj logiranja'
                    body = f'Postovani,\n\nUnesen je pogresan PIN 3 puta prilikom logiranja na ovaj korisnicki racun. Ukoliko ste to Vi, Vas sigurnosni kod je {random_string}. Ukoliko niste molimo da ODMAH kontaktirate poslovnicu banke.\nPozdrav,\nBanka ETF'

                    message = f'Subject: {subject}\n\n{body}'

                    with smtplib.SMTP(smtp_server, smtp_port) as smtp:
                        smtp.starttls()
                        smtp.login(smtp_username, smtp_password)
                        smtp.sendmail(from_email, to_email, message)
                    broj_logiranja = 3
                    pomocna = 1
                if (pomocna == 1):
                    login_notif.config(fg="red",
                                       text="Unijeli ste pogresan PIN 3 puta!\nSigurnosno obavjestenje je poslano na mail korisnika!")
                    pomocna = 0
                else:
                    login_notif.config(fg="red", text="Pogresan PIN!\nPreostali broj dozvoljenih pokušaja: " + str(
                        broj_logiranja))
            return
    login_notif.config(fg="red", text="Korisnicki racun nije pronadjen!")


def modifikuj_korisnika():
    global ime
    global prezime
    global podaci_korisnika
    global podaci_korisnika_1
    global podaci_korisnika_2
    global podaci_korisnika_3
    global podaci_korisnika_4
    global podaci_korisnika_5
    global podaci_korisnika_6
    ime = StringVar()
    prezime = StringVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    modifikuj_korisnika_screen = Toplevel(master)
    modifikuj_korisnika_screen.geometry("800x530")
    modifikuj_korisnika_screen.title('MODIFIKUJ KORISNIKA')
    Label(modifikuj_korisnika_screen, text="Unesite ime korisnika: ", font=('Calibri', 12)).grid(
        row=1, sticky=W, pady=10)
    Entry(modifikuj_korisnika_screen, textvariable=ime).grid(row=1, column=1, padx=5)
    Label(modifikuj_korisnika_screen, text="Unesite prezime korisnika: ", font=('Calibri', 12)).grid(
        row=2, sticky=W, pady=10)
    Entry(modifikuj_korisnika_screen, textvariable=prezime).grid(row=2, column=1, padx=5)
    Button(modifikuj_korisnika_screen, text="Pronadji korisnika", font=('Calibri', 12), width=30,command=pronadji).grid(row=4, sticky=N, padx=10)
    podaci_korisnika = Label(modifikuj_korisnika_screen,font=('Calibri', 12))
    podaci_korisnika.grid(row=5, column=1, padx=5)
    podaci_korisnika_1 = Label(modifikuj_korisnika_screen,font=('Calibri', 12))
    podaci_korisnika_1.grid(row=6, column=1, padx=5)
    podaci_korisnika_2 = Label(modifikuj_korisnika_screen,font=('Calibri', 12))
    podaci_korisnika_2.grid(row=7, column=1, padx=5)
    podaci_korisnika_3 = Label(modifikuj_korisnika_screen,font=('Calibri', 12))
    podaci_korisnika_3.grid(row=8, column=1, padx=5)
    podaci_korisnika_4 = Label(modifikuj_korisnika_screen,font=('Calibri', 12))
    podaci_korisnika_4.grid(row=9, column=1, padx=5)
    podaci_korisnika_5 = Label(modifikuj_korisnika_screen,font=('Calibri', 12))
    podaci_korisnika_5.grid(row=10, column=1, padx=5)
    podaci_korisnika_6 = Label(modifikuj_korisnika_screen, font=('Calibri', 12))
    podaci_korisnika_6.grid(row=11, column=1, padx=5)
    Button(modifikuj_korisnika_screen, text="Promijeni PIN", font=('Calibri', 12), width=30,command=promijeni_PIN).grid(row=14, sticky=N)
    Button(modifikuj_korisnika_screen, text="Promijeni datum rodjenja", font=('Calibri', 12), width=30,command=promijeni_datum_rodjenja).grid(row=15, sticky=N)
    Button(modifikuj_korisnika_screen, text="Promijeni status", font=('Calibri', 12), width=30,command=promijeni_status).grid(row=16, sticky=N)
    Button(modifikuj_korisnika_screen, text="Promijeni e-mail", font=('Calibri', 12), width=30,command=promijeni_e_mail).grid(row=17, sticky=N)

def promijeni_ime():
    global novo_ime
    novo_ime = StringVar()
    promijeni_ime_screen = Toplevel(master)
    promijeni_ime_screen.geometry("400x430")
    promijeni_ime_screen.title('PROMJENA IMENA')
    Label(promijeni_ime_screen, text="Unesite novo ime korisnika: ", font=('Calibri', 12)).grid(row=1, sticky=W, pady=10)
    Entry(promijeni_ime_screen, textvariable=novo_ime).grid(row=2, column=1, padx=5)
    Button(promijeni_ime_screen, text="Promijeni ime!", font=('Calibri', 12), width=30,command=promjena_imena).grid(row=3, sticky=N)

def promjena_imena():
    global novo_ime_korisnika
    global ime_korisnika_1
    novo_ime_korisnika = novo_ime.get()
    ime_korisnika_1 = ime.get()
    fajl = open(sifruj_poruku(ime_korisnika_1), "r+")
    fajl_data = fajl.read()
    fajl_data = dekriptuj(fajl_data)
    fajl_data = fajl_data.split('\n')
    print(novo_ime_korisnika)
    fajl_data[0] = novo_ime_korisnika
    fajl_data = '\n'.join(fajl_data)
    fajl.close()
    os.remove(sifruj_poruku(ime_korisnika_1))
    file = open(sifruj_poruku(novo_ime_korisnika),"wb")
    fajl_data = enkriptuj(fajl_data)
    file.write(fajl_data)
    file.close()
    novo = open(sifruj_poruku(novo_ime_korisnika),"r")
    novo = novo.read()


def promijeni_PIN():
    global novi_pin
    novi_pin = StringVar()
    promijeni_ime_screen = Toplevel(master)
    promijeni_ime_screen.geometry("400x430")
    promijeni_ime_screen.title('PROMJENA PIN-A')
    Label(promijeni_ime_screen, text="Unesite novi PIN korisnika: ", font=('Calibri', 12)).grid(row=1, sticky=W,pady=10)
    Entry(promijeni_ime_screen, textvariable=novi_pin).grid(row=2, column=1, padx=5)
    Button(promijeni_ime_screen, text="Promijeni PIN!", font=('Calibri', 12), width=30,command=promjena_pina).grid(row=3, sticky=N)



def promjena_pina():
    global novi_pin_1
    global ime_korisnika_1
    novi_pin_1 = novi_pin.get()
    ime_korisnika_1 = ime.get()
    fajl = open(sifruj_poruku(ime_korisnika_1), "r+")
    fajl_data = fajl.read()
    fajl_data = dekriptuj(fajl_data)
    fajl_data = fajl_data.split('\n')
    fajl_data[2] = novi_pin_1
    fajl_data = '\n'.join(fajl_data)
    fajl.close()
    os.remove(sifruj_poruku(ime_korisnika_1))
    file = open(sifruj_poruku(ime_korisnika_1), "wb")
    fajl_data = enkriptuj(fajl_data)
    file.write(fajl_data)
    file.close()
    novo = open(sifruj_poruku(ime_korisnika_1), "r")
    novo = novo.read()

def promijeni_datum_rodjenja():
    global novi_datum
    novi_datum = StringVar()
    promijeni_ime_screen = Toplevel(master)
    promijeni_ime_screen.geometry("400x430")
    promijeni_ime_screen.title('PROMJENA DATUMA RODJENJA')
    Label(promijeni_ime_screen, text="Unesite novi datum rodjenja korisnika: ", font=('Calibri', 12)).grid(row=1, sticky=W,pady=10)
    Entry(promijeni_ime_screen, textvariable=novi_datum).grid(row=2, column=1, padx=5)
    Button(promijeni_ime_screen, text="Promijeni datum rodjenja!", font=('Calibri', 12), width=30, command=promjena_datuma).grid(row=3, sticky=N)
    return
def promjena_datuma():
    global novi_datum_1
    global ime_korisnika_1
    novi_datum_1 = novi_datum.get()
    ime_korisnika_1 = ime.get()
    fajl = open(sifruj_poruku(ime_korisnika_1), "r+")
    fajl_data = fajl.read()
    fajl_data = dekriptuj(fajl_data)
    fajl_data = fajl_data.split('\n')
    fajl_data[3] = novi_datum_1
    fajl_data = '\n'.join(fajl_data)
    fajl.close()
    os.remove(sifruj_poruku(ime_korisnika_1))
    file = open(sifruj_poruku(ime_korisnika_1), "wb")
    fajl_data = enkriptuj(fajl_data)
    file.write(fajl_data)
    file.close()
    novo = open(sifruj_poruku(ime_korisnika_1), "r")
    novo = novo.read()
    return
def promijeni_status():
    global temp_status
    temp_status = StringVar()
    promijeni_status_screen = Toplevel(master)
    promijeni_status_screen.geometry("400x430")
    promijeni_status_screen.title('PROMJENA STATUSA KORISNIKA')
    Label(promijeni_status_screen, text="Izaberite novi status korisnika: ").grid(row=1, column=0)
    Radiobutton(promijeni_status_screen, text="Zaposlen", variable=temp_status, value="Zaposlen").grid(row=2, column=0)
    Radiobutton(promijeni_status_screen, text="Penzioner", variable=temp_status, value="Penzioner").grid(row=3, column=0)
    Radiobutton(promijeni_status_screen, text="Student", variable=temp_status, value="Student").grid(row=4, column=0)
    Button(promijeni_status_screen, text="Promijeni status korisnika!", font=('Calibri', 12), width=30, command=promjena_statusa).grid(row=6, sticky=N)
    return

def promjena_statusa():
    global novi_status_1
    global ime_korisnika_1
    novi_status_1 = temp_status.get()
    ime_korisnika_1 = ime.get()
    fajl = open(sifruj_poruku(ime_korisnika_1), "r+")
    fajl_data = fajl.read()
    fajl_data = dekriptuj(fajl_data)
    fajl_data = fajl_data.split('\n')
    fajl_data[4] = novi_status_1
    fajl_data = '\n'.join(fajl_data)
    fajl.close()
    os.remove(sifruj_poruku(ime_korisnika_1))
    file = open(sifruj_poruku(ime_korisnika_1), "wb")
    fajl_data = enkriptuj(fajl_data)
    file.write(fajl_data)
    file.close()
    novo = open(sifruj_poruku(ime_korisnika_1), "r")
    novo = novo.read()
    return

def promijeni_e_mail():
    global novi_email
    novi_email = StringVar()
    promijeni_ime_screen = Toplevel(master)
    promijeni_ime_screen.geometry("400x430")
    promijeni_ime_screen.title('PROMJENA E-MAILA')
    Label(promijeni_ime_screen, text="Unesite novi e-mail korisnika: ", font=('Calibri', 12)).grid(row=1, sticky=W, pady=10)
    Entry(promijeni_ime_screen, textvariable=novi_email).grid(row=2, column=1, padx=5)
    Button(promijeni_ime_screen, text="Promijeni email!", font=('Calibri', 12), width=30, command=promjena_emaila).grid(row=3, sticky=N)


def promjena_emaila():
    global novi_email_1
    global ime_korisnika_1
    novi_email_1 = novi_email.get()
    ime_korisnika_1 = ime.get()
    fajl = open(sifruj_poruku(ime_korisnika_1), "r+")
    fajl_data = fajl.read()
    fajl_data = dekriptuj(fajl_data)
    fajl_data = fajl_data.split('\n')
    fajl_data[6] = novi_email_1
    fajl_data = '\n'.join(fajl_data)
    fajl.close()
    os.remove(sifruj_poruku(ime_korisnika_1))
    file = open(sifruj_poruku(ime_korisnika_1), "wb")
    fajl_data = enkriptuj(fajl_data)
    file.write(fajl_data)
    file.close()
    novo = open(sifruj_poruku(ime_korisnika_1), "r")
    novo = novo.read()


def pronadji():
    global podaci_korisnika
    global ime_korisnika
    ime_korisnika = ime.get()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    korisnici = os.listdir()
    for name in korisnici:
        if desifruj_poruku(name) == ime_korisnika:
            global podaci_korisnika
            global podaci_korisnika_1
            global podaci_korisnika_2
            global podaci_korisnika_3
            global podaci_korisnika_4
            global podaci_korisnika_5
            global podaci_korisnika_6
            fajl = open(sifruj_poruku(ime_korisnika),"r")
            fajl = fajl.read()
            fajl = dekriptuj(fajl)
            fajl = fajl.split('\n')
            podaci_korisnika.config(fg="green",text = "Ime i prezime korisnika: "+ fajl[0] + " " + fajl[1])
            podaci_korisnika_1.config(fg="green",text = "PIN korisnika: "+ fajl[2])
            podaci_korisnika_2.config(fg="green",text = "Datum rodjenja korisnika: "+ fajl[3])
            podaci_korisnika_3.config(fg="green",text = "Spol korisnika: "+ fajl[4])
            podaci_korisnika_4.config(fg="green",text = "Status korisnika: "+ fajl[5])
            podaci_korisnika_5.config(fg="green",text = "E-mail korisnika: "+ fajl[6])
            podaci_korisnika_6.config(fg="green",text = "Broj racuna korisnika: "+ fajl[7])




        #else:
            #podaci_korisnika.config(fg="red",text="Nepostojeci korisnik!")
def admin_login_session():
    global login_name
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Admin korisnici')
    all_accounts = os.listdir()
    login_name = temp_login_name.get()
    login_password = temp_login_password.get()
    for name in all_accounts:
        if desifruj_poruku(name) == login_name:
            file = open(name, "r")
            file_data = file.read()
            file_data = dekriptuj(file_data)
            file_data = file_data.split('\n')
            password = file_data[3]
            admin_kljuc = file_data[0]
            if (admin_kljuc != "abcdefg"):
                login_notif.config(fg="red", text="Pogresan username i/ili PIN ili nepostojeci racun!")
                return
            if login_password == password:
                login_screen.destroy()
                account_dashboard = Toplevel(master)
                account_dashboard.title('Admin dashboard')
                account_dashboard.geometry("400x480")
                pol = file_data[5]
                Label(account_dashboard, text="Account Dashboard", font=('Calibri', 12)).grid(row=0, sticky=N, pady=10)
                if (pol == "Muski"):
                    Label(account_dashboard, text="Dobro dosao, " + desifruj_poruku(name), font=('Calibri', 12)).grid(
                        row=1, sticky=W, pady=10)
                if (pol == "Zenski"):
                    Label(account_dashboard, text="Dobro dosla, " + desifruj_poruku(name), font=('Calibri', 12)).grid(
                        row=1, sticky=W, pady=10)
                current_date_time = datetime.now()
                danas = datetime.now()
                formatted_date_time = current_date_time.strftime("%d.%m.%Y %H:%M:%S")
                Label(account_dashboard, text="Trenutni datum i vrijeme: " + formatted_date_time,
                      font=('Calibri', 12)).grid(row=2, sticky=W, pady=10)
                Button(account_dashboard, text="Modifikuj korisnika", font=('Calibri', 12), width=30,
                       command=modifikuj_korisnika).grid(row=5, sticky=N, padx=10)
                Button(account_dashboard, text="Prikazi korisnike", font=('Calibri', 12), width=30,
                       command=prikazi_korsinike).grid(row=6, sticky=N, padx=10)
                Button(account_dashboard, text="Upravljanje stanjem", font=('Calibri', 12), width=30,
                       command=upravljanje_stanjem).grid(row=7, sticky=N, padx=10)
               # Button(account_dashboard, text="Promijeni lozinku", font=('Calibri', 12), width=30,
                 #      ).grid(row=8, sticky=N, padx=10)
                Button(account_dashboard, text="Odjavi se!", font=('Calibri', 12), width=30,
                       command=account_dashboard.destroy).grid(row=14, sticky=N, padx=10)
                Label(account_dashboard).grid(row=8, sticky=N, pady=10)

            else:
                global broj_logiranja
                global pomocna
                global ime_korisnika
                ime_korisnika = temp_login_name.get()
                print(broj_logiranja)
                broj_logiranja -= 1;
                if (broj_logiranja == 0):
                    global email
                    global user_details
                    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Admin korisnici')
                    file_data = open(sifruj_poruku(ime_korisnika), "r+")
                    data = file_data.read()
                    data = dekriptuj(data)
                    data = data.split('\n')
                    email = data[7]
                    slova = string.ascii_letters + string.digits  # Generiše string od slova i brojeva
                    random_string = ''.join(random.choice(slova) for i in range(10))
                    global pomocna
                    smtp_server = 'smtp.gmail.com'
                    smtp_port = 587
                    smtp_username = 'Nothing for hackers'
                    smtp_password = 'Nothing for hackers'

                    from_email = email
                    to_email = email
                    subject = 'Neuspjeli pokusaj logiranja'
                    body = f'Postovani,\n\nUnesen je pogresan PIN 3 puta prilikom logiranja na ovaj korisnicki racun. Ukoliko niste molimo da ODMAH kontaktirate poslovnicu banke.\nPozdrav,\nBanka ETF'

                    message = f'Subject: {subject}\n\n{body}'

                    with smtplib.SMTP(smtp_server, smtp_port) as smtp:
                        smtp.starttls()
                        smtp.login(smtp_username, smtp_password)
                        smtp.sendmail(from_email, to_email, message)
                    broj_logiranja = 3
                    pomocna = 1

                if (pomocna == 1):
                    login_notif.config(fg="red",
                                       text="Unijeli ste pogresan PIN 3 puta!\nSigurnosno obavjestenje je poslano na mail korisnika!")
                    pomocna = 0
                else:
                    login_notif.config(fg="red", text="Pogresan PIN!\nPreostali broj dozvoljenih pokušaja: " + str(
                        broj_logiranja))
            return
    login_notif.config(fg="red", text="Korisnicki racun nije pronadjen!")


def placanje():
    global upravljanje_notif
    global upravljanje_notif1
    global ime
    global prezime
    global broj_racuna
    global uplata
    uplata = IntVar()
    ime = StringVar()
    prezime = StringVar()
    broj_racuna = IntVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    placanje_screen = Toplevel(master)
    placanje_screen.title('Placanje')
    placanje_screen.geometry("600x400")
    Label(placanje_screen, text="Unesite ime primaoca: ", font=('Calibri', 12)).grid(row=1, sticky=W, pady=10)
    Label(placanje_screen, text="Unesite prezime primaoca: ", font=('Calibri', 12)).grid(row=2, sticky=W, pady=10)
    Entry(placanje_screen, textvariable=ime).grid(row=1, column=1, padx=5)
    Entry(placanje_screen, textvariable=prezime).grid(row=2, column=1, padx=5)
    #Entry(placanje_screen, textvariable=broj_racuna).grid(row=3, column=1, padx=5)
    Button(placanje_screen, text="Pronadji korisnika!", command=nadji_korisnika, width=15, font=('Calibri', 12)).grid(
        row=4, sticky=W, pady=5, padx=5)
    upravljanje_notif = Label(placanje_screen, font=('Calibri', 12))
    upravljanje_notif.grid(row=7, sticky=W)
    upravljanje_notif1 = Label(placanje_screen, font=('Calibri', 12))
    Label(placanje_screen, text="Unesite visinu uplate na racun korisnika: ", font=('Calibri', 12)).grid(row=9,sticky=W,pady=10)
    Entry(placanje_screen, textvariable=uplata).grid(row=9, column=1, padx=5)
    Button(placanje_screen, text="Uplati!", command=jednokratna_sifra, width=15, font=('Calibri', 12)).grid(row=10,sticky=N,pady=5,padx=5)

def slanje_sifre_na_mail():
    global slova
    global email
    global ime_korisnika
    ime_korisnika = temp_login_name.get()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    file_data = open(sifruj_poruku(ime_korisnika), "r+")
    data = file_data.read()
    data = dekriptuj(data)
    data = data.split('\n')
    email = data[6]
    #email = 'ebalihodzi1@etf.unsa.ba'
    sifra = StringVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Jednokratne sifre')
    slova = string.ascii_letters + string.digits  # Generiše string od slova i brojeva
    sifra = ''.join(random.choice(slova) for i in range(4))

    file = open(ime_korisnika, "w")
    file.write(sifra)
    file.close()
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'Nothing for hackers'
    smtp_password = 'Nothing for hackers'
    from_email = email
    to_email = email
    subject = 'Sigurnosna provjera za uplatu'
    body = f'Postovani,\n\nSigurnosna sifra za Vasu transakciju je: {sifra}'
    message = f'Subject: {subject}\n\n{body}'

    with smtplib.SMTP(smtp_server, smtp_port) as smtp:
        smtp.starttls()
        smtp.login(smtp_username, smtp_password)
        smtp.sendmail(from_email, to_email, message)

def jednokratna_sifra():
    global sifra
    global random_string
    global ime_korisnika
    sifra = StringVar()
    ime_korisnika = ime.get()
    jednokratna_sifra_screen = Toplevel(master)
    jednokratna_sifra_screen.title('Jednokratna sifra')
    jednokratna_sifra_screen.geometry("600x200")
    slanje_sifre_na_mail()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Jednokratne sifre')
    Label(jednokratna_sifra_screen, text="Unesite jednokratnu šifru koja Vam je poslana na mail:  ",
          font=('Calibri', 12)).grid(row=4, sticky=W, pady=10)
    Entry(jednokratna_sifra_screen, textvariable=sifra).grid(row=5, column=1, padx=5)
    Button(jednokratna_sifra_screen, text="Potvrdi", command=unos_sifre, width=15, font=('Calibri', 12)).grid(row=7,sticky=N,pady=5,padx=5)

def unos_sifre():
    global unesena_sifra
    global ime_korisnika
    global unesena_sifra
    ime_korisnika = temp_login_name.get()
    unesena_sifra = sifra.get()
    file = open(ime_korisnika, "r")
    file_data = file.read()
    if (unesena_sifra == file_data):
        uplati()
    else:
        print("Unesena je neispravna sifra")


def upravljanje_stanjem():
    global ime
    global prezime
    global broj_racuna
    global upravljanje_notif
    global upravljanje_notif1
    global uplata
    global unos
    uplata = IntVar()
    broj_racuna = StringVar()
    ime = StringVar()
    prezime = StringVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    login_name = temp_login_name.get()
    upravljanje_stanjem_screen = Toplevel(master)
    upravljanje_stanjem_screen.title('Upravljanje stanjem')
    upravljanje_stanjem_screen.geometry("660x400")
    Label(upravljanje_stanjem_screen, text="Unesite ime korisnika: ", font=('Calibri', 12)).grid(row=0, sticky=E,pady=10)
    Label(upravljanje_stanjem_screen, text="Unesite prezime korisnika: ", font=('Calibri', 12)).grid(row=1, sticky=E,pady=10)
    Entry(upravljanje_stanjem_screen, textvariable=ime).grid(row=0, column=1, padx=5)
    Entry(upravljanje_stanjem_screen, textvariable=prezime).grid(row=1, column=1, padx=5)
    Button(upravljanje_stanjem_screen, text="Pronadji korisnika!", command=nadji_korisnika, width=15,font=('Calibri', 12)).grid(row=4, sticky=W, pady=5, padx=5)
    upravljanje_notif = Label(upravljanje_stanjem_screen, font=('Calibri', 12))
    upravljanje_notif.grid(row=5, sticky=W)
    upravljanje_notif1 = Label(upravljanje_stanjem_screen, font=('Calibri', 12))
    upravljanje_notif1.grid(row=6, sticky=W)
    Label(upravljanje_stanjem_screen, text="Unesite visinu uplate na racun korisnika: ", font=('Calibri', 12)).grid(row=9, sticky=W, pady=10)
    Entry(upravljanje_stanjem_screen, textvariable=uplata).grid(row=9, column=1, padx=5)
    Button(upravljanje_stanjem_screen, text="Uplati!", command=admin_uplati, width=15, font=('Calibri', 12)).grid(row=10,sticky=N,pady=5,padx=5)

def uplati():
    global login_name
    global stanje
    global unos
    global linije
    global email
    global novo
    novo = StringVar()
    email = StringVar()
    stanje = StringVar()
    pare = uplata.get()
    login_name = ime.get()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Stanja racuna')
    all_accounts = os.listdir()
    for name in all_accounts:
        if desifruj_poruku(name) == login_name:
            file_data = open(name, "r+")
            data = file_data.read()
            data = dekriptuj(data)
            data = data.split('\n')
            stanje = data[0]
            print(stanje)
            stanje_1 = int(stanje) + int(pare)
            print(int(stanje) + int(pare))
            print(name)
            new_file = open((name), "wb")
            new_file.write(enkriptuj(str(stanje_1)))
            new_file.close()
            print(ime_uplatioca)
            new_file = open(sifruj_poruku(ime_uplatioca), "r+")
            data = new_file.read()
            data = dekriptuj(data)
            data = data.split('\n')
            stanje = data[0]

            print(stanje)
            novo = int(stanje) - pare
            print(stanje_1)
            print(novo)
            new_file.close()
            novi_fajl = open(sifruj_poruku(ime_uplatioca), "wb")
            novi_fajl.write(enkriptuj(str(novo)))
            novi_fajl.close()
            os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
            file_data = open(name, "r")
            data = file_data.read()
            data = dekriptuj(data)
            data = data.split('\n')
            print(data)
            email = data[6]
            to_email = data[6]
            file_data.close()
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            smtp_username = 'Nothing for hackers'
            smtp_password = 'Nothing for hackers'
            from_email = email
            to_email = email
            subject = 'Uplata'
            body = f'Postovani,\n\nNa Vas racun je upaceno {pare} KM.\nPozdrav,\nOB Banka'
            message = f'Subject: {subject}\n\n{body}'

            with smtplib.SMTP(smtp_server, smtp_port) as smtp:
                smtp.starttls()
                smtp.login(smtp_username, smtp_password)
                smtp.sendmail(from_email, to_email, message)

def admin_uplati():
    global login_name
    global stanje
    global unos
    global linije
    global email
    global novo
    novo = StringVar()
    email = StringVar()
    stanje = StringVar()
    pare = uplata.get()
    login_name = ime.get()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Stanja racuna')
    all_accounts = os.listdir()
    for name in all_accounts:
        if desifruj_poruku(name) == login_name:
            file_data = open(name, "r+")
            data = file_data.read()
            data = dekriptuj(data)
            data = data.split('\n')
            print(data)
            stanje = data[0]
            stanje_1 = int(stanje) + int(pare)
            new_file = open((name), "wb")
            new_file.write(enkriptuj(str(stanje_1)))
            new_file.close()
            os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
            file_data = open(name, "r")
            data = file_data.read()
            data = dekriptuj(data)
            data = data.split('\n')
            email = data[6]
            file_data.close()
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            smtp_username = 'bankaetf@gmail.com'
            smtp_password = 'xetv zdcw kekg nzvf'
            from_email = email
            to_email = email
            subject = 'Uplata'
            body = f'Postovani,\n\nNa Vas racun je upaceno {pare} KM.\n\nPozdrav,\nOB Banka'
            message = f'Subject: {subject}\n\n{body}'

            with smtplib.SMTP(smtp_server, smtp_port) as smtp:
                smtp.starttls()
                smtp.login(smtp_username, smtp_password)
                smtp.sendmail(from_email, to_email, message)


def nadji_korisnika():
    global login_name
    global broj_racuna
    global ime_uplatioca
    global sifra
    global stanje
    ime_uplatioca = temp_login_name.get()
    sifra = StringVar()
    stanje = StringVar()
    broj_racuna = StringVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    login_name = ime.get()
    login_password = temp_login_password.get()
    for name in all_accounts:
        if desifruj_poruku(name) == login_name:
            os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
            file = open(name, "r")
            file_data = file.read()
            file_data = dekriptuj(file_data)
            file_data = file_data.split('\n')
            sifra = file_data[2]
            broj_racuna = file_data[7]
            file.close()
            os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Stanja racuna')
            file = open(name, "r")
            file_data = file.read()
            file_data = dekriptuj(file_data)
            file_data = file_data.split('\n')
            stanje = int(file_data[0][0:])
        upravljanje_notif.config(fg="green", text="Korisnicki racun je pronadjen, broj racuna je : " + str(broj_racuna))
        upravljanje_notif1.config(fg="green", text="Stanje na racunu korisnika je : " + str(stanje))


def promjena_lozinke():
    global novi_pin_1
    global novi_pin_2
    global trenutni_pin
    global promjena_notif
    global login_name
    global login_password
    login_name = temp_login_name.get()
    login_password = temp_login_password.get()
    trenutni_pin = StringVar()
    novi_pin_1 = StringVar()
    novi_pin_2 = StringVar()
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    promjena_lozinke_screen = Toplevel(master)
    promjena_lozinke_screen.title('Promjena lozinke')
    promjena_lozinke_screen.geometry("460x200")
    Label(promjena_lozinke_screen, text="Unesite trenutni PIN: ", font=('Calibri', 12)).grid(row=0, sticky=W, pady=10)
    Label(promjena_lozinke_screen, text="Unesite novi PIN: ", font=('Calibri', 12)).grid(row=1, sticky=W, pady=10)
    Label(promjena_lozinke_screen, text="Potvrdite novi PIN: ", font=('Calibri', 12)).grid(row=2, sticky=W, pady=10)
    Entry(promjena_lozinke_screen, textvariable=trenutni_pin).grid(row=0, column=2, padx=5)
    Entry(promjena_lozinke_screen, textvariable=novi_pin_1, show="*").grid(row=1, column=2, padx=5)
    Entry(promjena_lozinke_screen, textvariable=novi_pin_2, show="*").grid(row=2, column=2, padx=5)
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1')
    dugme = PhotoImage(file="dugme.png")
    Button(promjena_lozinke_screen, text="Promijeni lozinku",command=promjena_lozinke_korisnik, font=('Calibri', 12)).grid(row=5, sticky=N)
    promjena_notif = Label(promjena_lozinke_screen, font=('Calibri', 12))
    promjena_notif.grid(row=6, sticky=W)

def promjena_lozinke_korisnik():
    global novi_pin_11
    global novi_pin_22
    global promjena_notif
    novi_pin_11 = novi_pin_1.get()
    novi_pin_22 = novi_pin_2.get()
    global login_name
    global login_password
    global uneseni_pin
    uneseni_pin = trenutni_pin.get()
    login_name = temp_login_name.get()
    login_password = temp_login_password.get()
    print(login_name)
    print(login_password)
    if uneseni_pin != login_password:
        promjena_notif.config(fg="red", text="Niste unijeli ispravan trenutni PIN!")
        return
    if novi_pin_11 != novi_pin_22:
        promjena_notif.config(fg="red", text="Niste unijeli isti PIN 2 puta! ")
        return
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    fajl = open(sifruj_poruku(login_name), "r+")
    fajl_data = fajl.read()
    fajl_data = dekriptuj(fajl_data)
    fajl_data = fajl_data.split('\n')
    fajl_data[2] = novi_pin_11
    fajl_data = '\n'.join(fajl_data)
    fajl.close()
    os.remove(sifruj_poruku(login_name))
    file = open(sifruj_poruku(login_name), "wb")
    fajl_data = enkriptuj(fajl_data)
    file.write(fajl_data)
    file.close()
    novo = open(sifruj_poruku(login_name), "r")
    novo = novo.read()
    promjena_notif.config(fg="green", text="Uspjesno promijenjen PIN!")




def personal_details():
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    file = open(sifruj_poruku(login_name), 'r')
    file_data = file.read()
    file_data = dekriptuj(file_data)
    user_details = file_data.split('\n')
    details_name = user_details[0]
    details_lastname = user_details[1]
    details_age = user_details[3]
    details_gender = user_details[4]
    details_email = user_details[6]
    details_racun = user_details[7]
    personal_details_screen = Toplevel(master)
    personal_details_screen.title('Podaci o korisniku')
    Label(personal_details_screen, text="Podaci o korisniku", font=('Calibri', 12)).grid(row=0, sticky=N, pady=10)
    Label(personal_details_screen, text="Ime : " + details_name, font=('Calibri', 12)).grid(row=1, sticky=W)
    Label(personal_details_screen, text="Prezime : " + details_lastname, font=('Calibri', 12)).grid(row=2, sticky=W)
    Label(personal_details_screen, text="Godine : " + details_age, font=('Calibri', 12)).grid(row=3, sticky=W)
    Label(personal_details_screen, text="Spol : " + details_gender, font=('Calibri', 12)).grid(row=4, sticky=W)
    Label(personal_details_screen, text="E-mail korisnika :" + details_email, font=('Calibri', 12)).grid(row=6,sticky=W)
    Label(personal_details_screen, text="Broj racuna :" + details_racun, font=('Calibri', 12)).grid(row=7,sticky=W)

# Image import
img = Image.open('secure1.png')
img = img.resize((300, 300))
img = ImageTk.PhotoImage(img)
master.iconbitmap('secure1.ico')
master.geometry("300x500")
dugme = PhotoImage(file="dugme.png")
Label(master, image=img).grid(row=2, sticky=N, pady=15)
Button(master, text="Registracija", font=('Segoe UI Semibold', 15),borderwidth=0, command=odabir_register,image=dugme,compound="center",fg="#%02x%02x%02x" % (240,240,240)).grid(row=4, sticky=N)
Button(master, text="Prijava", font=('Segoe UI Semibold', 15),borderwidth=0, command=odabir_login,image=dugme,compound="center",fg="#%02x%02x%02x" % (240,240,240)).grid(row=6, sticky=N)

master.mainloop()
