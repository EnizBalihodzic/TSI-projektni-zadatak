from tkinter import *
from datetime import datetime
from random import randint
from cryptography.fernet import Fernet
import os
import smtplib
import random
import string


global key
key = b'5zIvqVejFHSBZlS8gmWYvJ7z8EDuCFgvenloiomROTY='
cipher_suite = Fernet(key)
global dugme


def enkriptuj(ulaz):
    global key
    enkriptovan_tekst = cipher_suite.encrypt((ulaz).encode('utf-8'))
    return enkriptovan_tekst


def dekriptuj(ulaz):
    dekriptovano = cipher_suite.decrypt(ulaz)
    dekriptovano = dekriptovano.decode('utf-8')
    return dekriptovano


def desifruj_poruku(poruka):
    originalni_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '
    permutirani_string = 'iLSaOeXrBCqDpYcVFlfhZTMyjzNJbwWxvQgUGmKkHuPnRdJtAIEo?'

    if len(originalni_string) != len(permutirani_string):
        raise ValueError("Stringovi za permutaciju moraju biti iste dužine.")

    sifra = str.maketrans(permutirani_string, originalni_string)
    return poruka.translate(sifra)


def sifruj_poruku(poruka):
    originalni_string = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '
    permutirani_string = 'iLSaOeXrBCqDpYcVFlfhZTMyjzNJbwWxvQgUGmKkHuPnRdJtAIEo?'

    if len(originalni_string) != len(permutirani_string):
        raise ValueError("Stringovi za permutaciju moraju biti iste dužine.")

    sifra = str.maketrans(originalni_string, permutirani_string)
    return poruka.translate(sifra)

def generator_racuna():
    # Generiranje žiro računa
    account_number = str(randint(1110000000000000000, 1119999999999999999))
    return account_number



def finish_reg(temp_name, temp_lastname, temp_age, temp_gender, temp_password, temp_status, temp_email, notif):
    global broj_racuna
    global stanje_racuna
    global pomocno_ime
    stanje_racuna = IntVar()
    stanje_racuna = 0
    name = temp_name
    if name.isalpha() == False:
        notif.config(fg="red", text="Ime korisnika mora sadržavati isključivo slova!")
        return
    if len(name) > 20:
        notif.config(fg="red", text="Ime korisnika mora biti kraće od 20 karaktera!")
        return
    lastname = temp_lastname
    if lastname.isalpha() == False:
        notif.config(fg="red", text="Prezime korisnika mora sadržavati isključivo slova!")
        return
    if len(lastname) > 20:
        notif.config(fg="red", text="Prezime korisnika mora biti kraće od 20 karaktera!")
        return
    age = temp_age
    gender = temp_gender
    password = temp_password
    status = temp_status
    email = temp_email
    os.chdir(r'C:\Users\eniz.balihodzic\Downloads\pythonProject1\Korisnici')
    all_accounts = os.listdir()
    broj_racuna = generator_racuna()
    pomocno_ime = sifruj_poruku(name)
    if name == "" or age == "" or gender == "" or password == "":
        notif.config(fg="red", text="Sva polja morau biti popunjena! ")
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

    
    notif.config(fg="green", text="Account has been created")
