import unittest
from tkinter import Label
from test1 import admin_finish_reg

#Test ukoliko pokusamo kreirati racun sa jednim praznim poljem
class TestFinishRegFunction(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
    def test_finish_reg_uspjesno(self):
        temp_name = "Asmir"
        temp_lastname = ""
        temp_age = "12.12.1992"
        temp_gender = "Muski"
        temp_password = ""
        temp_status = "Zaposlen"
        temp_email = "asmir@gmail.com"
        notif = Label()
        admin_finish_reg(temp_name, temp_lastname, temp_age, temp_gender, temp_password, temp_status, temp_email, notif)
        expected_text = "Sva polja moraju biti popunjena!"
        self.assertEqual(notif.cget("text"), expected_text)
if __name__ == '__main__':
    unittest.main()
