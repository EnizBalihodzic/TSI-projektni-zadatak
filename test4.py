import unittest
from tkinter import Label
from test1 import finish_reg

#Test ukoliko pokusamo kreirati racun sa jednim praznim poljem
class TestFinishRegFunction(unittest.TestCase):
    def setUp(self):
        pass
    def tearDown(self):
        pass
    def test_finish_reg_uspjesno(self):
        temp_name = "Elektrotehnickifakultetsarajevo"
        temp_lastname = "Etfovic"
        temp_age = "25"
        temp_gender = "Muski"
        temp_password = "password123"
        temp_status = "Zaposlen"
        temp_email = ""
        notif = Label()
        finish_reg(temp_name, temp_lastname, temp_age, temp_gender, temp_password, temp_status, temp_email, notif)
        expected_text = "Sva polja morau biti popunjena!"
        self.assertEqual(notif.cget("text"), expected_text)
if __name__ == '__main__':
    unittest.main()
