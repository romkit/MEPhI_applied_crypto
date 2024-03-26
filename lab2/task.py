import hashlib
import json
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes
from pygost.gost3412 import GOST3412Kuznechik
from pygost.mgm import MGM

MASTER_SALT = b'39767755be30289a0c3b779a02308b9383161abfd77db356b4af6e68afd6887b'
K1_SALT = b'68824789e3814b9b015c7ce8bbd7db1bb206b197bcbc9995921e2a781a80a982'
K2_SALT = b'a3105ef147eb97a01437f00263d6136a45827d908071f64b5b7200ba01c52cbc'
NONCE = b'\x00' * GOST3412Kuznechik.blocksize
AD = b'\xff' * GOST3412Kuznechik.blocksize
PASSWORD_SIZE = 64
PASSWORD_STORAGE = 'storage.json'
FLASH_DRIVE_PATH = 'password_manager.md5'


def add_padding(data):
    # добавить паддинг
    if len(data) > PASSWORD_SIZE:
        data = data[:PASSWORD_SIZE]
    padding_size = PASSWORD_SIZE - len(data)
    data += get_random_bytes(padding_size) + long_to_bytes(padding_size)
    return data


def remove_padding(data):
    # удалить паддинг
    padding_size = data[-1]
    data = data[:-padding_size - 1]
    return data


class PasswordManager:
    def __init__(self):
        self._k1 = None
        self._k2 = None
        self._db = {}

    def set_db(self, password_data):
        # установить текущие данные
        self._db = json.loads(password_data)

    def set_master_key(self):
        # генерация мастер-ключа
        password = input("Input new master-key: ")
        master_key = PBKDF2(password=password, salt=MASTER_SALT, dkLen=32, count=1000000, hmac_hash_module=SHA256)

        self.set_keys(master_key)

    def set_keys(self, master_key):
        # получить ключи из мастер-ключа
        self._k1 = HMAC.new(master_key, K1_SALT, digestmod=SHA256).digest()
        self._k2 = HMAC.new(master_key, K2_SALT, digestmod=SHA256).digest()

    def get_domain_hash(self, domain):
        # получить хеш домена с помощью HMAC
        hashed = HMAC.new(self._k1, domain.encode(), digestmod=SHA256)
        return hashed.hexdigest()

    def check_master_pass(self):
        # проверка мастер-ключа
        password = input('Input your master-key: ')
        master_key = PBKDF2(password=password, salt=MASTER_SALT, dkLen=32, count=1000000, hmac_hash_module=SHA256)

        existed_domain = input("Input one of the existing domains from db: ")
        self.set_keys(master_key)
        hashed_domain = self.get_domain_hash(existed_domain)
        if hashed_domain not in self._db:
            print(f"Password is not correct or no domain {existed_domain} in database")
            return True
        else:
            print("Password is correct")

    def get_encrypt_password(self, password):
        # получение шифрованного пароля
        mgm = MGM(GOST3412Kuznechik(self._k2).encrypt,
                  GOST3412Kuznechik.blocksize)
        encrypt_password = mgm.seal(NONCE, add_padding(password), AD)
        return encrypt_password.hex()

    def add_record(self, domain, password):
        # добавление записи в базу
        domain_hash = self.get_domain_hash(domain)
        encrypt_password = self.get_encrypt_password(password.encode())
        self._db[domain_hash] = (encrypt_password,
                                 hashlib.md5(domain_hash.encode() + encrypt_password.encode()).hexdigest())

    def get_decrypt_password(self, encrypt_password):
        # получение расшифрованного пароля
        mgm = MGM(GOST3412Kuznechik(self._k2).encrypt,
                  GOST3412Kuznechik.blocksize)
        password = mgm.open(NONCE, bytes.fromhex(encrypt_password), AD)
        password = remove_padding(password)
        return password

    def get_record(self, domain):
        # возврат пароля к введенному домену
        domain_hash = self.get_domain_hash(domain)
        if domain_hash in self._db:
            encrypt_password = self._db[domain_hash][0]
            password = self.get_decrypt_password(encrypt_password)
            print(f'domain: {domain} \npassword: {password}')
        else:
            print(f"No record for {domain} in database")

    def rewrite_record(self, domain):
        # перезапись для указанного домена
        domain_hash = self.get_domain_hash(domain)
        if domain_hash not in self._db:
            print(f"No domain name {domain} in database")
            return
        password = input("Input new password: ")
        encrypt_password = self.get_encrypt_password(password.encode())
        self._db[domain_hash] = (encrypt_password,
                                 hashlib.md5(domain_hash.encode() + encrypt_password.encode()).hexdigest())

    def delete_record(self, domain):
        # удаление записи из бд
        hashed_domain = self.get_domain_hash(domain)
        if hashed_domain in self._db:
            self._db.pop(hashed_domain)
        else:
            print(f"No record for {domain} in database")
            return
        print(f"Domain {domain} was deleted from database")


    def save_db_to_file(self):
        # сохранение базы в файл
        try:
            with open(PASSWORD_STORAGE, "r") as file:
                backup = json.load(file)
            with open(f"{str(datetime.now()).replace(':', '.')}.json", "w") as file:
                json.dump(backup, file)
        except FileNotFoundError:
            pass
        with open(PASSWORD_STORAGE, "w") as file:
            json.dump(self._db, file)

    def get_md5_hash_file(self):
        # получение хеша файла
        hash_md5 = hashlib.md5()
        with open(PASSWORD_STORAGE, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    def save_md5(self):
        # сохранение хеша "на диск"
        md5_hash = self.get_md5_hash_file()
        with open(FLASH_DRIVE_PATH, "w") as file:
            file.write(md5_hash)

    def check_md5_hash(self):
        # проверка хеша файла
        # и правильного хранения паролей (защита от swap-attack)
        try:
            with open(FLASH_DRIVE_PATH, "r") as file:
                saved_md5_value = file.read()
        except FileNotFoundError:
            print("No data about hash, unable to verify integrity")
            return True
        with open(PASSWORD_STORAGE, "r") as file:
            db = json.load(file)
        received_value = self.get_md5_hash_file()
        if saved_md5_value != received_value:
            for key in db:
                received_hash = hashlib.md5(key.encode() + db[key][0].encode()).hexdigest()
                if received_hash != db[key][1]:
                    print("Swap attack")
                    return True
            print("Rollback attack")
            return True
        else:
            print("Password storage integrity confirmed")

    def start(self):
        # обертка для начала работы
        self.set_master_key()
        self.add_record('google.com', 'google_pass')
        self.add_record('yandex.ru', 'yandex_pass')
        self.save_db_to_file()
        self.save_md5()

    def task_1(self):
        # обертка для демонстрации корректной работы
        with open(PASSWORD_STORAGE, 'r') as storage:
            self.set_db(storage.read())
        print('Hash checking')
        if self.check_md5_hash():
            return
        if self.check_master_pass():
            return
        self.get_record('google.com')
        self.get_record('asdsdads')
        self.add_record('yahoo.com', 'yahoo_pass')
        self.rewrite_record('yahoo.com')
        self.get_record('yahoo.com')
        self.delete_record('yandex.ru')
        self.get_record('yandex.ru')
        self.add_record('test_1.com', 'test_1_pass')
        self.add_record('test_2.com', 'test_2_pass')
        self.save_db_to_file()
        self.save_md5()

    def task_2(self):
        # обертка для демонстрации защиты от атак
        with open(PASSWORD_STORAGE, 'r') as storage:
            self.set_db(storage.read())
        print('Hash checking')
        if self.check_md5_hash():
            return
        if self.check_master_pass():
            return


if __name__ == "__main__":
    pm = PasswordManager()
    pm.start()
    pm.task_1()
    #pm.task_2()