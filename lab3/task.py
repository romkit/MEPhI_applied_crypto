import random
from collections import Counter
import gostcrypto
import numpy as np
from Crypto.Random import get_random_bytes
from lab1.task_1 import UC, User, get_hash, bytearray_to_normal

sign_obj = gostcrypto. \
    gostsignature.new(gostcrypto.gostsignature.MODE_256,
                      gostcrypto.gostsignature.
                      CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])

N = 11
M = 3
T = N - M
LEN = 90


def get_vander(m, n):
    # получение матрицы Вандермонда
    random_elements = np.random.choice(range(1, 256), n, replace=False)
    vander_matrix = np.vander(random_elements, m, increasing=True)
    return vander_matrix


def create_user(name):
    # создание объектов классов
    name.set_private_key()
    name.set_public_key()
    name.get_cert_from_uc(centr)


class Gateway(User):
    def __init__(self):
        super(Gateway, self).__init__()
        self.f_string = None
        self.storages = None

    def deposit_transmit(self, f, f_sign, username, storages):
        # выполнение части протокола Deposit на шлюзе
        # partner_sert = self.get_partner_cert(username, cert_num)
        if not self.uc_name.check_sign(username, f, f_sign):
            print('Wrong User sign')
            return
        self.f_string = f
        self.storages = storages
        for i, key in enumerate(storages.keys()):
            responce_ = storages[key].deposit(f, f_sign, username)
            if not self.uc_name.check_sign(responce_[0], str(username).encode() + str(f).encode(), responce_[1]):
                print(f'Wrong storage_{i} sign')
                return
        sign = self.get_sign(str(username).encode() + str(f).encode())
        return sign

    def retrieval(self, username, sign, vander, CORRECT_VANDER):
        # выполнение части алгоритма Retrieval на шлюзе
        if not self.uc_name.check_sign(username, self.f_string, sign):
            print('Wrong User sign')
            return
        hashes = []
        parts = []
        for key in self.storages.keys():
            responce_ = storages[key].retrieval(username, sign)
            parts.append(responce_[0])
            hashes.append(responce_[1])

        result_hash = []
        for i in range(len(hashes[0])):
            most_common = Counter([elem[i] for elem in hashes]).most_common(1)[0][0]
            result_hash.append(most_common)
        print('Hashes on Gateway: ', result_hash)
        correct_numbers = []
        for i, hash in enumerate(hashes):
            if result_hash[i] == hash[i]:
                correct_numbers.append(i)

        m = []
        new_vander = []
        t = 0
        if not CORRECT_VANDER:
            t = 1
        sample = random.sample(correct_numbers, M - t)
        for number in sample:
            m.append(parts[number])
            new_vander.append(vander[number])
        new_vander = np.array(new_vander)
        try:
            inv_vander = np.linalg.inv(new_vander)
            return inv_vander @ m
        except np.linalg.LinAlgError:
            print('Have no storages to correct retrieval')
            exit()


class new_User(User):
    def __init__(self):
        super(new_User, self).__init__()
        self.f_string = None
        self.f_sign = None

    def deposit(self, f, gw, storages):
        # выполнение части протокола Deposit у пользователя
        f_sign = self.get_sign(f)
        self.f_sign = f_sign
        self.f_string = f
        gw_sign = gw.deposit_transmit(f, f_sign, self.username, storages)
        if not self.uc_name.check_sign(gw.username, str(self.username).encode() + str(f).encode(), gw_sign):
            print('Wrong User sign')
            return

    def retrieval(self, gw, vander_matrix, CORRECT_VANDER=True, TRESHOLD_RETR=False):
        # выполнение части алгоритма Retrieval у пользователя
        recov = gw.retrieval(self.username, self.f_sign, vander_matrix, CORRECT_VANDER, TRESHOLD_RETR)
        out = []
        for rec in np.transpose(recov):
            for r in rec:
                out.append(r)
        return out


class Data_Storage(User):
    def __init__(self, number):
        super(Data_Storage, self).__init__()
        self.numb = number
        self.uhd = []
        self.f_string = None
        self.user_sign = None

    def deposit(self, f, f_user_sign, username):
        # выполнение части протокола Deposit у сервера УХД
        if not self.uc_name.check_sign(username, f, f_user_sign):
            print('Wrong sign')
            return
        else:
            self.f_string = f
            self.uhd.append(f_user_sign)
            sign = self.get_sign(str(username).encode() + str(f).encode())
            return self.username, sign

    def dispersal(self, vander):
        # выполнение протокола Dispersal у сервера УХД
        s_list = np.transpose(np.array([self.f_string[i:i + M] for i in range(0, len(self.f_string), M)]))
        disp = vander @ s_list
        disp_hash = []
        for i, d in enumerate(disp):
            disp_hash.append(bytearray_to_normal(get_hash(d)))
        self.uhd.insert(0, disp[self.numb])
        self.uhd.insert(1, disp_hash)
        print(f'storage_{self.numb} data: {self.uhd}')

    def retrieval(self, username, sign):
        # выполнение алгоритма Retrieval у сервера УХД
        if not self.uc_name.check_sign(username, self.f_string, sign) or sign != self.uhd[2]:
            print('Wrong sign')
            return
        return self.uhd[:-1]


if __name__ == "__main__":
    centr = UC()
    centr.set_private_key()
    centr.set_public_key()
    centr.set_crl()
    user = new_User()
    gw = Gateway()
    storages = {}
    for i in range(N):
        storages[f'storage_{i}'] = Data_Storage(i)
    create_user(user)
    create_user(gw)
    for key in storages.keys():
        create_user(storages[key])
    F = get_random_bytes(LEN)
    if LEN % M != 0:
        diff = LEN // M
        new_len = M * diff
        F = F + b'0' * (new_len - LEN)
    F = [b for b in F]
    vander = get_vander(M, N)
    user.deposit(F, gw, storages)
    for key in storages.keys():
        storages[key].dispersal(vander)
    r = user.retrieval(gw, vander)
    retr = list(map(lambda num: int(num) % 256, r))
    print('original: ', F)
    print('result: ', retr)
