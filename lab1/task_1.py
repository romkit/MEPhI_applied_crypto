import uuid
import secrets
from datetime import datetime, timedelta
import gostcrypto
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
import json
import binascii

sign_obj = gostcrypto. \
    gostsignature.new(gostcrypto.gostsignature.MODE_256,
                      gostcrypto.gostsignature.
                      CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB'])


def get_hash(obj):
    hash_str = str(obj).encode('utf-8')
    hash_obj = gostcrypto.gosthash.new('streebog256', data=hash_str)
    return hash_obj.digest()


def bytearray_to_normal(obj):
    return binascii.hexlify(obj).decode('utf-8')


def create_user(name):
    name.set_private_key()
    name.set_public_key()
    name.get_cert_from_uc(centr)


class UC:
    def __init__(self):
        self.name = uuid.uuid4()
        self.delta = timedelta(days=10)
        self.users_certs = {}  # {num_1: [{}], num_2: [{}]}
        self.canc_certs = []
        self.test_text = 'This-is-test-text'.encode('utf-8')
        self.public_key = None
        self.private_key = None

    def get_private_key(self):
        return secrets.randbits(256).to_bytes(32, byteorder='big')
        # gost = gostcrypto.gostCrypto()
        # return gostcrypto.generate_private_key()

    def get_public_key(self, private_key):
        return sign_obj.public_key_generate(private_key)

    def set_private_key(self):
        self.private_key = self.get_private_key()

    def set_public_key(self):
        self.public_key = self.get_public_key(self.private_key)

    def get_sign(self, obj):
        hash_obj = get_hash(obj)
        return binascii.hexlify(
            sign_obj.sign(self.private_key, hash_obj)).decode('utf-8')

    def get_cert(self, username, public_key, test_cipher):
        if username in self.users_certs and public_key in [cert['public_key'] for cert in self.users_certs[username]]:
            print('User already has a cert for this key')
            return
        if username not in self.users_certs.keys():
            self.users_certs[username] = []
        if not sign_obj.verify(public_key, get_hash(self.test_text), test_cipher):
            print('Wrong cipher')
            return
        cert = {
            'cert_num': secrets.randbelow(2 ** 10),
            'ds_alg': 'GOST 256',
            'self_name': str(self.name),
            'start': str(datetime.now()),
            'end': str(datetime.now() + self.delta),
            'alg_to': 'GOST 256',
            'username': str(username),
            'public_key': bytearray_to_normal(public_key)
        }

        uc_sign = self.get_sign(cert)
        cert['uc_sign'] = uc_sign
        self.users_certs[username].append(cert)
        return cert

    def set_crl(self):
        crl = {
            'ds_alg': 'GOST 256',
            'self_name': str(self.name),
            'start': str(datetime.now()),
            'end': str(datetime.now() + self.delta),
            'canc_certs': [],
        }
        uc_sign = self.get_sign(crl)
        # crl['uc_sign'] = binascii.hexlify(uc_sign).decode('utf-8')
        self.canc_certs = [crl, uc_sign]

    def crl(self, username, cert_num, test_cipher):
        current_cert = None
        if username not in self.users_certs:
            print('User is not exist')
            return
        for cert in self.users_certs[username]:
            if cert['cert_num'] == cert_num:
                current_cert = cert
        if current_cert is None:
            print('Cert is not exists for user')
            return
        if not sign_obj.verify(bytearray.fromhex(current_cert['public_key']),
                               get_hash(self.test_text), test_cipher):
            print('Wrong cipher')
            return
        new_canc_cert = [current_cert['cert_num'],
                         str(datetime.now())]
        self.users_certs[username].remove(current_cert)
        crl = self.canc_certs[0]
        crl['canc_certs'].append(new_canc_cert)

        uc_sign = self.get_sign(crl)
        self.canc_certs = [crl, uc_sign]
        print('canceled certs: ', self.canc_certs)
        return self.canc_certs


class User:
    def __init__(self):
        self.username = uuid.uuid4()
        self.private_key = None
        self.public_key = None
        self.certs = []
        self.crl = None

    def get_private_key(self):
        return secrets.randbits(256).to_bytes(32, byteorder='big')

    def get_public_key(self, private_key):
        return sign_obj.public_key_generate(private_key)

    def set_private_key(self):
        self.private_key = self.get_private_key()

    def set_public_key(self):
        self.public_key = self.get_public_key(self.private_key)

    def get_sign(self, obj):
        hash_obj = get_hash(obj)
        return sign_obj.sign(self.private_key, hash_obj)

    def get_cert_from_uc(self, uc):
        test_cipher = self.get_sign(uc.test_text)
        cert = uc.get_cert(self.username, self.public_key, test_cipher)
        self.certs.append(cert)
        print('Cert created: ', cert)

    def remove_cert_from_uc(self, uc, cert_num):
        test_cipher = self.get_sign(uc.test_text)
        uc.crl(self.username, cert_num, test_cipher)
        removing = next((cert for cert in self.certs if cert['cert_num'] == cert_num), None)
        self.certs.remove(removing)

    def get_partner_cert(self, uc, username, cert_num):
        try:
            partner_cert = None
            for cert in uc.users_certs[username]:
                if cert['cert_num'] == cert_num:
                    partner_cert = cert
            if partner_cert is None:
                print('Have no cert_num for username')
                return
            if partner_cert['cert_num'] in uc.canc_certs[0]:
                print('Cert is canceled')
                return
            else:
                print('Partner cert: ', partner_cert)
        except KeyError:
            print('have no username')


if __name__ == "__main__":
    centr = UC()
    centr.set_private_key()
    centr.set_public_key()
    centr.set_crl()
    # print(centr.get_cert('AAAA'))
    # print(centr.crl('AAAA'))

    Alice = User()
    # Alice.set_private_key()
    # Alice.set_public_key()
    # Alice.get_cert_from_uc(centr)
    create_user(Alice)
    Alice.remove_cert_from_uc(centr, Alice.certs[0]['cert_num'])
    Alice.get_cert_from_uc(centr)

    Bob = User()
    create_user(Bob)
    print('certs: ', centr.users_certs)
    Bob.get_partner_cert(centr, Alice.username, Alice.certs[0]['cert_num'])
    Alice.remove_cert_from_uc(centr, Alice.certs[0]['cert_num'])
