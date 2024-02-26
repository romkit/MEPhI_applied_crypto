import gostcrypto

hash_string = u'Се ветри, Стрибожи внуци, веютъ с моря стрелами на храбрыя плъкы Игоревы'.encode('cp1251')
hash_obj = gostcrypto.gosthash.new('streebog256', data=hash_string)

print(hash_obj.digest())