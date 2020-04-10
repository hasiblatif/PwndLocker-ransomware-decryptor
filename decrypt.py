import sys, os
import binascii
import optparse
import settings 

def get_encrypted_size(data):
	try:
		size = change_endianness(binascii.hexlify(data[-148: -146]))
		return int(size, 16)
	except:
		None

def get_key(data, ext):
	try:
		if ext == "pwnd":
			return settings.key
		# in .key extension, key is appended to encrypted file 
		else: 
			key = data[-0x78: -0x40]
			return binascii.hexlify(key)
	except:
		return None

def verify_encryption(data):
	try:
		encryption_marker = "07c6a3f1594152bd"
		marker = data[-180: -172]
		if binascii.hexlify(marker) == encryption_marker:
			return True
	except:
		pass
	return False

#  ROL function taken from https://gyeongje.tistory.com/353
def ROL(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)

def verify_and_decrypt(encrypted_file_path, options):
	encrypted_file_path = os.path.abspath(encrypted_file_path)
	Decrypted_data = ''
	encrypted_file_data = ''
	encrypted_size = 0
	encrypted_file_key = ''
	ext = encrypted_file_path.split(".")[-1]
	decrypted_file_path = encrypted_file_path[:-len(ext)-1]
	if ext != "pwnd" and ext != "key":
		print "[-] File not encrypted by PwndLocker ransomware: "+ encrypted_file_path
		return
	try:
		with open(encrypted_file_path, "rb") as f:
			encrypted_file_data = f.read()
	except:
		print "[-] Error opening file: " + encrypted_file_path
		print traceback.print_exc()
		return 

	if verify_encryption(encrypted_file_data):
		print "[+] Encrpted by PwndLocker ransomware, trying decryption ..."
		encrypted_size = get_encrypted_size(encrypted_file_data)
		encrypted_file_key = get_key(encrypted_file_data, ext)

		#key is appended to table data 
		table_data =  settings.table + encrypted_file_key + encrypted_file_key[0:0x20]

		# multiple operations are performed on table data including encryption by the same algo which is used for file encryption
		key = prepare_key(table_data)
		counter = settings.start_of_encryption_offset
		initial = counter
		while counter < encrypted_size:
			# 8 bytes are read in two dwords and are decrypted 
			first_four_bytes = change_endianness(binascii.hexlify(encrypted_file_data[counter: counter+4]))
			second_four_bytes = change_endianness(binascii.hexlify(encrypted_file_data[counter+4: counter+8]))
			edx, eax = decrypt(key, second_four_bytes,first_four_bytes)
			Decrypted_data += change_endianness("%08x" % eax) + change_endianness("%08x" %edx)
			counter += 8

		delta = encrypted_size % 8
		delta=  binascii.hexlify(encrypted_file_data[encrypted_size - delta: encrypted_size])
		if initial != 0:
			Decrypted_data = Decrypted_data[:-16]
		Decrypted_data = encrypted_file_data[:initial] + binascii.unhexlify(Decrypted_data + delta)
		with open(decrypted_file_path, "wb") as f:
			f.write(Decrypted_data)
		if options.delete_encrypted:
			print "[+] Deleteing encrypted file:" + encrypted_file_path
			os.remove(encrypted_file_path)
		print "[+] successfully decrypted: " + encrypted_file_path
	else:
		print "[-] Not encrypted by PwndLocker ransomware version this decryptor is built for : " + encrypted_file_path

def change_endianness(bytes):
	d= ''
	index1 = len(bytes) -2
	while index1 !=-2:
		d += bytes[index1: index1+2] 
		index1 -= 2
	return d

def prepare_key(table_data):
	d= binascii.unhexlify(table_data)
	key_index = len(table_data) - 8
	index = 0x44 * 2
	final = ''
	Decrypted_data = ''

	while True:
		a = int(change_endianness(table_data[index : index +8]),16)
		b = int(table_data[key_index : key_index + 8],16)
		k =   (a ^ b ) & 0xffffffff
		k = "%08x" % k
		prev = final
		final = change_endianness(k) + prev
		index -= 8
		key_index -= 8
		if index == -8:
			break
	final = final + table_data[0x48*2:-0x48*2] + 8 * "00" + table_data[-0x40*2:]
	key_index = -0x48*2
	eax = final[key_index: key_index+ 8] 
	key_index =  key_index + 8
	edx = final[key_index : key_index  + 8]

	tmp1 = ''
	edx, eax = encrypt(final, eax, edx)
	tmp1 = tmp1 + change_endianness("%08x" % edx ) + change_endianness("%08x" % eax)
	counter = 0
	tmp = tmp1 + final[len(tmp1):]

	while counter != 0x208:
		index = counter*16
		eax = tmp[index:index + 8]
		edx = tmp[index + 8 : index + 0x10]
		counter +=1
		edx, eax = encrypt(tmp, eax, edx)
		tmp1 = tmp1 + change_endianness("%08x" %edx) + change_endianness("%08x" %eax )
		tmp = tmp1 + final[len(tmp1):]
	return tmp

def decrypt(key, dword1, dword2):

	edi = 0xf
	dword1 = int(dword1,16)
	dword2 = int(dword2,16)
	index = 0x40*2
	dword1 = (dword1 ^ int(change_endianness(key[index:index+8]),16)) & 0xffffffff
	dword2 = (dword2 ^ int(change_endianness(key[index+8: index+0x10]),16)) & 0xffffffff

	while edi != -1:
		tmp = dword2
		dword2 = dword1
		dword1 = tmp

		dword1 =  ROL(dword1,0x10)
		cl = dword1 & 0xff
		index = (cl * 8) + (0x448*2)
		esi = int(change_endianness(key[ index: index + 8]),16) & 0xffffffff
		cl = (dword1 >> 8 ) & 0xff
		index = (cl * 8) + (0x48*2)
		esi += int(change_endianness(key[index: index + 8]),16) & 0xffffffff
		dword1 = ROL(dword1, 0x10)
		cl = (dword1 >> 8 ) & 0xff
		index = (cl * 8) + (0x848*2)
		esi = (esi ^ int(change_endianness(key[index: index + 8]),16)) & 0xffffffff
		cl = dword1  & 0xff
		index = (cl * 8) + (0xc48*2)
		esi +=  int(change_endianness(key[index: index + 8]),16) &  0xffffffff
		dword2 = (dword2 ^ esi) & 0xffffffff
		dword1 = (dword1 ^ int(change_endianness(key[edi*8: (edi*8) + 8]),16) ) & 0xffffffff
		edi -= 1

	return dword2, dword1

def encrypt(key, dword1, dword2):
	
	edi = 0
	dword1 = int(change_endianness(dword1),16)
	dword2 = int(change_endianness(dword2),16)

	while edi != 0x10:
		
		dword1 = dword1 ^ int(change_endianness(key[edi*8: (edi*8) + 8]),16)
		dword1 =  ROL(dword1,0x10)
		cl = dword1 & 0xff
		index = (cl * 8) + (0x448*2)
		esi = int(change_endianness(key[ index: index + 8]),16) & 0xffffffff
		cl = (dword1 >> 8 ) & 0xff
		index = (cl * 8) + (0x48*2)
		esi += int(change_endianness(key[index: index + 8]),16) & 0xffffffff
		dword1 = ROL(dword1, 0x10)
		cl = (dword1 >> 8 ) & 0xff
		index = (cl * 8) + (0x848*2)
		esi = (esi ^ int(change_endianness(key[index: index + 8]),16)) & 0xffffffff
		cl = dword1  & 0xff
		index = (cl * 8) + (0xc48*2)
		esi +=  int(change_endianness(key[index: index + 8]),16) 
		esi = esi &  0xffffffff
		dword2 = (dword2 ^ esi) & 0xffffffff
		tmp = dword2
		dword2 = dword1
		dword1 = tmp
		edi += 1
	index = 0x40*2
	dword1 = (dword1 ^ int(change_endianness(key[index:index+8]),16)) & 0xffffffff
	dword2 = (dword2 ^ int(change_endianness(key[index+8: index+0x10]),16)) & 0xffffffff
	return dword2, dword1

def traverse_dir(dir_name, options):

	if os.path.isdir(dir_name):
		if options.recursive:
			for root, dirs, files in os.walk(dir_name):
				
				for file in files:
					file_name = os.path.join(root,file)
					verify_and_decrypt(file_name,options)
		else:
			for file in os.listdir(dir_name):
				file_name = os.path.join(dir_name,file)
				if os.path.isfile(file_name):
					verify_and_decrypt(file_name,options)
	else:
		print "[-] Please provide directory with switch --dir not file "
if __name__ == "__main__":
	parser = optparse.OptionParser()
	parser.add_option('--file', action="store", dest="file_name", help='Decrypt single file')
	parser.add_option('--dir', action="store", dest="dir_name", help='Decrypt all files in a directory')
	parser.add_option('--recursive', action="store_true", dest='recursive', default=False, help='Decrypt files in sub-directories recursively, root directory should be provided with --dir option')
	parser.add_option('--del', action="store_true", dest='delete_encrypted', default=False, help='Delete encrypted files after decryption. [Caution : NOT recommended until single file decryption is successfully tested')

	options, args = parser.parse_args()
	if options.file_name:
		verify_and_decrypt(options.file_name,options)
	elif options.dir_name:
		traverse_dir(options.dir_name, options)