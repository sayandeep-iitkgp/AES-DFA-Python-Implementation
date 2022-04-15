import math
import numpy as np
import scipy
import random
import csv
from aes import *
	

# Implement Fault injection
def inject_fault(state, byte_loc=0): 
	for i in range(4): 
		for j in range(4):
			if((i*4 + j) == byte_loc):
				state[j][i] = state[j][i]^(random.randint(1,255) & 0xff)	# Modify here; Hint: Generate random integer within range (1,d) (d<=255)
											# with the command (random.randint(1,d) & 0xff)
										    # ^(random.randint(1,255) & 0xff)
	return state

# Encryption module with fault injection simulation 
def encrypt_faultsim(pt=None, inj_round=8, byte_loc=0):
	
	if pt is None:
		pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
	for i in range(4):
		for j in range(4):
			cipher.state[j][i] = pt[i*4 + j]
	rnd = 0
	cipher.AddRoundKey(rnd)
		
	for rnd in range(1, cipher.Nr):
		# Fault injection ###########################
		if (rnd == inj_round):
			temp_state = inject_fault(cipher.state,byte_loc=byte_loc)
			for i in range(4):
				for j in range(4):
					cipher.state[j][i] = temp_state[j][i]	
		#############################################				
		cipher.SubBytes()
		cipher.ShiftRows()
		cipher.MixColumns()
		cipher.AddRoundKey(rnd)
	cipher.SubBytes()
	cipher.ShiftRows()
	cipher.AddRoundKey(cipher.Nr)
	
	for i in range(4):
		for j in range(4):
			cipher.ciphertext[i*4 + j] = cipher.state[j][i]
	
	return cipher.ciphertext	



# Parameters
no_faulty_ciphertexts = 2
inject_round = 8
byte_loc = 0


# Initialize
cipher = AES()
cipher.KeyExpansion()

print(intarraytohexstring(cipher.get_lastroundkey()))

correct_ct_list = []
faulty_ct_list = []

for i in range(no_faulty_ciphertexts):
	# Generate Random plaintext
	rand_pt = [random.randint(0,255) for x in range(16)]

	# Perform Correct execution
	correct = cipher.encrypt(pt=rand_pt)
	print("Correct Ciphertext %d:	"%(i+1), end=" ")
	print(correct)
	correct_ct_list.append(intarraytohexstring(correct))
	
	# Perform Faulty execution
	faulty = encrypt_faultsim(pt=rand_pt, inj_round=inject_round, byte_loc=byte_loc)
	print("Faulty Ciphertext %d:	"%(i+1), end=" ")
	print(faulty)
	faulty_ct_list.append(intarraytohexstring(faulty))
	print("")



# Print the correct and faulty ciphertexts to a file
#filename = 'fault_file.csv'

#with open(filename, mode='w') as fault_file:
#	fault_writer = csv.writer(fault_file, delimiter=',')
#	for l in range(len(correct_ct_list)):	
#		fault_writer.writerow([correct_ct_list[l], faulty_ct_list[l]])


