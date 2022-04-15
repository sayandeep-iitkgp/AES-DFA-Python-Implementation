"""
DFA on AES with 8th round fault injection and two faulty ciphertexts.
This code only finds out first 32-key bits and is used as a tutorial.
Modifications for full round key recovery is trivial, but requires
more computational effort.

Written by: Sayandeep Saha 
"""
import numpy as np
import sys


def xtime(x):
	tmp1 = x<<1
	tmp1 = tmp1&0xff
	tmp2 = x>>7
	tmp2 = tmp2&1
	tmp2 = tmp2*0x1b
	val = tmp1^tmp2
	return val

def field_mul_2(x):
	return xtime(x)
	
def field_mul_3(x):
	return xtime(x)^x	
	

sbox_inv = [82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251, 
124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203, 
84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78, 
8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37, 
114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146, 
108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132, 
144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6, 
208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107, 
58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 
150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110, 
71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27, 
252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244, 
31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95, 
96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239, 
160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97, 
23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125]


correct_ct_1 = [54, 251, 62, 31, 168, 154, 18, 131, 74, 98, 236, 61, 160, 81, 91, 27]	# Correct ciphertext 1
correct_ct_2 = [2, 168, 206, 102, 111, 178, 253, 220, 51, 156, 153, 210, 144, 215, 255, 238] # Correct ciphertext 2
faulty_ct_1 = [222, 60, 208, 208, 190, 127, 73, 72, 224, 207, 242, 132, 78, 245, 132, 99] # Faulty ciphertext 1
faulty_ct_2 = [179, 99, 204, 215, 117, 200, 50, 110, 8, 192, 75, 212, 236, 238, 27, 48]  # Faulty ciphertext 2


# Associated data structures
correct_key_pool_1 = []
correct_key_pool_2 = []
correct_ct_1_state = np.zeros(shape = (4, 4), dtype='int')
correct_ct_2_state = np.zeros(shape = (4, 4), dtype='int')
faulty_ct_1_state = np.zeros(shape = (4, 4), dtype='int')
faulty_ct_2_state = np.zeros(shape = (4, 4), dtype='int')
round_key = np.zeros(shape = (4, 4), dtype='int')

# Create the state arrays
cnt = 0
for i in range(4):
	for j in range(4):
		correct_ct_1_state[j][i] = correct_ct_1[cnt]
		correct_ct_2_state[j][i] = correct_ct_2[cnt]
		faulty_ct_1_state[j][i] = faulty_ct_1[cnt]
		faulty_ct_2_state[j][i] = faulty_ct_2[cnt]
		cnt = cnt + 1



# Now, invert the ciphertexts and find the key

# Invert the first ciphertext and dump potential key candidates

cnt1 = 0
for fault in range(1, 256):
	for key_0 in range(0,256):
		t1=correct_ct_1_state[0][0]^key_0;
		t2=faulty_ct_1_state[0][0]^key_0;
		t1=t1&0xff;
		t2=t2&0xff;
		inv_t1=sbox_inv[t1];
		inv_t2=sbox_inv[t2];
		if((field_mul_2(fault))==((inv_t1^inv_t2)&0xff)):
			for key_1 in range(0,256):
				t1=correct_ct_1_state[1][3]^key_1;
				t2=faulty_ct_1_state[1][3]^key_1;
				t1=t1&0xff;
				t2=t2&0xff;
				inv_t1=sbox_inv[t1];
				inv_t2=sbox_inv[t2];
				if(fault==((inv_t1^inv_t2)&0xff)):
					for key_2 in range(0,256):
						t1=correct_ct_1_state[2][2]^key_2;
						t2=faulty_ct_1_state[2][2]^key_2;
						t1=t1&0xff;
						t2=t2&0xff;
						inv_t1=sbox_inv[t1];
						inv_t2=sbox_inv[t2];
						if(fault==((inv_t1^inv_t2)&0xff)):
							for key_3 in range(0, 256):
								t1=correct_ct_1_state[3][1]^key_3;
								t2=faulty_ct_1_state[3][1]^key_3;
								t1=t1&0xff;
								t2=t2&0xff;
								inv_t1=sbox_inv[t1];
								inv_t2=sbox_inv[t2];								
								if((field_mul_3(fault))==((inv_t1^inv_t2)&0xff)):
									correct_key_pool_1.append((key_0, key_1, key_2, key_3))
									cnt1 = cnt1 + 1
																																
	
# Invert the second ciphertext and dump potential key candidates
cnt2 = 0
for fault in range(1, 256):
	for key_0 in range(0,256):
		t1=correct_ct_2_state[0][0]^key_0;
		t2=faulty_ct_2_state[0][0]^key_0;
		t1=t1&0xff;
		t2=t2&0xff;
		inv_t1=sbox_inv[t1];
		inv_t2=sbox_inv[t2];
		if((field_mul_2(fault))==((inv_t1^inv_t2)&0xff)):
			for key_1 in range(0,256):
				t1=correct_ct_2_state[1][3]^key_1;
				t2=faulty_ct_2_state[1][3]^key_1;
				t1=t1&0xff;
				t2=t2&0xff;
				inv_t1=sbox_inv[t1];
				inv_t2=sbox_inv[t2];
				if(fault==((inv_t1^inv_t2)&0xff)):
					for key_2 in range(0,256):
						t1=correct_ct_2_state[2][2]^key_2;
						t2=faulty_ct_2_state[2][2]^key_2;
						t1=t1&0xff;
						t2=t2&0xff;
						inv_t1=sbox_inv[t1];
						inv_t2=sbox_inv[t2];
						if(fault==((inv_t1^inv_t2)&0xff)):
							for key_3 in range(0, 256):
								t1=correct_ct_2_state[3][1]^key_3;
								t2=faulty_ct_2_state[3][1]^key_3;
								t1=t1&0xff;
								t2=t2&0xff;
								inv_t1=sbox_inv[t1];
								inv_t2=sbox_inv[t2];								
								if((field_mul_3(fault))==((inv_t1^inv_t2)&0xff)):
									for i in range(cnt1):
										if ( (key_0 == correct_key_pool_1[i][0]) and (key_1 == correct_key_pool_1[i][1]) and (key_2 == correct_key_pool_1[i][2]) and (key_3 == correct_key_pool_1[i][3])):
											round_key[0][0] = key_0
											round_key[1][3] = key_1
											round_key[2][2] = key_2
											round_key[3][1] = key_3		
									correct_key_pool_2.append((key_0, key_1, key_2, key_3))
									cnt2 = cnt2 + 1

np.set_printoptions(formatter={'int':hex})
print(round_key)
		
