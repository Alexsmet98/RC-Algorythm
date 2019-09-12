#include "RC_6.h"

RC_6::RC_6() {
	std::cout << "Select key length: 1)128bit 2)192bit 3)256bit\n";
	while (true) {
		char variant = 0;
		std::cin >> variant;
		if (variant == '1') {
			key_length = 128;
			break;
		}
		else if (variant == '2') {
			key_length = 192;
			break;
		}
		else if (variant == '3') {
			key_length = 256;
			break;
		}
		std::cout << "Enter \'1\', \'2\' or \'3\': ";
	}
	L_length = key_length / w;

	S = (unsigned int*)malloc(sizeof(unsigned int) * (2 * r + 4));

	L = (unsigned int*)malloc(sizeof(unsigned int) * L_length);

	generate_keys();

	correlation = 0;
	distribution_0 = 0;
	distribution_1 = 0;
}

RC_6::RC_6(const RC_6 &copy) {
	std::cout << "Copy constructor is working" << std::endl;
	const int w = copy.w, r = copy.r, log_w = copy.log_w;
	key_length = copy.key_length;
	L_length = copy.L_length;
	S = (unsigned int*)malloc(sizeof(unsigned int) * (2 * copy.r + 4));
	size_t i = sizeof(unsigned int) * (2 * copy.r + 4);
	for (size_t j = 0; j < i; ++j) 
	{
		S[i] = copy.S[i];
	}
	L = (unsigned int*)malloc(sizeof(unsigned int) * copy.L_length);
	i = sizeof(unsigned int) * copy.L_length;
	for (size_t j = 0; j < i; ++j)
	{
		L[i] = copy.L[i];
	}
}

RC_6::~RC_6() {
	if (S != NULL)
		free(S);
	if (L != NULL)
		free(L);
}

void RC_6::generate_keys() {
	const unsigned int P = 0xB7E15163;
	const unsigned int Q = 0x9E3779B9;

	std::cout << "Do you want to generate the key automatically? (y/n): ";
	std::string phrase;
	while (true) {
		char c = 0;
		std::cin >> c;
		if (c == 'y' || c == 'Y') {
			phrase = generate_phrase();
			break;
		}
		else if (c == 'n' || c == 'N') {
			std::cout << "Enter a phrase with a maximum length of " << key_length / 8 << " characters: ";
			while (true) {
				std::cin >> phrase;
				if (phrase.length() > key_length / 8)
					std::cout << "Length of phrase more " << key_length / 8 << " characters, enter phrase again: ";
				else
					break;
			}
			break;
		}
		else
			std::cout << "You need to enter \'y\' or \'n\': ";
	}

	int i, j;
	for (i = 0, j = 0; i < L_length && j + 3 < phrase.length(); i++, j += 4) {
		L[i] = ((unsigned char)phrase[j] << 24) + ((unsigned char)phrase[j + 1] << 16) +
			((unsigned char)phrase[j + 2] << 8) + (unsigned char)phrase[j + 3];
	}
	if (i < L_length) {
		L[i] = 0;
		int shift = 24;
		for (; j < phrase.length(); j++) {
			L[i] += (unsigned char)phrase[j] << shift;
			shift -= 8;
		}
		if (shift != 24)
			i++;
		for (; i < L_length; i++) {
			L[i] = 0;
		}
	}

	S[0] = P;
	for (i = 1; i < 2 * r + 4; i++) {
		S[i] = S[i - 1] + Q;
	}

	int v = std::max(2 * r + 4, L_length) * 3;
	unsigned int A = 0, B = 0;
	i = 0, j = 0;

	for (int count = 0; count < v; count++) {
		S[i] = CSL(S[i] + A + B, 3);
		A = S[i];
		i++;
		if (i == 2 * r + 4)
			i = 0;

		L[j] = CSL(L[j] + A + B, A + B);
		B = L[j];
		j++;
		if (j == L_length)
			j = 0;
	}
}

void RC_6::encrypt(const std::string& in_file_name, const std::string& out_file_name) {
	std::ifstream in_file;
	std::ofstream out_file;

	in_file.open(in_file_name, std::ifstream::binary);

	in_file.seekg(0, in_file.end);
	size_t size_of_file = in_file.tellg();
	in_file.seekg(0, in_file.beg);

	unsigned char rem = 16 - size_of_file % 16;

	char* buffer = (char*)malloc(sizeof(char) * (size_of_file + rem));
	in_file.read(buffer, size_of_file);

	in_file.close();

	for (int j = 0; j < rem; j++)
		buffer[size_of_file + j] = 0;

	buffer[size_of_file + rem - 1] = rem;



	size_t i;
	for (i = 0; i + 15 < size_of_file + rem; i += 16) {
		unsigned int a, b, c, d;
		a = ((unsigned char)buffer[i] << 24) + ((unsigned char)buffer[i + 1] << 16) +
			((unsigned char)buffer[i + 2] << 8) + (unsigned char)buffer[i + 3];
		b = ((unsigned char)buffer[i + 4] << 24) + ((unsigned char)buffer[i + 5] << 16) +
			((unsigned char)buffer[i + 6] << 8) + (unsigned char)buffer[i + 7];
		c = ((unsigned char)buffer[i + 8] << 24) + ((unsigned char)buffer[i + 9] << 16) +
			((unsigned char)buffer[i + 10] << 8) + (unsigned char)buffer[i + 11];
		d = ((unsigned char)buffer[i + 12] << 24) + ((unsigned char)buffer[i + 13] << 16) +
			((unsigned char)buffer[i + 14] << 8) + (unsigned char)buffer[i + 15];

		encrypt_words(a, b, c, d);

		buffer[i] = a >> 24, buffer[i + 1] = a >> 16, buffer[i + 2] = a >> 8, buffer[i + 3] = a;
		buffer[i + 4] = b >> 24, buffer[i + 5] = b >> 16, buffer[i + 6] = b >> 8, buffer[i + 7] = b;
		buffer[i + 8] = c >> 24, buffer[i + 9] = c >> 16, buffer[i + 10] = c >> 8, buffer[i + 11] = c;
		buffer[i + 12] = d >> 24, buffer[i + 13] = d >> 16, buffer[i + 14] = d >> 8, buffer[i + 15] = d;
	}

	out_file.open(out_file_name, out_file.binary);
	out_file.write(buffer, size_of_file + rem);
	//out_file.write(size, sizeof(size_t));
	out_file.close();

	free(buffer);
	//free(size);
}

void RC_6::decrypt(const std::string& in_file_name, const std::string& out_file_name) {
	std::ifstream in_file;
	std::ofstream out_file;

	in_file.open(in_file_name, std::ifstream::binary);

	in_file.seekg(0, in_file.end);
	size_t size_of_file = in_file.tellg();
	in_file.seekg(0, in_file.beg);
	char* buffer = (char*)malloc(sizeof(char) * size_of_file);
	in_file.read(buffer, size_of_file);

	in_file.close();

	size_t i;
	for (i = 0; i + 15 < size_of_file; i += 16) {
		unsigned int a, b, c, d;
		a = ((unsigned char)buffer[i] << 24) + ((unsigned char)buffer[i + 1] << 16) +
			((unsigned char)buffer[i + 2] << 8) + (unsigned char)buffer[i + 3];
		b = ((unsigned char)buffer[i + 4] << 24) + ((unsigned char)buffer[i + 5] << 16) +
			((unsigned char)buffer[i + 6] << 8) + (unsigned char)buffer[i + 7];
		c = ((unsigned char)buffer[i + 8] << 24) + ((unsigned char)buffer[i + 9] << 16) +
			((unsigned char)buffer[i + 10] << 8) + (unsigned char)buffer[i + 11];
		d = ((unsigned char)buffer[i + 12] << 24) + ((unsigned char)buffer[i + 13] << 16) +
			((unsigned char)buffer[i + 14] << 8) + (unsigned char)buffer[i + 15];

		decrypt_words(a, b, c, d);

		buffer[i] = a >> 24, buffer[i + 1] = a >> 16, buffer[i + 2] = a >> 8, buffer[i + 3] = a;
		buffer[i + 4] = b >> 24, buffer[i + 5] = b >> 16, buffer[i + 6] = b >> 8, buffer[i + 7] = b;
		buffer[i + 8] = c >> 24, buffer[i + 9] = c >> 16, buffer[i + 10] = c >> 8, buffer[i + 11] = c;
		buffer[i + 12] = d >> 24, buffer[i + 13] = d >> 16, buffer[i + 14] = d >> 8, buffer[i + 15] = d;
	}

	size_of_file -= (unsigned char)buffer[size_of_file - 1];

	//if (size < size_of_file) {
	out_file.open(out_file_name, out_file.binary);
	out_file.write(buffer, size_of_file);
	out_file.close();
	//}

	free(buffer);
}

unsigned int RC_6::CSL(unsigned int a, unsigned int b) {
	unsigned int unit_mask = 1;
	unsigned int mask_b = unit_mask;
	for (int i = 1; i < log_w; i++) {
		mask_b += unit_mask << i;
	}
	b = b & mask_b;

	unsigned int mask_a = mask_b << (32 - log_w);
	unsigned int cycle_transfer = a & mask_a;
	cycle_transfer = cycle_transfer >> (32 - log_w);
	a = (a << log_w) + cycle_transfer;

	return a;
}

unsigned int RC_6::CSR(unsigned int a, unsigned int b) {
	unsigned int unit_mask = 1;
	unsigned int mask_b = unit_mask;
	for (int i = 1; i < log_w; i++) {
		mask_b += unit_mask << i;
	}
	b = b & mask_b;

	unsigned int mask_a = mask_b;
	unsigned int cycle_transfer = a & mask_a;
	cycle_transfer = cycle_transfer << (32 - log_w);
	a = (a >> log_w) + cycle_transfer;

	return a;
}

void RC_6::encrypt_words(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d) {
	b += S[0];
	d += S[1];
	for (int i = 1; i <= r; i++) {
		unsigned int t_b = b;
		unsigned int t_d = d;
		unsigned int csl_b = CSL(function(b), log_w);
		unsigned int csl_d = CSL(function(d), log_w);

		d = CSL(a ^ csl_b, csl_d) + S[2 * i];
		b = CSL(c ^ csl_d, csl_b) + S[2 * i + 1];
		a = t_b;
		c = t_d;
	}
	a += S[2 * r + 2];
	c += S[2 * r + 3];
}

void RC_6::decrypt_words(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d) {
	a -= S[2 * r + 2];
	c -= S[2 * r + 3];
	for (int i = r; i >= 1; i--) {
		unsigned int t_a = a;
		unsigned int t_c = c;
		unsigned int csl_a = CSL(function(a), log_w);
		unsigned int csl_c = CSL(function(c), log_w);

		a = CSR(d - S[2 * i], csl_c) ^ csl_a;
		c = CSR(b - S[2 * i + 1], csl_a) ^ csl_c;
		b = t_a;
		d = t_c;
	}
	b -= S[0];
	d -= S[1];
}

unsigned int RC_6::function(unsigned int x) {
	return x * (2 * x + 1);
}

std::string RC_6::generate_phrase() {
	std::string phrase;
	phrase.resize(key_length / 8);
	srand(time(NULL));
	for (int i = 0; i < key_length / 8; i++) {
		phrase[i] = rand();
	}
	std::cout << "Your auto-generated phrase: " << phrase << '\n';
	return phrase;
}

void RC_6::correlation_destribution(const std::string& plaintext_name, const std::string& ciphertext_name) {
	std::ifstream plaintext, ciphertext;

	plaintext.open(plaintext_name, plaintext.binary);
	plaintext.seekg(0, plaintext.end);
	int size1 = plaintext.tellg();
	plaintext.seekg(0, plaintext.beg);
	unsigned char* buffer1 = (unsigned char*)malloc(sizeof(unsigned char) * size1);
	plaintext.read((char*)buffer1, size1);
	plaintext.close();

	ciphertext.open(ciphertext_name, ciphertext.binary);
	ciphertext.seekg(0, ciphertext.end);
	int size2 = ciphertext.tellg();
	ciphertext.seekg(0, ciphertext.beg);
	unsigned char* buffer2 = (unsigned char*)malloc(sizeof(unsigned char) * size2);
	ciphertext.read((char*)buffer2, size2);
	ciphertext.close();

	if (size1 >= size2)
		return;

	int n_matches = 0, n_mismatches = 0;
	int n_0 = 0, n_1 = 0;

	for (int i = 0; i < size2; i++) {
		for (int j = 0; j < 8; j++) {
			unsigned char a2 = (buffer2[i] >> j) % 2;
			if (a2 == 0)
				n_0++;
			else if (a2 == 1)
				n_1++;
			if (i >= size1)
				continue;
			unsigned char a1 = (buffer1[i] >> j) % 2;
			if (a1 == a2)
				n_matches++;
			else
				n_mismatches++;
		}
	}

	correlation = (float)(n_matches - n_mismatches) / (size1 * 8.0);
	//if (correlation < 0)
	//correlation = -correlation;
	distribution_0 = (float)n_0 / (size2 * 8);
	distribution_1 = (float)n_1 / (size2 * 8);

	free(buffer1);
	free(buffer2);
}

RC_6&
RC_6::operator= (const RC_6& copy)
{
	std::cout << "Operator + is working" << std::endl;
	const int w = copy.w, r = copy.r, log_w = copy.log_w;
	key_length = copy.key_length;
	L_length = copy.L_length;
	if (S)
		free(S);
	if (L)
		free (L);
	S = (unsigned int*)malloc(sizeof(unsigned int) * (2 * copy.r + 4));
	size_t i = sizeof(unsigned int) * (2 * copy.r + 4);
	for (size_t j = 0; j < i; ++j)
	{
		S[i] = copy.S[i];
	}
	L = (unsigned int*)malloc(sizeof(unsigned int) * copy.L_length);
	i = sizeof(unsigned int) * copy.L_length;
	for (size_t j = 0; j < i; ++j)
	{
		L[i] = copy.L[i];
	}
	return *this;
}