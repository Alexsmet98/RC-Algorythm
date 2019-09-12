#ifndef RC_6_H
#define RC_6_H

#include <iostream>
#include <string>
#include <ctime>
#include <algorithm>
#include <fstream>

class RC_6 {
private:
	const int w = 32, r = 20, log_w = 5;

	float correlation;
	float distribution_0, distribution_1;

	int key_length;
	int L_length;
	unsigned int* S;
	unsigned int* L;

	unsigned int function(unsigned int x);
	unsigned int CSL(unsigned int a, unsigned int b);
	unsigned int CSR(unsigned int a, unsigned int b);
	std::string generate_phrase();
	void generate_keys();
	void encrypt_words(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d);
	void decrypt_words(unsigned int& a, unsigned int& b, unsigned int& c, unsigned int& d);

public:
	RC_6();
	~RC_6();
	RC_6::RC_6(const RC_6 &copy);
	void encrypt(const std::string& in_file_name, const std::string& out_file_name);
	void decrypt(const std::string& in_file_name, const std::string& out_file_name);
	void correlation_destribution(const std::string& plaintext_name, const std::string& ciphertext_name);


	float get_correlation() { return correlation; }
	float get_distribution_0() { return distribution_0; }
	float get_distribution_1() { return distribution_1; }
	RC_6& operator= (const RC_6& pol);
};

#endif // !RC_6_H