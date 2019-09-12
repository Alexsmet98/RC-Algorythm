#include "RC_6.h"

int main() {
	std::string in_file_name = "enc.bmp";
	std::string out_file_name = "out_file2.bmp";
	std::string ciphertext_name = "test11.bmp";

	RC_6 encryption_algorithm = RC_6();
	encryption_algorithm.encrypt(in_file_name, ciphertext_name);
	encryption_algorithm.decrypt(ciphertext_name, out_file_name);

	encryption_algorithm.correlation_destribution(in_file_name, ciphertext_name);
	float correlation = encryption_algorithm.get_correlation();
	float distribution_0 = encryption_algorithm.get_distribution_0();
	float distribution_1 = encryption_algorithm.get_distribution_1();

	std::cout << "Correlation: " << correlation << "\n";
	std::cout << "Distribution of 0: " << distribution_0 << "\n";
	std::cout << "Distribution of 1: " << distribution_1 << "\n";
	system("PAUSE");
	return 0;
}