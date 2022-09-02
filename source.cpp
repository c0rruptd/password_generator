#include <iostream>
#include "password_generator.h"

using namespace generator;

std::ostream& operator<<(std::ostream& stream, std::vector<uint32_t> char_stats) {
	stream << "Upper Characters: " << char_stats[0] << std::endl;
	stream << "Lower Characters: " << char_stats[1] << std::endl;
	stream << "Digits: " << char_stats[2] << std::endl;
	stream << "Special Characters: " << char_stats[3] << std::endl;
	return stream;
}
#if 1
int main() {
	std::string sample_string = "Aa1!";
	std::string sample_password1 = generate_password(18); // generates a 18-char-password 
	std::string sample_password2 = "QDMM,MNi0ISP7dYi";    // sample password for demonstrating remove_duplicate() & any_dupes() functions

	std::cout << "Random integer: " << random_int(0, 10) << std::endl; // generates a random integer between 0 and 10
	std::cout << "Maximum entropy of a 18 character password: " << max_entropy(18) << std::endl << std::endl;
	// returns the maximum possible entropy bits of a 16 char password
	std::cout << "Char type of 'A': " << chartypeof('A') << ":" << std::endl; // returns char type

	/* upper case -> 0
	*  lower case -> 1
	*  digit -> 2
	*  special -> 3 */

	std::cout << "Char stats of " << sample_string << "\n" << char_stats(sample_string) << std::endl << std::endl;
	std::cout << "Entropy bits of " << sample_password1 << ":\n" << entropy_bits(sample_password1) << " bits" << std::endl;
	std::cout << "Number of tries required to brute force password: " << pow(2, entropy_bits(sample_password1)) << std::endl << std::endl;

	std::cout << "Example password with duplicates: " << sample_password2 << std::endl;
	std::cout << "Any duplicates? " << any_dupes(sample_password2) << std::endl;
	remove_duplicates(sample_password2);
	std::cout << "After removing duplicates: " << sample_password2 << std::endl;
	std::cout << "Any duplicates? " << any_dupes(sample_password2) << std::endl;
}
#elif 0
int main() { // for debugging later
	
}
#endif