#pragma once

#define _PASSGEN_BEGIN namespace generator{
#define _PASSGEN_END }

#include <random>
#include <chrono>
#include <cmath>
#include <vector>

const char ascii_pool[] = "!\"#$%&\'()*+,-./0123456789:;<=>?ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz";
const uint32_t ascii_length = sizeof(ascii_pool) / sizeof(char);

template<typename Ty_>
struct Vector2 {
public:
	Ty_ x, y;
	Vector2(Ty_ a, Ty_ b) : x(a), y(b) {}
};

enum char_type {
	upper_   = 0,
	lower_   = 1,
	digit_   = 2,
	special_ = 3
};

_PASSGEN_BEGIN
int random_int(int lower_bound = 0, int upper_bound = ascii_length) {
	if (lower_bound >= upper_bound)
		return 0;
	uint32_t seed = (uint32_t)std::chrono::steady_clock::now().time_since_epoch().count();
	std::default_random_engine engine(seed);
	std::uniform_int_distribution<int> distribution(lower_bound, upper_bound);
	return distribution(engine);
};

bool compare_w2(const int lower_bound, const int value, const int upper_bound) {
	if (lower_bound <= value && value <= upper_bound) 
		return true; 
	else 
		return false; 
}

double max_entropy(const double password_length) { return password_length * log2(94); }

char_type chartypeof(const char character) {
	// compares the ascii value of char to ranges of different char types
	bool is_uppercase = compare_w2(65, int(character), 90);
	bool is_lowercase = compare_w2(97, int(character), 122);
	bool is_digit	  = compare_w2(48, int(character), 57);
	bool is_special_char =
		compare_w2(33, int(character), 47) || \
		compare_w2(58, int(character), 64) || \
		compare_w2(91, int(character), 96) || \
		compare_w2(123, int(character), 126);

	if      (is_uppercase)
		return upper_; 

	else if (is_lowercase)   
		return lower_; 

	else if (is_digit)        
		return digit_; 

	else if (is_special_char) 
		return special_; 
};

std::vector<uint32_t> char_stats(const std::string& str) {
	uint32_t upper_count = NULL, lower_count = NULL, digit_count = NULL, special_count = NULL;
	for (uint32_t i = 0; i < str.size(); i++) {
		if		(chartypeof(str[i]) == 0) 
			upper_count++;
		
		else if (chartypeof(str[i]) == 1) 
			lower_count++;
		
		else if (chartypeof(str[i]) == 2) 
			digit_count++;
		
		else if (chartypeof(str[i]) == 3) 
			special_count++;
	}
	return { upper_count, lower_count, digit_count, special_count };
}

double entropy_bits(const std::string& password) {
	uint32_t pool_size = 0;

	// ignore states to prevent overaddition to pool_size
	bool ignore_special_chars = 0, ignore_digits = 0, ignore_uppercase = 0, ignore_lowercase = 0;

	for (uint32_t i = 0; i < password.size(); i++) {
		char_type i_char = chartypeof(password[i]);

		if (i_char == 0 && !ignore_uppercase) {
			pool_size += 26;
			ignore_uppercase = 1;
		}
		else if (i_char == 1 && !ignore_lowercase) {
			pool_size += 26;
			ignore_lowercase = 1;
		}
		else if (i_char == 2 && !ignore_digits) {
			pool_size += 10;
			ignore_digits = 1;
		}
		else if (i_char == 3 && !ignore_special_chars) {
			pool_size += 32;
			ignore_special_chars = 1;
		}
	}

	/*
	* Entropy Bits Formula:
	* E = log2(R^L)
	* E = L * log2(R) (using the laws of log)
	* where R is the pool size
	* L is the length of the password
	* E is the entropy bits
	*
	* Number of tries that it will take to crack password can be calculated by
	* 2^entropy_bits
	*		or
	* pow(2, password.size() * log2(pool_size));
	*
	* Source: https://www.omnicalculator.com/other/password-entropy
	*/

	return password.size() * log2(pool_size);
}

/* Old function with while loop
void enlarge_pool(std::string& password) {

	const char upper_pool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const char lower_pool[] = "abcdefghijklmnopqrstuvwxyz";
	const char digit_pool[] = "0123456789";
	const char special_pool[] = "!\"#$%&\'()*+,-./:;<=>?";

	const uint32_t upper_length = sizeof(upper_pool) / sizeof(char);
	const uint32_t lower_length = sizeof(lower_pool) / sizeof(char);
	const uint32_t digit_length = sizeof(digit_pool) / sizeof(char);
	const uint32_t special_length = sizeof(special_pool) / sizeof(char);

	while (true) { // repeats if multiple char types are missing
		if (entropy_bits(password) == max_entropy(password.size())) { return; } // if the password is already strong discards
		else {
			Vector2<uint32_t> instruction(1, 0); // for storing the pools to replace
			std::vector<uint32_t> password_stats = char_stats(password);

			for (uint32_t i = 0; i < password_stats.size(); i++) {
				if (password_stats[i] > instruction.x) { instruction.x = i; } // finds the largest amount of char type
				else if (password_stats[i] == 0) { instruction.y = i; } // finds the missing char type
			}
			for (uint32_t i = 0; i < password.size(); i++) {
				if (chartypeof(password[i]) == instruction.x) {
					if (instruction.y == 0) { password[i] = upper_pool[random_int(0, upper_length)]; } // if the missing char type is a upper case char
					else if (instruction.y == 1) { password[i] = lower_pool[random_int(0, lower_length)]; } // if the missing char type is a lower case char
					else if (instruction.y == 2) { password[i] = digit_pool[random_int(0, digit_length)]; } // if the missing char type is a digit char
					else if (instruction.y == 3) { password[i] = special_pool[random_int(0, special_length)]; } // if the missing char type is a special char
					break;
				}
			}
		}
	}
}
*/

void enlarge_pool(std::string& password) {
	const char upper_pool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const char lower_pool[] = "abcdefghijklmnopqrstuvwxyz";
	const char digit_pool[] = "0123456789";
	const char special_pool[] = "!\"#$%&\'()*+,-./:;<=>?";

	const uint32_t upper_length   = sizeof(upper_pool)   / sizeof(char);
	const uint32_t lower_length   = sizeof(lower_pool)   / sizeof(char);
	const uint32_t digit_length   = sizeof(digit_pool)   / sizeof(char);
	const uint32_t special_length = sizeof(special_pool) / sizeof(char);
	if (entropy_bits(password) == max_entropy(password.size())) 
		return;  // if the password is already strong discards
	else {
		Vector2<uint32_t> instruction(1, 0); // for storing the pools to replace
		std::vector<uint32_t> password_stats = char_stats(password);

		for (uint32_t i = 0; i < password_stats.size(); i++) {
			if (password_stats[i] > instruction.x) 
				instruction.x = i;// finds the largest amount of char type
			else if (password_stats[i] == 0) 
				instruction.y = i; // finds the missing char type
		}
		for (uint32_t i = 0; i < password.size(); i++) {
			if (chartypeof(password[i]) == instruction.x) {
				if (instruction.y == 0) 
					password[i] = upper_pool[random_int(0, upper_length)];  // if the missing char type is a upper case char
				else if (instruction.y == 1)  
					password[i] = lower_pool[random_int(0, lower_length)]; // if the missing char type is a lower case char
				else if (instruction.y == 2)  
					password[i] = digit_pool[random_int(0, digit_length)];  // if the missing char type is a digit char
				else if (instruction.y == 3) 
					password[i] = special_pool[random_int(0, special_length)]; // if the missing char type is a special char
				break;
			}
		}
		if (entropy_bits(password))
			enlarge_pool(password);
	}
}

std::string generate_password(uint32_t length = 8) {
	std::string password(length, ' ');
	for (uint32_t i = 0; i < password.size(); i++) 
		password[i] = ascii_pool[random_int()]; 
	enlarge_pool(password);
	return password;
}

bool any_dupes(std::string& str) {
	for (size_t i = 1; i < str.size() - 1; i++) 
		if (str[i] == str[i + 1] || str[i] == str[i - 1]) 
			return true;
	return false;
}

void remove_duplicates(std::string& str) {
	for (size_t i = 1; i < str.size() - 1; i++) {
		while (str[i] == str[i + 1] || str[i] == str[i - 1])  
			str[i] = ascii_pool[random_int()]; 
	}
}
_PASSGEN_END