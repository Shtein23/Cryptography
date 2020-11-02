#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <locale.h>

#define SIZE_OF_BLOCK 1

#ifndef uint64_t
# define uint64_t unsigned long long
#endif

uint64_t calculate_c(int64_t p, int64_t q);
uint64_t calculate_s(uint64_t p, uint64_t q, uint64_t c, uint64_t n);
uint64_t calculate_d(uint64_t m);
uint64_t greatest_common_divider(uint64_t a, uint64_t b);
uint64_t calculation(uint64_t E, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t num);
uint64_t X(uint64_t i, uint64_t a);
uint64_t Y(uint64_t i, uint64_t a, uint64_t b);
uint64_t cipher(unsigned char w, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t num);
uint64_t decipher(unsigned char E, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t p, uint64_t q, uint64_t m, uint64_t d, uint64_t num);
uint64_t prime_number(void);
uint64_t read_bytes(unsigned char * buf);
int64_t legendre_sym(int64_t a, int64_t p);
int64_t jacobi_sym(int64_t a, int64_t n);
int64_t jacobi_sym2(int64_t a, int64_t p);
void make_keys();
void fill(unsigned char * buf, uint64_t num);

uint64_t calculate_c(int64_t p, int64_t q)
{
	uint64_t a = 3;
	uint64_t b = 1000;
	uint64_t c = 0;
	uint64_t sigma_p = 0;
	uint64_t sigma_q = 0;
	while (1)
	{
		c = rand() % (RAND_MAX - a + 1);
		sigma_p = legendre_sym(c, p);
		sigma_q = legendre_sym(c, q);
		if ((((-p - sigma_p) % 4) == 0) && (((-q - sigma_q) % 4) == 0))
		{
			break;
		}
	}
	return c;
}

uint64_t calculate_s(uint64_t p, uint64_t q, uint64_t c, uint64_t n)
{
	srand(time(NULL));
	uint64_t s = 0;
	do
	{
		s = rand();
	} while (!((jacobi_sym2(s*s - c, n) == -1) && (greatest_common_divider(s, n) == 1)));
	return c;
}

uint64_t calculate_d(uint64_t m)
{
	uint64_t d = 0;
	while (1)
	{
		d = rand();
		if ((d > 1) && (greatest_common_divider(d, m) == 1))
			break;
	}
	return d;
}

void make_keys()
{
	srand(time(NULL));
	uint64_t x = legendre_sym(271, 2343);
	uint64_t y = jacobi_sym2((uint64_t)-1, (uint64_t)143);
	uint64_t z = jacobi_sym2((uint64_t)4686, (uint64_t)4686);

	uint64_t p = prime_number();
	uint64_t q = prime_number();
	uint64_t n = p * q;
	uint64_t c = calculate_c(p, q);
	uint64_t s = calculate_s(p, q, c, n);
	uint64_t m = (p - legendre_sym(c, p)) * (q - legendre_sym(c, q)) / 4;
	uint64_t d = calculate_d(m);
	uint64_t obr = inverse(d, m);
	if (obr < 0)
	{
		obr += m;
	}
	uint64_t e = ((m + 1) / 2 * obr) % m;

	unsigned char * buffer = (unsigned char*)malloc(sizeof(unsigned char) * sizeof(uint64_t));
	FILE *public_key_file;
	char name_in0[] = "public_key.bin";
	public_key_file = fopen(name_in0, "wb");

	fill(buffer, n);
	fwrite(buffer, sizeof(n), 1, public_key_file);
	fill(buffer, e);
	fwrite(buffer, sizeof(e), 1, public_key_file);
	fill(buffer, c);
	fwrite(buffer, sizeof(c), 1, public_key_file);
	fill(buffer, s);
	fwrite(buffer, sizeof(s), 1, public_key_file);
	fclose(public_key_file);

	FILE *private_key_file;
	char name_in00[] = "private_key.bin";
	private_key_file = fopen(name_in00, "wb");
	fill(buffer, p);
	fwrite(buffer, sizeof(p), 1, private_key_file);
	fill(buffer, q);
	fwrite(buffer, sizeof(q), 1, private_key_file);
	fill(buffer, m);
	fwrite(buffer, sizeof(m), 1, private_key_file);
	fill(buffer, d);
	fwrite(buffer, sizeof(d), 1, private_key_file);
	fclose(private_key_file);
}

void fill(unsigned char * buf, uint64_t num)
{
	for (int i = 0; i < (sizeof(char) * sizeof(uint64_t)); i++)
	{
		buf[i] = num % 0x100;
		num /= 0x100;
	}
}

uint64_t read_bytes(unsigned char * buf)
{
	uint64_t num = 0;
	char c = 0;
	for (int i = 0; i < (sizeof(char) * sizeof(uint64_t)); i++)
	{
		c = buf[i];
		num += buf[i] << (8 * i);
	}
	return num;
}

int encrypt()
{
	unsigned char * buffer = (unsigned char*)malloc(sizeof(unsigned char) * sizeof(uint64_t));
	uint64_t n = 0;
	uint64_t e = 0;
	uint64_t c = 0;
	uint64_t s = 0;
	uint64_t num = 0;


	FILE *public_key_file;
	char name_in0[] = "public_key.bin";
	if ((public_key_file = fopen(name_in0, "rb")) == NULL)
	{
		printf("Can't get public key file");
		getchar();
		return -1;
	}
	else
	{
		public_key_file = fopen(name_in0, "rb");
		fread(buffer, sizeof(n), 1, public_key_file);
		n = read_bytes(buffer);
		fread(buffer, sizeof(e), 1, public_key_file);
		e = read_bytes(buffer);
		fread(buffer, sizeof(c), 1, public_key_file);
		c = read_bytes(buffer);
		fread(buffer, sizeof(s), 1, public_key_file);
		s = read_bytes(buffer);
		fclose(public_key_file);
	}

	FILE *input;
	char name_in1[] = "input.txt";
	FILE *output;
	char name_in2[] = "encrypted.bin";
	if (((input = fopen(name_in1, "rb")) == NULL) || ((output = fopen(name_in2, "wb")) == NULL))
	{
		printf("Can't get public file");
		getchar();
		return -1;
	}
	else
	{
		int result;
		uint64_t block;
		char b1;
		char b2;
		while (1)
		{
			buffer = (unsigned char*)malloc(1 * (SIZE_OF_BLOCK + 1));
			result = fread(buffer, 1, SIZE_OF_BLOCK, input);
			if (!result)
			{
				break;
			}
			block = 0;
			for (int i = 0; i < SIZE_OF_BLOCK; i++)
			{
				block += buffer[i] << (i * 8);
			}
			block = cipher(block, &b1, &b2, n, e, c, s, num);
			buffer[0] = block;
			buffer[1] = b1;
			buffer[2] = b2;
			fwrite(buffer, 1, (SIZE_OF_BLOCK + 2), output);
			num++;
		}
	}
	return 0;
}

int decrypt()
{
	unsigned char * buffer = (unsigned char*)malloc(sizeof(unsigned char) * sizeof(uint64_t));
	unsigned char * buf_b = (unsigned char*)malloc(sizeof(unsigned char) * 1);
	uint64_t n;
	uint64_t e;
	uint64_t c;
	uint64_t s;
	uint64_t num = 0;

	FILE *public_key_file;
	char name_in0[] = "public_key.bin";
	if ((public_key_file = fopen(name_in0, "rb")) == NULL)
	{
		printf("Can't get public key file");
		getchar();
		return -1;
	}
	else
	{
		public_key_file = fopen(name_in0, "rb");
		fread(buffer, sizeof(n), 1, public_key_file);
		n = read_bytes(buffer);
		fread(buffer, sizeof(e), 1, public_key_file);
		e = read_bytes(buffer);
		fread(buffer, sizeof(c), 1, public_key_file);
		c = read_bytes(buffer);
		fread(buffer, sizeof(s), 1, public_key_file);
		s = read_bytes(buffer);
		fclose(public_key_file);
	}

	uint64_t p;
	uint64_t q;
	uint64_t m;
	uint64_t d;

	FILE *private_key_file;
	char name_in00[] = "private_key.bin";
	if ((private_key_file = fopen(name_in00, "rb")) == NULL)
	{
		printf("Can't get private key file");
		getchar();
		return -1;
	}
	else
	{
		private_key_file = fopen(name_in00, "rb");
		fread(buffer, sizeof(p), 1, public_key_file);
		p = read_bytes(buffer);
		fread(buffer, sizeof(q), 1, public_key_file);
		q = read_bytes(buffer);
		fread(buffer, sizeof(m), 1, public_key_file);
		m = read_bytes(buffer);
		fread(buffer, sizeof(d), 1, public_key_file);
		d = read_bytes(buffer);
		fclose(public_key_file);
	}

	FILE *input;
	char name_in1[] = "encrypted.bin";
	FILE *output;
	char name_in2[] = "decrypted.txt";
	if (((input = fopen(name_in1, "rb")) == NULL) || ((output = fopen(name_in2, "wb")) == NULL))
	{
		printf("Не удалось открыть файл");
		getchar();
		return -1;
	}
	else
	{
		int result;
		uint64_t block;
		char b1 = 0;
		char b2 = 0;
		while (1)
		{
			buffer = (unsigned char*)malloc(1 * SIZE_OF_BLOCK + 2);
			result = fread(buffer, 1, (SIZE_OF_BLOCK + 2), input);
			if (!result)
			{
				break;
			}
			block = 0;
			for (int i = 0; i < SIZE_OF_BLOCK; i++)
			{
				block += buffer[i] << (i * 8);
			}

			b1 = buffer[1];
			b2 = buffer[2];

			block = decipher(block, b1, b2, n, e, c, s, p, q, m, d, num);
			buffer[0] = block;
			fwrite(buffer, 1, SIZE_OF_BLOCK, output);
			num++;
		}
	}
}

uint64_t cipher(unsigned char w, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t num)
{
	w = (uint64_t)w;
	int ja = jacobi_sym(w*w - c, n);
	if (ja == 1)
		*b1 = 0;
	else if (ja == -1)
		*b1 = 1;

	uint64_t a_num = 0;
	uint64_t a_denom = 0;
	uint64_t b_num = 0;
	uint64_t b_denom = 0;
	if (*b1 == 1)
	{
		a_num = w*w + c;
		a_denom = w*w - c;
		b_num = 2 * w;
		b_denom = w*w - c;
	}
	else
	{
		a_num = (w*w + c)*(s*s + c) + 4 * c*s*w;
		a_denom = (w*w - c)*(s*s - c);
		b_num = 2 * s*(w*w + c) + 2 * w*(s*s + c);
		b_denom = (w*w - c)*(s*s - c);
	}

	uint64_t a = a_num*inverse(a_denom, n);
	uint64_t b = b_num*inverse(b_denom, n);

	if (a % 2 == 0)
	{
		*b2 = 0;
	}
	else
	{
		*b2 = 1;
	}

	uint64_t E = 0;
	E = calculation(w, n, e, c, s, num);
	if (E)
	{
		*b1 = E % 2;
		*b2 = (*b1 + 1) % 2;
		return E;
	}
	E = (X(e, a)*inverse(Y(e, a, b), n)) % n;
	return E;
}

uint64_t X(uint64_t i, uint64_t a)
{
	if (i == 1)
		return a;
	else if (i % 2 == 0)
	{
		return (2 * X(i / 2, a)*X(i / 2, a) - 1);
	}
	else
	{
		return (2 * X(i / 2, a) *X((i - 1) / 2 + 1, a) - a);
	}
}

uint64_t Y(uint64_t i, uint64_t a, uint64_t b)
{
	if (i == 1)
		return b;
	else if (i % 2 == 0)
	{
		return 2 * X(i / 2, a)*Y(i / 2, a, b);
	}
	else
	{
		return (2 * X(i / 2, a)*Y((i - 1) / 2 + 1, a, b) - b);
	}
}

uint64_t decipher(unsigned char E, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t p, uint64_t q, uint64_t m, uint64_t d, uint64_t num)
{
	E = (uint64_t)E;

	uint64_t a_num = E*E + c;
	uint64_t a_denom = E*E - c;
	uint64_t b_num = 2 * E;
	uint64_t b_denom = E*E - c;

	uint64_t a = a_num*inverse(a_denom, n);
	uint64_t b = b_num*inverse(b_denom, n);

	E = calculation(E, n, e, c, s, num);
	if (E)
	{
		return E;
	}
	uint64_t Xd = X(d, a);
	uint64_t Yd = Y(d, a, b);

	uint64_t a_shtrih;

	uint64_t w = 0;
	w = calculation(E, n, e, c, s, num);
	if (w)
	{
		*b1 = E % 2;
		*b2 = (*b1 + 1) % 2;
		return w;
	}
	if (!(*b1))
	{
		return 0;
	}
}

uint64_t calculation(uint64_t E, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t num)
{
	num %= 12;
	if (num < 4)
	{
		return (E ^ (unsigned char)(n >> (8 * num)));
	}
	else if ((num >= 4) && (num < 8))
		return (E ^ (unsigned char)(e >> (8 * (num - 4))));
	else if ((num >= 8) && (num < 10))
		return (E ^ (unsigned char)(c >> (8 * (num - 8))));
	else if ((num >= 10) && (num < 12))
		return (E ^ (unsigned char)(s >> (8 * (num - 10))));
}



void extended_euclid(uint64_t a, uint64_t b, uint64_t *x, uint64_t *y, uint64_t *d)
{
	uint64_t q, r, x1, x2, y1, y2;
	if (b == 0) {
		*d = a, *x = 1, *y = 0;
		return;
	}

	x2 = 1, x1 = 0, y2 = 0, y1 = 1;
	while (b > 0) {
		q = a / b, r = a - q * b;
		*x = x2 - q * x1, *y = y2 - q * y1;
		a = b, b = r;
		x2 = x1, x1 = *x, y2 = y1, y1 = *y;
	}

	*d = a, *x = x2, *y = y2;
}

long inverse(uint64_t a, uint64_t n)
{
	uint64_t d, x, y;
	extended_euclid(a, n, &x, &y, &d);
	if (d == 1) return x;
	return 0;
}

uint64_t prime_number(void)
{
	uint64_t a;
	while (1)
	{
		uint64_t z = 0;
		uint64_t kol = 0;
		do
		{
			a = rand();
		} while (a < 3);

		for (uint64_t i = 2; i < a; i++)
		{
			if (a % i == 1)
				continue;
			if (a % i == 0)
			{
				z = 1;
				break;
			}
		}
		if (z == 0)
		{
			break;
		}
	}
	return a;
}

uint64_t get_multiplier(uint64_t N)
{

	for (uint64_t i = 2; i*i <= N; i++)
	{
		if (N%i == 0)
		{
			return i;
		}
	}
	return 0;
}

uint64_t greatest_common_divider(uint64_t a, uint64_t b)
{
	return b ? greatest_common_divider(b, a % b) : a;
}

int64_t legendre_sym(int64_t a, int64_t p)
{
	if (a == 0)
	{
		return 0;
	}
	else if (a == 1)
	{
		return 1;
	}
	else if ((a % 2) == 0)
	{
		return (legendre_sym(a / 2, p) * pow(-1, (p*p - 1) / 8));
	}
	else if (a % 2 == 1)
	{
		return (legendre_sym(p % a, a) * pow(-1, (a - 1)*(p - 1) / 4));
	}

}

int64_t jacobi_sym2(int64_t a, int64_t p)
{
	int64_t res = 1;
	int64_t multiplier = get_multiplier(p);
	while (multiplier)
	{
		res *= legendre_sym(a, multiplier);
		p /= multiplier;
		multiplier = 0;
	}
	res *= legendre_sym(a, p);
}

int64_t jacobi_sym(int64_t a, int64_t n)
{

	if (a < 0)
	{
		return (jacobi_sym(-a, n) * pow(-1, (n - 1) / 2));
	}
	else if (a % 2 == 0)
	{
		return (jacobi_sym(a / 2, n) * pow(-1, (n*n - 1) / 8));
	}
	else if (a == 1)
	{
		return 1;
	}
	else if (a < n)
	{
		return (pow(-1, (a - 1)*(n - 1) / 4) * jacobi_sym(n, a));
	}
	else
	{
		return (a % n, n);
	}
}

int main()
{
	setlocale(LC_ALL, "Rus");
	printf("%s\n", "Нажмите g для генерации ключей, e для шифрования, d для дешифрования");
	char mode;
	scanf("%c", &mode);
	while (!((mode == 'e') || (mode == 'E') || (mode == 'd') || (mode == 'D') || (mode == 'g') || (mode == 'G')))
	{
		printf("%s\n", "Повторите ввод");
		scanf("%c", &mode);
	}
	if ((mode == 'g') || (mode == 'G'))
	{
		make_keys();
		printf("%s\n", "Генерация ключей завершена");
	}
	else if ((mode == 'e') || (mode == 'E'))
	{
		if (encrypt() == -1)
		{
			printf("%s\n", "Ошибка открытия файла");
			return 0;
		}
		printf("%s\n", "Done");
	}
	else if ((mode == 'd') || (mode == 'd'))
	{
		if (decrypt() == -1)
		{
			printf("%s\n", "Ошибка открытия файла");
			return 0;
		}
		printf("%s\n", "Done");
	}

	getchar();
	return 0;

}