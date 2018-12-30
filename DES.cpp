/* ========================================================================== **
 *
 *                                    DES.cpp
 *
 * Copyright:
 *  Copyright © 2018, 2019 by Abdelrahman Ahmed Kamal
 *
 * Email: abdelrhman81995@gmail.com
 *
 *
 * -------------------------------------------------------------------------- **
 *
 * Description:
 *
 *  Implements Both DES Encryption, and Decryption.
 *  
 *
 * -------------------------------------------------------------------------- **
 *
 * License:
 *
 *  This is a Free software, feel free to use, edit , or distribute.
 *  You shall not used for any unethical purpose.
 *
 *
 * -------------------------------------------------------------------------- **
 */

//to stop preprocessor warrnings regarding unsecure scanf & printf
#define _CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<string>
#define ENABLE_DEBUG_ALL 0
#include "Debug.h"


//Used to select to wun Either Encryption Alg. or Decryption Alg Statically
#define ENCRYPTION 1
#define DECRYPTION 0

//Represents number of Des DESROUNDS
#define DESROUNDS 16
/*Different Data Sizes used in the Algorithm*/
#define WIDTH_64  64
#define WIDTH_56 56
#define WIDTH_48 48
#define WIDTH_32 32
#define WIDTH_28 28

/*
Preproc.Direct used in SBox()
*/
//Number of S boxes
#define NSBOX 8
//Extracts The Mosst and least significant bits of a 6-bit number
#define RowMask 0x21
//Extracts The inner four bits of a 6-bit number
#define ColMask ~0x21
//Helps Determining Row Number
#define SECONDROW 0x20
#define THIRDROW 0x21

//Rotates Any Given number to the left by certain amount
#define RotateLeft(number,amount) (( number <<amount)|( number>>(WIDTH_28-amount)))
using namespace std;
/*
	*Key Generation Tables
*/
static unsigned char PermutedChoice1[] = { 57, 49, 41, 33, 25, 17, 9,
											1, 58, 50, 42, 34, 26, 18,
											10, 2, 59, 51, 43, 35, 27,
											19, 11, 3, 60, 52, 44, 36,
											63, 55, 47, 39, 31, 23, 15,
											7, 62, 54, 46, 38, 30, 22,
											14, 6, 61, 53, 45, 37, 29,
											21, 13, 5, 28, 20, 12, 4 };

static unsigned char PermutedChoice2[] = {  14, 17, 11, 24, 1, 5, 3, 28,
											15, 6, 21, 10, 23, 19, 12, 4,
											26, 8, 16, 7, 27, 20, 13, 2,
											41, 52, 31, 37, 47, 55, 30, 40,
											51, 45, 33, 48, 44, 49, 39, 56,
											34, 53, 46, 42, 50, 36, 29, 32 };
static unsigned char ShiftAmounts[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

/*
	*S-Boxes
*/
static unsigned char Sboxes[8][4][16] = {
	//SBOX1
	{ { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
	{ 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
	{ 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
	{ 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },
	//SBOX2
	{ { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
	{ 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
	{ 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
	{ 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
	//SBOX3
	{ { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
	{ 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
	{ 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
	{ 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
	//SBOX4
	{ { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
	{ 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
	{ 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
	{ 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
	//SBOX5
	{ { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
	{ 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
	{ 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
	{ 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
	//SBOX6
	{ { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
	{ 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
	{ 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
	{ 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
	//SBOX7
	{ { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
	{ 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
	{ 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
	{ 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
	//SBOX8
	{ { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
	{ 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
	{ 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
	{ 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } } };

/*
	*Des Function Tables
*/
static unsigned char ExpansionPermutation[] = { 32, 1, 2, 3, 4, 5,
												4, 5, 6, 7, 8, 9,
												8, 9, 10, 11, 12, 13,
												12, 13, 14, 15, 16, 17,
												16, 17, 18, 19, 20, 21,
												20, 21, 22, 23, 24, 25,
												24, 25, 26, 27, 28, 29,
												28, 29, 30, 31, 32, 1 };

static unsigned char P_Box[] = {16, 7, 20, 21, 29, 12, 28, 17,
								1, 15, 23, 26, 5, 18, 31, 10,
								2, 8, 24, 14, 32, 27, 3, 9,
								19, 13, 30, 6, 22, 11, 4, 25 };

/*
	*First and last round additional tables
*/
unsigned char InitialPermutation[] = {  58, 50, 42, 34, 26, 18, 10, 2,
										60, 52, 44, 36, 28, 20, 12, 4,
										62, 54, 46, 38, 30, 22, 14, 6,
										64, 56, 48, 40, 32, 24, 16, 8,
										57, 49, 41, 33, 25, 17, 9, 1,
										59, 51, 43, 35, 27, 19, 11, 3,
										61, 53, 45, 37, 29, 21, 13, 5,
										63, 55, 47, 39, 31, 23, 15, 7 };

unsigned char InverseInitialPermutation[] ={40, 8, 48, 16, 56, 24, 64, 32,
											39, 7, 47, 15, 55, 23, 63, 31,
											38, 6, 46, 14, 54, 22, 62, 30,
											37, 5, 45, 13, 53, 21, 61, 29,
											36, 4, 44, 12, 52, 20, 60, 28,
											35, 3, 43, 11, 51, 19, 59, 27,
											34, 2, 42, 10, 50, 18, 58, 26,
											33, 1, 41, 9, 49, 17, 57, 25 };

/*
*KeyHandler()
Manages (1-Key Seperation, 2-Left Rotation, 3-Key Recombination),
Returns The 56-bit key used in the Key for the next Round
*/
inline unsigned long long KeyHandler(unsigned long long KeyBeforeHandling, unsigned short ShiftAmount) {
	//Key Separation
	struct {
		unsigned long Right : WIDTH_28;
		unsigned long : 0;
		unsigned long Left : WIDTH_28;
	}seperate;
	//Extract the lower 28 bits(Right Half bits)
	seperate.Right = (unsigned long)0xffffffff & KeyBeforeHandling;
	//Extracting the next 28 bits (left Half bits)
	seperate.Left = KeyBeforeHandling >> WIDTH_28;
#if(SEPERATED_KEY==1)
	printf("Left Key:%07lX\t\t\t\t,Right Key:%07lX\n", seperate.Left, seperate.Right);
#endif
	//Halves Rotation
	seperate.Right = RotateLeft(seperate.Right, ShiftAmount);
	seperate.Left = RotateLeft(seperate.Left, ShiftAmount);
#if(ROTATED_KEY==1)
	printf("Rotated Left Key:%07lX\t\t\t,Rotated Right Key:%07lX\n", seperate.Left, seperate.Right);
#endif
	//Recombine the key
	//Type casting is very CRUCIAL, as the compiler assumes it's a 32-bit operation by default
	unsigned long long NewKey = (((unsigned long long)seperate.Left << WIDTH_28) | seperate.Right);
#if(RECOMBINED_KEY==1)
	printf("Recombied Key:%014llX\n", NewKey);
#endif
	return NewKey;
}

inline uint64_t Xor(unsigned long long Operand1, unsigned long long Operand2) {
	return (Operand1^Operand2);
}
/*
*Permutation(): Manipulate bits of an input of size <=64 bit and returns the new value
*/
inline static uint64_t Permutation(unsigned short inputSize, uint64_t InputData, const unsigned char *Table, unsigned short outputSize) {

	unsigned long long outputData = 0;
	for (int i = 0; i <outputSize;++i) {
		/*inputSize-Table[i]as the elements of the Table are counted from
			the left most bit starting from 1 till the right most bit assume it's48
			while we are doing binary working with binary in an opposite way
			assume table[i]=5, and inputsize =48 this means we are accessing bit
			48-5=43, referenced to 0 (43 42 ........4 3 2 1 0)
		*/
		if ((InputData&((unsigned long long)1 << (inputSize - Table[i])))!=0)
			outputData |= (unsigned long long)1 << (outputSize-1-i);
	}
	return outputData;
}
/*
*GenerateRoundsKeys(): creates an array of keys of 16 round, returns a pointer to it
*/
inline unsigned long long* GenerateRoundsKeys(unsigned long long Key_64) {

#if(PRINT_ROUNDS_KEYS==1)
	printf("**********************Key Generation for all Rounds***********************\n");
#endif
	uint64_t Key = Permutation(WIDTH_64, Key_64, PermutedChoice1, WIDTH_56);
#if(PERMUTED_CHOICE_1==1)
	printf("Key After Permuted Choice 1:%014llX\n", Key);
#endif
	uint64_t AlteredKey;
	unsigned long long *RoundKeys = new unsigned long long[DESROUNDS];
	for (int i = 0; i < DESROUNDS; i++, Key = AlteredKey) {
#if(PRINT_ROUNDS_KEYS==1)
		printf("***********************Key Generation for Round #%02u***********************\n", i + 1);
#endif
		AlteredKey = KeyHandler(Key, ShiftAmounts[i]);
		RoundKeys[i] = Permutation(WIDTH_56, AlteredKey, PermutedChoice2, WIDTH_48);
#if(PERMUTED_CHOICE_2==1)
		printf("Key After Permuted Choice 2(Round Key):%012llX\n", RoundKeys[i]);
#endif

	}
	return RoundKeys;
}
/*
*SBox() returns a 32-bit output of the 8 S boxes
*/
static inline unsigned long  SBox(unsigned long long XorOutput) {

	unsigned short Sbox_Input[NSBOX];
	{
		unsigned long long MASK = 0xfc0000000000;
		for (int i = WIDTH_48, j = 0; i > 0; i -= 6, j++, MASK >>= 6) {
		Sbox_Input[j] = (XorOutput&MASK) >> (i - 6);
		}
	}
	//Array of 2-D Arrays where each element is an sbox


	//row,column are used to index each sbox
	unsigned short row = 0, column = 0;
	//string SBoxOutputHexa = "";
	unsigned long SBoxOutput = 0;
	{
		for (int i = 0,j=28; i < NSBOX; i++,j-=4) {
			//clear the inner 4bits of the 6-bit value(SBox input)
			row = Sbox_Input[i] & RowMask;
			//Downsize row values to be represented in 2bits
			if (row == SECONDROW)
				row = 2;
			else if (row == THIRDROW)
				row = 3;
			//clearing least and most significant bits then shifting left to get column value
			column = ((Sbox_Input[i] & ColMask) >> 1);
			//based on i we will access the (i+1)th SBox
			SBoxOutput |= (Sboxes[i][row][column]<<j);
		}
	}
	/*string SBoxOutputBinary = "";
	for (int i = 0; i < SBoxOutputHexa.length(); i++) {
		SBoxOutputBinary += HexaToBinary(SBoxOutputHexa[i]);
	}*/

	return SBoxOutput;
}

inline unsigned long DesFunction(unsigned long RightData, unsigned long long PermutedKey) {


	unsigned long long PermutedRightData = 0;
	PermutedRightData = Permutation(WIDTH_32, RightData, ExpansionPermutation, WIDTH_48);
#if(EXPANSION_PERMUTATION_OUTPUT==1)
	printf("Expansion Permutation Output:%012llX\n", Permutation);
#endif
#if(ROUND_KEY==1)
	printf("Round Key:%012llX\n", PermutedKey);
#endif
	unsigned long long XoredPermutedDataAndPermutedKey = 0;
	XoredPermutedDataAndPermutedKey = Xor(PermutedRightData, PermutedKey);
#if(EXPANSION_PERMUTATION_XOR_ROUND_KEY==1)
	printf("(Expansion Permutation XOR Round Key):%012llX\n", XoredPermutedDataAndPermutedKey);
#endif
	unsigned long long SBoxOutput = 0;
	SBoxOutput = SBox(XoredPermutedDataAndPermutedKey);
#if(SBOX_OUTPUT==1)
	printf("S-Box Output :%08lX\n", SBoxOutput);
#endif
	unsigned long  PBoxOutput = 0;
	PBoxOutput = Permutation(WIDTH_32, SBoxOutput, P_Box, WIDTH_32);
#if(P_PERMUTATION_OUTPUT==1)
	printf("P Permutation Output :%08lX\n", PBoxOutput);
#endif
	return PBoxOutput;
}

inline unsigned long long DES(unsigned long long Data, unsigned long long Key, unsigned short Encrypt) {


	unsigned long long *RoundKeys = GenerateRoundsKeys(Key);
#if(RUNNING_DES==1)
	if (Encrypt)
		printf("\n******************************DES Encryption******************************\n");
	else
		printf("\n******************************DES Decryption******************************\n");

#endif
	unsigned long long DataAfterIP = Permutation(64, Data, InitialPermutation, 64);
#if(INITIAL_PERMUTATION==1)
	printf("Initial Permutation Output:%016llX\n", DataAfterIP);
#endif
	unsigned long RightData = DataAfterIP & (unsigned long)0xffffffff;
	unsigned long LeftData = DataAfterIP >> WIDTH_32;
	if (Encrypt) {
		for (unsigned int i = 0; i < DESROUNDS; i++) {
#if(ROUND_NUMBER==1)
			printf("*********************************Round #%02u********************************\n", i + 1);
#endif
#if(PLAIN==1)
			printf("Left Data:%08lX\t\t\t\t,Right Data:%08lX\n", LeftData, RightData);
#endif

			unsigned long NewLeftTemp = RightData;
			RightData = DesFunction(RightData, RoundKeys[i]);
			RightData = Xor(RightData, LeftData);
#if(LEFT_XOR_P_PERMUTATION==1)
			printf("(Left XOR P Permutation Output):%08lX\n", RightData);
#endif
			LeftData = NewLeftTemp;
#if(ROUND_OUTPUT==1)
			printf("Round Output:%08lX%08lX\n", LeftData, RightData);
#endif
		}

	}
	else if (!Encrypt) {
		for (unsigned int i = 0; i < DESROUNDS; i++) {
#if(ROUND_NUMBER==1)
			printf("******************************Round #%02u******************************\n", i + 1);
#endif
#if(PLAIN==1)
			printf("Left Data:%08lX\t\t\t\t,Right Data:%08lX\n", LeftData, RightData);
#endif
			unsigned long NewLeftTemp = RightData;
			RightData = DesFunction(RightData, RoundKeys[15 - i]);

			RightData = Xor(RightData, LeftData);
#if(LEFT_XOR_P_PERMUTATION==1)
			printf("(Left XOR P Permutation Output):%08lX\n", RightData);
#endif
			LeftData = NewLeftTemp;
#if(ROUND_OUTPUT==1)
			printf("Round Output:%08lX%08lX\n", LeftData, RightData);
#endif
		}
	}
	unsigned long long InversePInput = 0;
	//Here we are swapping the resulted left and right then combine them
	InversePInput = (((unsigned long long)RightData << WIDTH_32) | LeftData);
#if (SWAP == 1)
	printf("Swapped Data:%016llX\n", InversePInput);
#endif
	unsigned long long CipherData = Permutation(WIDTH_64, InversePInput, InverseInitialPermutation, WIDTH_64);

	return CipherData;
}
int main() {

	printf("To Run DES properly please insert your input as below\n");
	printf(">Insert \"1\" for Encryption \"0\" for Decryption in DECIMAL Notation without quotes\n");
	printf(">Insert key in CAPITAL HEXA Notation (Input <= 16 HEXA Digits)\n");
	printf(">Insert Data in CAPITAL HEXA NOTATION (Input <= 16 HEXA Digits)\n");
	printf(">Insert a POSITIVE Number of times to run the algorithm in DECIMAL Notation\n");
	unsigned int Enc_Dec;
	scanf("%u", &Enc_Dec);
	unsigned long long Key, OldData;
	unsigned long N;
	scanf("%llX", &Key);
	scanf("%llX", &OldData);
	scanf("%u", &N);
	for (int i = 0; i < N; i++) {
		OldData = DES(OldData, Key, Enc_Dec);
	}
#if(ENABLE_DEBUG_ALL==0)
	printf("%016llX", OldData);

#endif
#if(INITIAL_PERMUTATION_INVERSE==1)
	if (Enc_Dec)
		printf("Cipher Text:%016llX\n", OldData);
	else
		printf("Plain Text:%016llX\n", OldData);
#endif
	system("pause");

}
