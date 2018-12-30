#ifdef ENABLE_DEBUG_ALL
#if(ENABLE_DEBUG_ALL==1)
/*
*Debug KeyHandler()
*/

#define SEPERATED_KEY 1
#define ROTATED_KEY 1
#define RECOMBINED_KEY 1

/*
*Debug GenerateRoundsKeys()
*/
#define PRINT_ROUNDS_KEYS 1
#define PERMUTED_CHOICE_1 1
#define PERMUTED_CHOICE_2 1

/*
*Debug DES()
*/
#define RUNNING_DES 1
#define ROUND_NUMBER 1
#define INITIAL_PERMUTATION 1
#define PLAIN 1
#define LEFT_XOR_P_PERMUTATION 1
#define ROUND_OUTPUT 1
#define SWAP 1
#define INITIAL_PERMUTATION_INVERSE 1

/*
*Debug DesFuction()
*/

#define EXPANSION_PERMUTATION_OUTPUT 1
#define ROUND_KEY 1
#define EXPANSION_PERMUTATION_XOR_ROUND_KEY 1
#define SBOX_OUTPUT 1
#define P_PERMUTATION_OUTPUT 1
#elif(ENABLE_DEBUG_ALL==0)
/*
*Debug KeyHandler()
*/

#define SEPERATED_KEY 0
#define ROTATED_KEY 0
#define RECOMBINED_KEY 0

/*
*Debug GenerateRoundsKeys()
*/
#define PRINT_ROUNDS_KEYS 0
#define PERMUTED_CHOICE_0 0
#define PERMUTED_CHOICE_2 0

/*
*Debug DES()
*/
#define RUNNING_DES 0
#define ROUND_NUMBER 0
#define INITIAL_PERMUTATION 0
#define PLAIN 0
#define LEFT_XOR_P_PERMUTATION 0
#define ROUND_OUTPUT 0
#define SWAP 0
#define INITIAL_PERMUTATION_INVERSE 0

/*
*Debug DesFuction()
*/

#define EXPANSION_PERMUTATION_OUTPUT 0
#define ROUND_KEY 0
#define EXPANSION_PERMUTATION_XOR_ROUND_KEY 0
#define SBOX_OUTPUT 0
#define P_PERMUTATION_OUTPUT 0
#endif
#endif
