/*
 * Because the standard library random number
 * functions are not availble at the kernel level
 * I wrote this simple random number generator.
 *
 * It uses the multiplicative congruential method.
 * See pg 263 of Banks and Carson "Discrete-Event
 * System Simulation".
 *
 */

void srand(unsigned i);
unsigned rand(void);
float frand(void);
