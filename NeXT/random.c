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

#include "random.h"

static unsigned x0=123457;     /* seed */
static unsigned a=16807;       /* constant multiplier */
static unsigned c=0;           /* increment */
static unsigned m=2147483647;  /* modulus */

/*
 * Set the seed to the argument.
 */

void srand(unsigned i)
{
  x0 = i;
}


/*
 * Use Linear Congruential Method to Generate
 * sequence.  Return either int or float...
 */
  
unsigned rand(void)
{
  unsigned tmpseed;

  tmpseed = (a*x0+c) % m;
  x0 = tmpseed;
  return (unsigned) x0;
}



float frand(void)
{
  unsigned tmpseed;

  tmpseed = (a*x0+c) % m;
  x0 = tmpseed;
  return (x0/(float)m);
}
