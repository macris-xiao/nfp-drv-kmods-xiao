#include <nfp.h>

__export __ctm int sym_ctm[32];
__export __emem int sym_emem[32];
__export __declspec((emem0_cache_upper)) int sym_cache[32];

int main(void)
{
	while (1)
		__asm ctx_arb[kill];
}
