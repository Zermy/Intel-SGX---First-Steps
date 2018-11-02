#include "Test_Step_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <cstring>
#include <cstdlib>
sgx_ecc_state_handle_t ctx;
sgx_ec256_private_t p_private;
sgx_ec256_public_t p_public;



int init()
{
	sgx_status_t ret = SGX_SUCCESS;
	ret = sgx_ecc256_open_context(&ctx);
	if (ret != SGX_SUCCESS)
		return ret;
	ret = sgx_ecc256_create_key_pair(&p_private, &p_public, ctx);
	return ret;
}


int sign(char* message, size_t len, void* buff, size_t sig_len)
{
	if (sig_len != sizeof(sgx_ec256_signature_t))
		return -1;

	sgx_status_t ret = sgx_ecdsa_sign((uint8_t*)message, len, &p_private, (sgx_ec256_signature_t*)buff, ctx);
	
	return ret;
}

int verify(char* message, size_t len, void* buff, size_t sig_len)
{
	uint8_t res;

	if (sig_len != sizeof(sgx_ec256_signature_t))
		return -1;

	sgx_status_t ret = sgx_ecdsa_verify((uint8_t*)message, len, &p_public, (sgx_ec256_signature_t*)buff, &res, ctx);

	return res;

}

int close()
{
	return sgx_ecc256_close_context(&ctx);
}


