#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <cstdlib>
#include <vector>
#include <gmpxx.h>
#include "../include/libhcs/pcs_t.h"
#include "../include/libhcs/hcs_random.h"
#include "../include/libhcs/hcs_shares.h"

/*
 * Threshold decryption where only the servers listed in `part` take part.
 * Servers outside `part` are never written into the hcs_shares structure, so
 * this also exercises the zero-initialised flag array.
 *
 * NOTE: the implementation signature is (pk, vk, hr, bits, threshold, total).
 */
static mpz_class threshold_decrypt(unsigned long total, unsigned long threshold,
                                   const std::vector<unsigned long> &part)
{
    hcs_random *hr = hcs_init_random();
    pcs_t_public_key *pk = pcs_t_init_public_key();
    pcs_t_private_key *vk = pcs_t_init_private_key();
    REQUIRE(pcs_t_generate_key_pair(pk, vk, hr, 256, threshold, total) == 1);

    pcs_t_polynomial *px = pcs_t_init_polynomial(vk, hr);

    mpz_class m = 42;
    mpz_class c;
    pcs_t_encrypt(pk, hr, c.get_mpz_t(), m.get_mpz_t());

    hcs_shares *hs = hcs_init_shares(total);
    for (unsigned long i = 0; i < total; ++i) {
        bool in = false;
        for (std::size_t k = 0; k < part.size(); ++k)
            if (part[k] == i) in = true;
        if (!in)
            continue; /* leave share i untouched (flag must stay 0) */

        mpz_t si, share;
        mpz_inits(si, share, NULL);
        pcs_t_compute_polynomial(vk, px, si, i);
        pcs_t_auth_server *au = pcs_t_init_auth_server();
        pcs_t_set_auth_server(au, si, i);
        pcs_t_share_decrypt(pk, au, share, c.get_mpz_t());
        hcs_set_share(hs, share, i);
        mpz_clears(si, share, NULL);
        pcs_t_free_auth_server(au);
    }

    mpz_class res;
    REQUIRE(pcs_t_share_combine(pk, res.get_mpz_t(), hs) != 0);

    hcs_free_shares(hs);
    pcs_t_free_polynomial(px);
    pcs_t_free_public_key(pk);
    pcs_t_free_private_key(vk);
    hcs_free_random(hr);
    return res;
}

TEST_CASE("hcs_shares flags default to zero") {
    hcs_shares *hs = hcs_init_shares(4);
    REQUIRE(hs != NULL);
    for (unsigned long i = 0; i < 4; ++i)
        REQUIRE(hcs_tst_flag(hs, i) == 0);
    hcs_free_shares(hs);
}

TEST_CASE("pcs_t decrypts when every server participates") {
    REQUIRE(threshold_decrypt(4, 2, std::vector<unsigned long>{0, 1, 2, 3}) == 42);
    REQUIRE(threshold_decrypt(5, 3, std::vector<unsigned long>{0, 1, 2, 3, 4}) == 42);
}

TEST_CASE("pcs_t decrypts from any threshold-sized subset") {
    /* Regression: combine used the full-set Lagrange weights and only worked
     * when all servers participated. */
    REQUIRE(threshold_decrypt(4, 2, std::vector<unsigned long>{0, 1}) == 42);
    REQUIRE(threshold_decrypt(4, 2, std::vector<unsigned long>{2, 3}) == 42);
    REQUIRE(threshold_decrypt(4, 2, std::vector<unsigned long>{1, 3}) == 42);
    REQUIRE(threshold_decrypt(4, 2, std::vector<unsigned long>{0, 3}) == 42);

    REQUIRE(threshold_decrypt(4, 3, std::vector<unsigned long>{0, 1, 2}) == 42);
    REQUIRE(threshold_decrypt(4, 3, std::vector<unsigned long>{1, 2, 3}) == 42);
    REQUIRE(threshold_decrypt(4, 3, std::vector<unsigned long>{0, 2, 3}) == 42);

    REQUIRE(threshold_decrypt(5, 2, std::vector<unsigned long>{1, 4}) == 42);
    REQUIRE(threshold_decrypt(5, 3, std::vector<unsigned long>{0, 2, 4}) == 42);
}

int main(int argc, char *argv[])
{
    return Catch::Session().run(argc, argv);
}
