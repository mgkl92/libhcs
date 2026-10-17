#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <cstdlib>
#include <vector>
#include <gmpxx.h>
#include "../include/libhcs/djcs_t.h"
#include "../include/libhcs/hcs_random.h"

/*
 * Threshold Damgard-Jurik decryption where only the servers listed in `part`
 * take part. djcs_t signals a missing share by the value zero, so servers
 * outside `part` are zeroed.
 *
 * NOTE: the implementation signature is (pk, vk, hr, s, bits, threshold, total).
 */
static mpz_class djcs_t_decrypt(unsigned long s, unsigned long total,
                                unsigned long threshold,
                                const std::vector<unsigned long> &part)
{
    hcs_random *hr = hcs_init_random();
    djcs_t_public_key *pk = djcs_t_init_public_key();
    djcs_t_private_key *vk = djcs_t_init_private_key();
    djcs_t_generate_key_pair(pk, vk, hr, s, 256, threshold, total);

    mpz_class m = 12345;
    mpz_class c;
    djcs_t_encrypt(pk, hr, c.get_mpz_t(), m.get_mpz_t());

    mpz_t *coeff = djcs_t_init_polynomial(vk, hr);
    mpz_t *shares = (mpz_t *)malloc(sizeof(mpz_t) * total);
    for (unsigned long i = 0; i < total; ++i)
        mpz_init(shares[i]);

    for (unsigned long i = 0; i < total; ++i) {
        mpz_t si;
        mpz_init(si);
        djcs_t_compute_polynomial(vk, coeff, si, i);
        djcs_t_auth_server *au = djcs_t_init_auth_server();
        djcs_t_set_auth_server(au, si, i);
        djcs_t_share_decrypt(pk, au, shares[i], c.get_mpz_t());
        mpz_clear(si);
        djcs_t_free_auth_server(au);

        bool in = false;
        for (std::size_t k = 0; k < part.size(); ++k)
            if (part[k] == i) in = true;
        if (!in)
            mpz_set_ui(shares[i], 0); /* zero == absent */
    }

    mpz_class res;
    djcs_t_share_combine(pk, res.get_mpz_t(), shares);

    for (unsigned long i = 0; i < total; ++i)
        mpz_clear(shares[i]);
    free(shares);
    djcs_t_free_polynomial(vk, coeff);
    djcs_t_free_public_key(pk);
    djcs_t_free_private_key(vk);
    hcs_free_random(hr);
    return res;
}

TEST_CASE("djcs_t s=1 decrypts") {
    REQUIRE(djcs_t_decrypt(1, 3, 2, std::vector<unsigned long>{0, 1}) == 12345);
    REQUIRE(djcs_t_decrypt(1, 3, 2, std::vector<unsigned long>{1, 2}) == 12345);
    REQUIRE(djcs_t_decrypt(1, 3, 3, std::vector<unsigned long>{0, 1, 2}) == 12345);
}

TEST_CASE("djcs_t s=2 decrypts") {
    /* Regression: the "encryption acceleration" replaced g^plain with
     * 1 + n^(s-1) * plain, which is only valid for s == 1 and broke s >= 2. */
    REQUIRE(djcs_t_decrypt(2, 2, 2, std::vector<unsigned long>{0, 1}) == 12345);
    REQUIRE(djcs_t_decrypt(2, 3, 2, std::vector<unsigned long>{0, 2}) == 12345);
    REQUIRE(djcs_t_decrypt(2, 3, 3, std::vector<unsigned long>{0, 1, 2}) == 12345);
}

TEST_CASE("djcs_t s=2 ep_add") {
    /* djcs_t_ep_add computes g^plain as well, so the same s >= 2 regression
     * applies: adding a plaintext to a ciphertext must survive a threshold
     * decryption. */
    hcs_random *hr = hcs_init_random();
    djcs_t_public_key *pk = djcs_t_init_public_key();
    djcs_t_private_key *vk = djcs_t_init_private_key();
    /* s, bits, threshold = 2, total = 2 */
    djcs_t_generate_key_pair(pk, vk, hr, 2, 256, 2, 2);

    mpz_class m1 = 1000;
    mpz_class m2 = 2345;
    mpz_class c1, c2;
    djcs_t_encrypt(pk, hr, c1.get_mpz_t(), m1.get_mpz_t());
    djcs_t_ep_add(pk, c2.get_mpz_t(), c1.get_mpz_t(), m2.get_mpz_t());

    mpz_t *coeff = djcs_t_init_polynomial(vk, hr);
    mpz_t shares[2];
    mpz_inits(shares[0], shares[1], NULL);
    for (unsigned long i = 0; i < 2; ++i) {
        mpz_t si;
        mpz_init(si);
        djcs_t_compute_polynomial(vk, coeff, si, i);
        djcs_t_auth_server *au = djcs_t_init_auth_server();
        djcs_t_set_auth_server(au, si, i);
        djcs_t_share_decrypt(pk, au, shares[i], c2.get_mpz_t());
        mpz_clear(si);
        djcs_t_free_auth_server(au);
    }

    mpz_class res;
    djcs_t_share_combine(pk, res.get_mpz_t(), shares);
    REQUIRE(res == m1 + m2);

    mpz_clears(shares[0], shares[1], NULL);
    djcs_t_free_polynomial(vk, coeff);
    djcs_t_free_public_key(pk);
    djcs_t_free_private_key(vk);
    hcs_free_random(hr);
}

int main(int argc, char *argv[])
{
    return Catch::Session().run(argc, argv);
}
