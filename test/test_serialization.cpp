#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#include <gmpxx.h>
#include "../include/libhcs/pcs.h"
#include "../include/libhcs/pcs_t.h"
#include "../include/libhcs/djcs.h"
#include "../include/libhcs/hcs_random.h"
#include "../include/libhcs/hcs_shares.h"
#include "../src/com/parson.h" /* json_free_serialized_string */

/* The export functions return a string allocated by parson, so it must be
 * released with json_free_serialized_string rather than free/realloc. */

TEST_CASE("pcs key export/import round-trips") {
    hcs_random *hr = hcs_init_random();
    pcs_public_key *pk = pcs_init_public_key();
    pcs_private_key *vk = pcs_init_private_key();
    pcs_generate_key_pair(pk, vk, hr, 256);

    char *pjs = pcs_export_public_key(pk);
    char *vjs = pcs_export_private_key(vk);

    pcs_public_key *pk2 = pcs_init_public_key();
    pcs_private_key *vk2 = pcs_init_private_key();
    REQUIRE(pcs_import_public_key(pk2, pjs) == 0);
    REQUIRE(pcs_import_private_key(vk2, vjs) == 0);

    mpz_t m, c, d;
    mpz_inits(m, c, d, NULL);
    mpz_set_ui(m, 12345);
    pcs_encrypt(pk2, hr, c, m);
    pcs_decrypt(vk2, d, c);
    /* Regression: the imported private key had hq computed from the wrong
     * base, so decryption produced garbage. */
    REQUIRE(mpz_cmp(m, d) == 0);

    mpz_clears(m, c, d, NULL);
    json_free_serialized_string(pjs);
    json_free_serialized_string(vjs);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    pcs_free_public_key(pk2);
    pcs_free_private_key(vk2);
    hcs_free_random(hr);
}

TEST_CASE("pcs_t public key export/import round-trips") {
    hcs_random *hr = hcs_init_random();
    pcs_t_public_key *pk = pcs_t_init_public_key();
    pcs_t_private_key *vk = pcs_t_init_private_key();
    /* bits, threshold = 2, total = 3 */
    REQUIRE(pcs_t_generate_key_pair(pk, vk, hr, 256, 2, 3) == 1);

    char *pjs = pcs_t_export_public_key(pk);
    pcs_t_public_key *pk2 = pcs_t_init_public_key();
    REQUIRE(pcs_t_import_public_key(pk2, pjs) == 0);

    pcs_t_polynomial *px = pcs_t_init_polynomial(vk, hr);
    mpz_t m, c;
    mpz_inits(m, c, NULL);
    mpz_set_ui(m, 42);
    pcs_t_encrypt(pk, hr, c, m);

    hcs_shares *hs = hcs_init_shares(3);
    for (unsigned long i = 0; i < 3; ++i) {
        mpz_t si, share;
        mpz_inits(si, share, NULL);
        pcs_t_compute_polynomial(vk, px, si, i);
        pcs_t_auth_server *au = pcs_t_init_auth_server();
        pcs_t_set_auth_server(au, si, i);
        pcs_t_share_decrypt(pk2, au, share, c); /* use the imported public key */
        hcs_set_share(hs, share, i);
        mpz_clears(si, share, NULL);
        pcs_t_free_auth_server(au);
    }

    mpz_t res;
    mpz_init(res);
    REQUIRE(pcs_t_share_combine(pk2, res, hs) != 0);
    REQUIRE(mpz_cmp(res, m) == 0);

    mpz_clears(m, c, res, NULL);
    hcs_free_shares(hs);
    json_free_serialized_string(pjs);
    pcs_t_free_polynomial(px);
    pcs_t_free_public_key(pk);
    pcs_t_free_private_key(vk);
    pcs_t_free_public_key(pk2);
    hcs_free_random(hr);
}

TEST_CASE("pcs_t auth server export/import round-trips") {
    hcs_random *hr = hcs_init_random();
    pcs_t_public_key *pk = pcs_t_init_public_key();
    pcs_t_private_key *vk = pcs_t_init_private_key();
    pcs_t_generate_key_pair(pk, vk, hr, 256, 2, 3);

    pcs_t_polynomial *px = pcs_t_init_polynomial(vk, hr);
    mpz_t si;
    mpz_init(si);
    pcs_t_compute_polynomial(vk, px, si, 0);

    pcs_t_auth_server *au = pcs_t_init_auth_server();
    pcs_t_set_auth_server(au, si, 0);

    char *ajs = pcs_t_export_auth_server(au);
    pcs_t_auth_server *au2 = pcs_t_init_auth_server();
    REQUIRE(pcs_t_import_auth_server(au2, ajs) == 0);
    REQUIRE(au->i == au2->i);
    REQUIRE(mpz_cmp(au->si, au2->si) == 0);

    json_free_serialized_string(ajs);
    mpz_clear(si);
    pcs_t_free_auth_server(au);
    pcs_t_free_auth_server(au2);
    pcs_t_free_polynomial(px);
    pcs_t_free_public_key(pk);
    pcs_t_free_private_key(vk);
    hcs_free_random(hr);
}

TEST_CASE("djcs key export/import round-trips") {
    hcs_random *hr = hcs_init_random();
    djcs_public_key *pk = djcs_init_public_key();
    djcs_private_key *vk = djcs_init_private_key();
    djcs_generate_key_pair(pk, vk, hr, 2, 256);

    char *pjs = djcs_export_public_key(pk);
    char *vjs = djcs_export_private_key(vk);
    djcs_public_key *pk2 = djcs_init_public_key();
    djcs_private_key *vk2 = djcs_init_private_key();
    REQUIRE(djcs_import_public_key(pk2, pjs) == 0);
    REQUIRE(djcs_import_private_key(vk2, vjs) == 0);

    mpz_t m, c, d;
    mpz_inits(m, c, d, NULL);
    mpz_set_ui(m, 777);
    djcs_encrypt(pk2, hr, c, m);
    djcs_decrypt(vk2, d, c);
    REQUIRE(mpz_cmp(m, d) == 0);

    mpz_clears(m, c, d, NULL);
    json_free_serialized_string(pjs);
    json_free_serialized_string(vjs);
    djcs_free_public_key(pk);
    djcs_free_private_key(vk);
    djcs_free_public_key(pk2);
    djcs_free_private_key(vk2);
    hcs_free_random(hr);
}

int main(int argc, char *argv[])
{
    return Catch::Session().run(argc, argv);
}
