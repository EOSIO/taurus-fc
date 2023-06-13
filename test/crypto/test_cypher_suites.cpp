#define BOOST_TEST_MODULE cypher_suites
#include <boost/test/included/unit_test.hpp>

#include <fc/crypto/public_key.hpp>
#include <fc/crypto/private_key.hpp>
#include <fc/crypto/signature.hpp>
#include <fc/utility.hpp>

#include <fstream>

using namespace fc::crypto;
using namespace fc;

BOOST_AUTO_TEST_SUITE(cypher_suites)
BOOST_AUTO_TEST_CASE(test_k1) try {
   auto private_key_string = std::string("5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3");
   auto expected_public_key = std::string("EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV");
   auto test_private_key = private_key(private_key_string);
   auto test_public_key = test_private_key.get_public_key();

   BOOST_CHECK_EQUAL(private_key_string, test_private_key.to_string());
   BOOST_CHECK_EQUAL(expected_public_key, test_public_key.to_string());
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_CASE(test_r1) try {
   auto private_key_string = std::string("PVT_R1_iyQmnyPEGvFd8uffnk152WC2WryBjgTrg22fXQryuGL9mU6qW");
   auto expected_public_key = std::string("PUB_R1_6EPHFSKVYHBjQgxVGQPrwCxTg7BbZ69H9i4gztN9deKTEXYne4");
   auto test_private_key = private_key(private_key_string);
   auto test_public_key = test_private_key.get_public_key();

   BOOST_CHECK_EQUAL(private_key_string, test_private_key.to_string());
   BOOST_CHECK_EQUAL(expected_public_key, test_public_key.to_string());
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_CASE(test_k1_recovery) try {
   auto payload = "Test Cases";
   auto digest = sha256::hash(payload, const_strlen(payload));
   auto key = private_key::generate<ecc::private_key_shim>();
   auto pub = key.get_public_key();
   auto sig = key.sign(digest);

   auto recovered_pub = public_key(sig, digest);
   std::cout << recovered_pub << std::endl;

   BOOST_CHECK_EQUAL(recovered_pub.to_string(), pub.to_string());
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_CASE(test_r1_recovery) try {
   auto payload = "Test Cases";
   auto digest = sha256::hash(payload, const_strlen(payload));
   auto key = private_key::generate<r1::private_key_shim>();
   auto pub = key.get_public_key();
   auto sig = key.sign(digest);

   auto recovered_pub = public_key(sig, digest);
   std::cout << recovered_pub << std::endl;

   BOOST_CHECK_EQUAL(recovered_pub.to_string(), pub.to_string());
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_CASE(test_k1_recyle) try {
   auto key = private_key::generate<ecc::private_key_shim>();
   auto pub = key.get_public_key();
   auto pub_str = pub.to_string();
   auto recycled_pub = public_key(pub_str);

   std::cout << pub << " -> " << recycled_pub << std::endl;

   BOOST_CHECK_EQUAL(pub.to_string(), recycled_pub.to_string());
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_CASE(test_r1_recyle) try {
   auto key = private_key::generate<r1::private_key_shim>();
   auto pub = key.get_public_key();
   auto pub_str = pub.to_string();
   auto recycled_pub = public_key(pub_str);

   std::cout << pub << " -> " << recycled_pub << std::endl;

   BOOST_CHECK_EQUAL(pub.to_string(), recycled_pub.to_string());
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_CASE(test_sha256_ifstream) try {
   std::string payload = "Test Cases";
   std::string tmpfile = "test_sha256_ifstream.tmp";
   std::string expected = "7e9a3189da470e08cc0ba10584b508f7d891f905eacd2bd181bfab1292a2ca5c";
   std::ofstream ofs(tmpfile, std::ios::out | std::ios::trunc);
   ofs << payload;
   ofs.close();
   std::ifstream ifs(tmpfile);
   sha256 digest = sha256::hash(ifs);
   std::cout << "sha256::hash(" << tmpfile << ") = "
             << digest.str() << std::endl;
   BOOST_CHECK_EQUAL(digest.str(), expected);
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_CASE(test_sha256_ifstream_large) try {
   // tmpfile will be ~11 MB
   std::string payload = "Test Cases\n";
   std::string tmpfile = "test_sha256_ifstream_large.tmp";
   std::string expected = "79c1f347d65e610e9024ddf2c190d0fa34bf8e92d293e9b55f8a35807c83e2b5";
   std::ofstream ofs(tmpfile, std::ios::out | std::ios::trunc);
   for (size_t i = 0; i != 1024 * 1024; ++i) {
      ofs << payload;
   }
   ofs.close();
   std::ifstream ifs(tmpfile);
   sha256 digest = sha256::hash(ifs);
   std::cout << "sha256::hash(" << tmpfile << ") = "
             << digest.str() << std::endl;
   BOOST_CHECK_EQUAL(digest.str(), expected);
} FC_LOG_AND_RETHROW();

BOOST_AUTO_TEST_SUITE_END()
