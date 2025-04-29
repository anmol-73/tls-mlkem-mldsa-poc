#include <oqs/oqs.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <openssl/ec.h>
#include <openssl/pem.h>

void save_to_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream ofs(filename, std::ios::binary);
    if (!ofs) {
        throw std::runtime_error("Failed to open file " + filename + " for writing.");
    }
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    ofs.close();
}

int main() {

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig) {
        std::cerr << "Failed to create MLDSA object!" << std::endl;
        return 1;
    }

    std::vector<uint8_t> public_key(sig->length_public_key);
    std::vector<uint8_t> private_key(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, public_key.data(), private_key.data()) != OQS_SUCCESS) {
        std::cerr << "Failed to generate MLDSA keypair!" << std::endl;
        OQS_SIG_free(sig);
        return 1;
    }

    std::cout << "[+] Generated MLDSA keypair.\n";

    // Save to files
    save_to_file("server_mldsa_priv.bin", private_key);
    save_to_file("server_mldsa_pub.bin", public_key);

    std::cout << "[+] Saved private key to server_mldsa_priv.bin\n";
    std::cout << "[+] Saved public key to server_mldsa_pub.bin\n";

    OQS_SIG_free(sig);

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) {
        std::cerr << "Failed to create context\n";
        return 1;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        std::cerr << "Failed to init keygen\n";
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    // Set the curve (e.g., prime256v1)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        std::cerr << "Failed to set curve\n";
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        std::cerr << "Keygen failed\n";
        EVP_PKEY_CTX_free(pctx);
        return 1;
    }

    EVP_PKEY_CTX_free(pctx);

    // Write private key
    FILE* priv = fopen("server_ecdsa_key.pem", "w");
    if (!priv || !PEM_write_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        std::cerr << "Failed to write private key\n";
        return 1;
    }
    fclose(priv);

    // Write public key
    FILE* pub = fopen("server_ecdsa_pub.pem", "w");
    if (!pub || !PEM_write_PUBKEY(pub, pkey)) {
        std::cerr << "Failed to write public key\n";
        return 1;
    }
    fclose(pub);

    EVP_PKEY_free(pkey);
    std::cout << "[+] EVP key pair generated successfully.\n";
    return 0;
}
