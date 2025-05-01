#include "httplib.h" // HTTP server library
#include <cstdint>
#include <nlohmann/json.hpp> // JSON for Modern C++ (used for HTTP message parsing)
#include <oqs/oqs.h>         // ML-KEM operations (from the liboqs C API)
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/kdf.h>
#include <openssl/params.h> // For constructing OCTET_STRING parameters
#include <oqs/sig.h>
#include <vector>
#include <string>
#include <random>
#include <cstring>
#include <iostream>
#include <exception>

using json = nlohmann::json;

// --- Base64 Helpers ---
// Encode a byte vector into Base64 using OpenSSL BIOs.
static std::string b64_encode(const std::vector<uint8_t> &in)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Do not add newlines
    BIO_write(b64, in.data(), in.size());
    BIO_flush(b64);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}

// Decode a Base64 string into a byte vector.
static std::vector<uint8_t> b64_decode(const std::string &in)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(in.data(), in.size());
    BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    std::vector<uint8_t> out(in.size());
    int len = BIO_read(b64, out.data(), out.size());
    out.resize(len);
    BIO_free_all(b64);
    return out;
}

// --- Generate Server ECDHE Keypair ---
// Generates an EC keypair on the NIST P-256 curve and returns the private key.
// The public key is output in PEM format (stored in server_ecdh_pub_pem).
EVP_PKEY *generate_server_ecdh_keypair(std::vector<uint8_t> &server_ecdh_pub_pem)
{
    std::cout << "[+] Generating server ECDHE P-256 keypair\n";
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx)
        throw std::runtime_error("Failed to create PKEY context");
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        throw std::runtime_error("Failed to initialize keygen");
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
        throw std::runtime_error("Failed to set curve NID");

    EVP_PKEY *server_ecdh_priv = nullptr;
    if (EVP_PKEY_keygen(pctx, &server_ecdh_priv) <= 0)
        throw std::runtime_error("Failed to generate keypair");
    EVP_PKEY_CTX_free(pctx);

    // Convert the server's public key to PEM for transmission
    BIO *bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, server_ecdh_priv))
        throw std::runtime_error("Failed to write PEM public key");
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    server_ecdh_pub_pem.assign(bptr->data, bptr->data + bptr->length);
    BIO_free(bio);

    std::cout << "[+] Server keypair generated\n";
    return server_ecdh_priv;
}

// --- Load or generate MLDSA private key ---
void load_server_mldsa_key(std::vector<uint8_t> &priv_key)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
        throw std::runtime_error("Failed to create MLDSA object");

    // Load server's MLDSA private key from disk (example)
    FILE *fp = fopen("server_mldsa_priv.bin", "rb");
    if (!fp)
        throw std::runtime_error("Failed to open server MLDSA private key file");
    priv_key.resize(sig->length_secret_key);
    fread(priv_key.data(), 1, priv_key.size(), fp);
    fclose(fp);
    std::cout << "[+] Loaded server MLDSA private key\n";
    OQS_SIG_free(sig);
}

void load_server_ecdsa_key(EVP_PKEY *&priv_key)
{
    FILE *fp = fopen("server_ecdsa_key.pem", "r");
    if (!fp)
        throw std::runtime_error("Failed to open server ECDSA private key file");
    priv_key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
}
// --- Perform ML-KEM Encapsulation ---
// Uses ML-KEM (algorithm ML_KEM_768) to encapsulate and produce a ciphertext and shared secret.
// client_mlkem_pk: ML-KEM public key received from the client.
bool perform_mlkem_encapsulation(const std::vector<uint8_t> &client_mlkem_pk,
                                 std::vector<uint8_t> &kem_ct,
                                 std::vector<uint8_t> &shared_mlkem)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        throw std::runtime_error("Failed to initialize ML-KEM");
    kem_ct.resize(kem->length_ciphertext);
    shared_mlkem.resize(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, kem_ct.data(), shared_mlkem.data(), client_mlkem_pk.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM encapsulation failed");
    OQS_KEM_free(kem);
    std::cout << "[+] ML-KEM encapsulation complete\n";
    return true;
}

// --- Compute ECDHE Shared Secret ---
// Derives the shared secret using ECDHE with the client's PEM-encoded public key.
bool compute_ecdh_shared_secret(EVP_PKEY *server_priv,
                                const std::vector<uint8_t> &client_ecdh_bytes,
                                std::vector<uint8_t> &shared_ecdh)
{
    // Convert client's public key bytes into a PEM string
    std::string client_pem_str(client_ecdh_bytes.begin(), client_ecdh_bytes.end());
    BIO *rbio = BIO_new_mem_buf(client_pem_str.data(), client_pem_str.size());
    EVP_PKEY *client_pub = PEM_read_bio_PUBKEY(rbio, nullptr, nullptr, nullptr);
    BIO_free(rbio);
    if (!client_pub)
    {
        std::cout << "[!] Failed to parse client ECDHE public key\n";
        return false;
    }

    // Set up the derivation context for ECDH
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(server_priv, nullptr);
    if (!derive_ctx)
    {
        EVP_PKEY_free(client_pub);
        throw std::runtime_error("Failed to create ECDH derive context");
    }
    if (EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, client_pub) <= 0)
    {
        EVP_PKEY_free(client_pub);
        EVP_PKEY_CTX_free(derive_ctx);
        std::cout << "[!] Failed to initialize ECDH derivation\n";
        return false;
    }
    size_t ecdh_len = 0;
    if (EVP_PKEY_derive(derive_ctx, nullptr, &ecdh_len) <= 0 || ecdh_len == 0)
    {
        std::cout << "[!] Failed to determine ECDHE shared secret length\n";
        EVP_PKEY_free(client_pub);
        EVP_PKEY_CTX_free(derive_ctx);
        return false;
    }
    shared_ecdh.resize(ecdh_len);
    if (EVP_PKEY_derive(derive_ctx, shared_ecdh.data(), &ecdh_len) <= 0)
    {
        std::cout << "[!] Failed to compute ECDHE shared secret\n";
        EVP_PKEY_free(client_pub);
        EVP_PKEY_CTX_free(derive_ctx);
        return false;
    }
    EVP_PKEY_free(client_pub);
    EVP_PKEY_CTX_free(derive_ctx);

    std::cout << "[+] ECDHE shared secret computed, length = " << shared_ecdh.size() << " bytes\n";
    return true;
}

// --- Derive Hybrid Key ---
// Combines the ML-KEM and ECDHE shared secrets and applies HKDF-SHA256 to derive a symmetric key.
bool derive_hybrid_key(const std::vector<uint8_t> &shared_mlkem,
                       const std::vector<uint8_t> &shared_ecdh,
                       std::vector<uint8_t> &hybrid_key)
{
    // Concatenate the two shared secrets to form input key material (IKM)
    std::vector<uint8_t> ikm = shared_mlkem;
    ikm.insert(ikm.end(), shared_ecdh.begin(), shared_ecdh.end());

    const char *info_str = "Hybrid KEM-ECDHE Key";
    size_t info_len = strlen(info_str);
    hybrid_key.resize(32); // AES-256 key size

    // Construct parameters for HKDF: digest, salt, key, info, and output buffer.
    OSSL_PARAM params[6];
    int i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>("SHA256"), 0);
    params[i++] = OSSL_PARAM_construct_octet_string("salt", nullptr, 0);
    params[i++] = OSSL_PARAM_construct_octet_string("key", const_cast<uint8_t *>(ikm.data()), ikm.size());
    params[i++] = OSSL_PARAM_construct_octet_string("info", const_cast<char *>(info_str), info_len);
    params[i++] = OSSL_PARAM_construct_octet_string("out", hybrid_key.data(), hybrid_key.size());
    params[i++] = OSSL_PARAM_construct_end();

    // Fetch and use HKDF to derive the final key.
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
        throw std::runtime_error("Failed to fetch HKDF algorithm");

    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
    {
        EVP_KDF_free(kdf);
        throw std::runtime_error("Failed to create HKDF context");
    }
    if (EVP_KDF_derive(kctx, hybrid_key.data(), hybrid_key.size(), params) <= 0)
        throw std::runtime_error("HKDF derivation failed");

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);

    std::cout << "[+] Hybrid key derived (" << hybrid_key.size() << " bytes)\n";
    return true;
}

// --- AES-256-GCM Encryption ---
// Encrypts a plaintext string using the symmetric key (derived from the hybrid exchange).
bool aes_256_gcm_encrypt(const std::vector<uint8_t> &key,
                         const std::string &plaintext,
                         std::vector<uint8_t> &ciphertext,
                         std::vector<uint8_t> &iv,
                         std::vector<uint8_t> &tag)
{
    // Generate a random 12-byte IV (recommended for GCM)
    iv.resize(12);
    std::random_device rd;
    for (auto &byte : iv)
        byte = rd() & 0xFF;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("Failed to create encryption context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("Failed to init AES-256-GCM");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
        throw std::runtime_error("Failed to set IV length");
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1)
        throw std::runtime_error("Failed to initialize key and IV for encryption");

    ciphertext.resize(plaintext.size());
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size()) != 1)
        throw std::runtime_error("Encryption update failed");

    int ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        throw std::runtime_error("Encryption finalization failed");
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    tag.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()) != 1)
        throw std::runtime_error("Failed to get GCM tag");

    EVP_CIPHER_CTX_free(ctx);
    std::cout << "[+] Message encrypted\n";
    return true;
}

void gen_sign_mldsa(const std::vector<uint8_t> &server_mldsa_priv_key, const std::vector<uint8_t> &message, std::vector<uint8_t> &signature)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
        throw std::runtime_error("Failed to create MLDSA object");
    signature.resize(sig->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig,
                     signature.data(), &sig_len,
                     message.data(), message.size(),
                     server_mldsa_priv_key.data()) != OQS_SUCCESS)
    {
        throw std::runtime_error("Failed to sign server ECDHE public key");
    }
    signature.resize(sig_len);
    std::cout << "[+] Server ECDHE public key signed\n";
    OQS_SIG_free(sig);
}

void gen_sign_ecdsa(EVP_PKEY *privkey, const std::vector<uint8_t> &message, std::vector<uint8_t> &signature)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        throw std::runtime_error("MD context alloc failed");

    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, privkey) <= 0)
        throw std::runtime_error("DigestSignInit failed");

    if (EVP_DigestSignUpdate(mdctx, message.data(), message.size()) <= 0)
        throw std::runtime_error("DigestSignUpdate failed");

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &sig_len) <= 0)
        throw std::runtime_error("DigestSignFinal length failed");

    signature.resize(sig_len);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &sig_len) <= 0)
        throw std::runtime_error("DigestSignFinal failed");
    signature.resize(sig_len);
    EVP_MD_CTX_free(mdctx);
}

// --- HTTP /key_exchange Handler ---
// Handles the key exchange request by processing client keys, performing ML-KEM encapsulation,
// computing the shared ECDHE secret, deriving the hybrid key, and encrypting a message.
void key_exchange_handler(const httplib::Request &req, httplib::Response &res,
                          EVP_PKEY *server_ecdh_priv, EVP_PKEY *server_ecdsa_priv, const std::vector<uint8_t> &server_ecdh_pub_pem, const std::vector<uint8_t> &server_mldsa_priv_key)
{
    std::cout << "-------------------------------\n";
    std::cout << "[+] Received /key_exchange request\n";
    try
    {
        // Parse client JSON and decode the Base64-enserver_ecdh_pub_pemcoded ML-KEM and ECDHE public keys.
        json j = json::parse(req.body);
        std::vector<uint8_t> client_mlkem_pk = b64_decode(j["mlkem_public_key"].get<std::string>());
        std::vector<uint8_t> client_ecdh_bytes = b64_decode(j["ecdh_public_key"].get<std::string>());
        std::cout << "[+] Client JSON parsed\n";

        // Perform ML-KEM encapsulation
        std::vector<uint8_t> kem_ct, shared_mlkem;
        perform_mlkem_encapsulation(client_mlkem_pk, kem_ct, shared_mlkem);

        // Compute the shared secret using ECDHE
        std::vector<uint8_t> shared_ecdh;
        if (!compute_ecdh_shared_secret(server_ecdh_priv, client_ecdh_bytes, shared_ecdh))
        {
            res.status = 500;
            res.set_content("ECDH shared secret computation failed", "text/plain");
            return;
        }

        // Derive the final hybrid key
        std::vector<uint8_t> hybrid_key;
        derive_hybrid_key(shared_mlkem, shared_ecdh, hybrid_key);

        // Encrypt a simple message using AES-256-GCM with the derived key
        std::string msg = "Hello, Client!";
        std::vector<uint8_t> ciphertext, iv, tag, mldsa_signature, ecdsa_signature;
        gen_sign_mldsa(server_mldsa_priv_key, server_ecdh_pub_pem, mldsa_signature);
        gen_sign_ecdsa(server_ecdsa_priv, server_ecdh_pub_pem, ecdsa_signature);
        aes_256_gcm_encrypt(hybrid_key, msg, ciphertext, iv, tag);

        // Build JSON response with Base64-encoded data
        json rsp = {
            {"server_ecdh_public_key", b64_encode(server_ecdh_pub_pem)},
            {"mldsa_signature", b64_encode(mldsa_signature)},
            {"ecdsa_signature", b64_encode(ecdsa_signature)},
            {"key", b64_encode(kem_ct)},
            {"ciphertext", b64_encode(ciphertext)},
            {"iv", b64_encode(iv)},
            {"tag", b64_encode(tag)}};
        res.set_content(rsp.dump(), "application/json");
        std::cout << "[+] Response sent\n";
    }
    catch (std::exception &e)
    {
        std::cerr << "[!] Exception in key_exchange_handler: " << e.what() << "\n";
        res.status = 500;
        res.set_content("Internal Server Error", "text/plain");
    }
}

int main()
{
    try
    {
        std::cout << "[+] Server starting\n";
        // Generate ECDHE keypair and obtain the PEM-encoded public key for transmission.
        std::vector<uint8_t> server_ecdh_pub_pem;
        std::vector<uint8_t> server_mldsa_priv_key;
        EVP_PKEY *server_ecdh_priv = generate_server_ecdh_keypair(server_ecdh_pub_pem);
        EVP_PKEY *server_ecdsa_priv = nullptr;
        load_server_mldsa_key(server_mldsa_priv_key);
        load_server_ecdsa_key(server_ecdsa_priv);
        httplib::Server svr;
        svr.Post("/key_exchange", [&](const httplib::Request &req, httplib::Response &res)
                 { key_exchange_handler(req, res, server_ecdh_priv, server_ecdsa_priv, server_ecdh_pub_pem, server_mldsa_priv_key); });

        std::cout << "[+] Listening on 0.0.0.0:5000\n";
        svr.listen("0.0.0.0", 5000);

        EVP_PKEY_free(server_ecdh_priv);
        std::cout << "[+] Server shutting down\n";
    }
    catch (std::exception &e)
    {
        std::cerr << "[!] Fatal error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
