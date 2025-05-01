#include <cstdint>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>

using json = nlohmann::json;

// Encode a vector of bytes to a Base64 string using OpenSSL BIO functions.
static std::string b64_encode(const std::vector<uint8_t> &in)
{
    try
    {
        BIO *b64 = BIO_new(BIO_f_base64()), *bmem = BIO_new(BIO_s_mem());
        // Chain the BIOs
        BIO_push(b64, bmem);
        // Disable newlines to keep Base64 output in one line
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, in.data(), in.size());
        BIO_flush(b64);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(b64, &bptr);
        // Create a string from the BIO memory buffer
        std::string out(bptr->data, bptr->length);
        BIO_free_all(b64);
        return out;
    }
    catch (...)
    {
        throw std::runtime_error("[!] Base64 encoding failed");
    }
}

// Decode a Base64 string to a vector of bytes.
static std::vector<uint8_t> b64_decode(const std::string &in)
{
    try
    {
        BIO *b64 = BIO_new(BIO_f_base64()), *bmem = BIO_new_mem_buf(in.data(), in.size());
        // Chain the BIOs
        BIO_push(b64, bmem);
        // Disable newlines as the input is one continuous string
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        std::vector<uint8_t> out(in.size());
        int len = BIO_read(b64, out.data(), out.size());
        out.resize(len);
        BIO_free_all(b64);
        return out;
    }
    catch (...)
    {
        throw std::runtime_error("[!] Base64 decoding failed");
    }
}

// Callback function for libcurl to write data received from the server.
static size_t curl_write(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    auto *str = static_cast<std::string *>(userdata);
    str->append(static_cast<char *>(ptr), size * nmemb);
    return size * nmemb;
}

// Generate an ML-KEM keypair (public and secret keys) and store them in vectors.
bool generate_mlkem(OQS_KEM *&kem, std::vector<uint8_t> &pk, std::vector<uint8_t> &sk)
{
    try
    {
        // Initialize the ML-KEM algorithm with the specified algorithm identifier.
        kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
        if (!kem)
            throw std::runtime_error("[!] Failed to initialize ML-KEM algorithm");

        // Resize the vectors according to expected key lengths.
        pk.resize(kem->length_public_key);
        sk.resize(kem->length_secret_key);

        // Generate the keypair; throw error if generation fails.
        if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS)
            throw std::runtime_error("[!] ML-KEM keypair generation failed");
        std::cout << "[+] ML-KEM keys generated: public key length = "
                  << pk.size() << ", secret key length = " << sk.size() << "\n";
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return false;
    }
}

// Generate an ECDH keypair using OpenSSL and return the private key and the PEM-encoded public key.
bool generate_ecdh(EVP_PKEY *&priv, std::string &pub_pem)
{
    try
    {
        // Create a context for EC key generation using the specified curve (P-256).
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
            throw std::runtime_error("[!] ECDH context initialization failed");

        // Generate the keypair.
        if (EVP_PKEY_keygen(pctx, &priv) <= 0)
            throw std::runtime_error("[!] ECDH key generation failed");
        EVP_PKEY_CTX_free(pctx);

        // Write the public key in PEM format to a memory BIO.
        BIO *mem = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(mem, priv);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(mem, &bptr);
        pub_pem.assign(bptr->data, bptr->length);
        BIO_free(mem);
        std::cout << "[+] ECDH keypair generated, public key (PEM) length = "
                  << pub_pem.size() << " bytes\n";
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return false;
    }
}

// Post the key exchange request to the given URL with a JSON payload and parse the JSON response.
bool post_key_exchange(const std::string &url, const json &req_json, json &resp_json)
{
    try
    {
        CURL *curl = curl_easy_init();
        if (!curl)
            throw std::runtime_error("[!] Failed to initialize libcurl");
        std::string resp_str;

        // Prepare headers for JSON content.
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Convert JSON to a string for sending.
        std::string body = req_json.dump();
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());

        // Set callback function to capture server response.
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_str);
        CURLcode code = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        if (code != CURLE_OK)
            throw std::runtime_error(std::string("[!] Request failed: ") + curl_easy_strerror(code));

        // Parse the response string as JSON.
        resp_json = json::parse(resp_str);
        std::cout << "[+] Server response received, size = " << resp_str.size() << " bytes\n";
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return false;
    }
}

// --- Load or generate MLDSA private key ---
void load_server_mldsa_key(std::vector<uint8_t> &pub_key)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
        throw std::runtime_error("Failed to create MLDSA object");

    // Load server's MLDSA public key from disk (example)
    FILE *fp = fopen("server_mldsa_pub.bin", "rb");
    if (!fp)
        throw std::runtime_error("Failed to open server MLDSA public key file");
    pub_key.resize(sig->length_public_key);
    fread(pub_key.data(), 1, pub_key.size(), fp);
    fclose(fp);
    std::cout << "[+] Loaded server MLDSA public key\n";
    OQS_SIG_free(sig);
}

void load_server_ecdsa_key(EVP_PKEY *&priv_key)
{
    FILE *fp = fopen("server_ecdsa_pub.pem", "r");
    if (!fp)
        throw std::runtime_error("Failed to open server ECDSA private key file");
    priv_key = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
}

bool ecdsa_verify(EVP_PKEY *pubkey, const std::vector<uint8_t> &message, const std::vector<uint8_t> &signature)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        throw std::runtime_error("MD context alloc failed");

    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pubkey) <= 0)
        throw std::runtime_error("DigestVerifyInit failed");

    if (EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()) <= 0)
        throw std::runtime_error("DigestVerifyUpdate failed");

    int ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
    EVP_MD_CTX_free(mdctx);
    return ret == 1;
}

void verify_cert(const std::vector<uint8_t> &mldsa_pub_key, EVP_PKEY *pub_key,
                 const std::vector<uint8_t> &mldsa_signature,
                 const std::vector<uint8_t> &ecdsa_signature,
                 const std::vector<uint8_t> &message)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
    {
        std::runtime_error("[-] Failed to create MLDSA object!\n");
    }
    OQS_STATUS rc = OQS_SIG_verify(sig,
                                   message.data(), message.size(),
                                   mldsa_signature.data(), mldsa_signature.size(),
                                   mldsa_pub_key.data());
    OQS_SIG_free(sig);
    if (rc == OQS_SUCCESS && ecdsa_verify(pub_key, message, ecdsa_signature))
    {
        std::cout << "[+] Signature verified successfully!\n";
    }
    else
    {
        throw std::runtime_error("[!] Signature verification failed");
    }
}
// Derive the shared secrets using ML-KEM decapsulation and ECDH key derivation.
bool derive_secrets(OQS_KEM *kem,
                    const std::vector<uint8_t> &sk,
                    const std::vector<uint8_t> &encaps_key,
                    EVP_PKEY *priv_ecdh,
                    const std::vector<uint8_t> &srv_ecdh_pub,
                    std::vector<uint8_t> &shared_mlkem,
                    std::vector<uint8_t> &shared_ecdh)
{
    try
    {
        // ML-KEM decapsulation: derive shared secret from the encapsulated key.
        shared_mlkem.resize(kem->length_shared_secret);
        if (OQS_KEM_decaps(kem, shared_mlkem.data(), encaps_key.data(), sk.data()) != OQS_SUCCESS)
            throw std::runtime_error("[!] ML-KEM decapsulation failed");
        std::cout << "[+] ML-KEM shared secret derived, length = " << shared_mlkem.size() << " bytes\n";

        // Read the server's ECDH public key from its PEM representation.
        BIO *mem = BIO_new_mem_buf(srv_ecdh_pub.data(), srv_ecdh_pub.size());
        EVP_PKEY *srv_pub = PEM_read_bio_PUBKEY(mem, nullptr, nullptr, nullptr);
        BIO_free(mem);

        // Set up an ECDH derivation context.
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(priv_ecdh, nullptr);
        EVP_PKEY_derive_init(dctx);
        EVP_PKEY_derive_set_peer(dctx, srv_pub);

        // Determine buffer length for the derived secret.
        size_t len = 0;
        EVP_PKEY_derive(dctx, nullptr, &len);
        shared_ecdh.resize(len);

        // Derive the shared ECDH secret.
        EVP_PKEY_derive(dctx, shared_ecdh.data(), &len);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(srv_pub);
        std::cout << "[+] ECDH shared secret derived, length = " << len << " bytes\n";
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return false;
    }
}

// Combine ML-KEM and ECDH shared secrets using HKDF to derive a final hybrid key.
bool derive_hybrid_key(const std::vector<uint8_t> &shared_mlkem,
                       const std::vector<uint8_t> &shared_ecdh,
                       std::vector<uint8_t> &hybrid_key)
{
    try
    {
        // Concatenate both shared secrets into the input keying material.
        std::vector<uint8_t> ikm = shared_mlkem;
        ikm.insert(ikm.end(), shared_ecdh.begin(), shared_ecdh.end());
        hybrid_key.resize(32); // Final key size is 32 bytes.

        const char *info = "Hybrid KEM-ECDHE Key";

        // Prepare HKDF parameters.
        OSSL_PARAM params[6];
        int idx = 0;
        params[idx++] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>("SHA256"), 0);
        params[idx++] = OSSL_PARAM_construct_octet_string("salt", nullptr, 0);
        params[idx++] = OSSL_PARAM_construct_octet_string("key", ikm.data(), ikm.size());
        params[idx++] = OSSL_PARAM_construct_octet_string("info", (void *)info, strlen(info));
        params[idx++] = OSSL_PARAM_construct_octet_string("out", hybrid_key.data(), hybrid_key.size());
        params[idx++] = OSSL_PARAM_construct_end();

        // Use OpenSSL's HKDF to derive the key.
        EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        bool ok = EVP_KDF_derive(kctx, hybrid_key.data(), hybrid_key.size(), params) > 0;
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);

        if (!ok)
            throw std::runtime_error("[!] HKDF derivation failed");
        std::cout << "[+] Hybrid key derived (32 bytes)\n";
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return false;
    }
}

// Decrypt the ciphertext using AES-256-GCM with the provided hybrid key.
bool aes_gcm_decrypt(const std::vector<uint8_t> &key,
                     const std::vector<uint8_t> &iv,
                     const std::vector<uint8_t> &ciphertext,
                     const std::vector<uint8_t> &tag,
                     std::vector<uint8_t> &plaintext)
{
    try
    {
        // Create and initialize the decryption context.
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);

        // Set the IV length for GCM mode.
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);

        // Initialize decryption with key and IV.
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
        plaintext.resize(ciphertext.size());
        int len = 0;

        // Process ciphertext.
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());

        // Set expected GCM tag value.
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void *)tag.data());

        // Finalize decryption; if authentication fails, an error is raised.
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0)
            throw std::runtime_error("[!] AES-GCM decryption failed or tag mismatch");
        EVP_CIPHER_CTX_free(ctx);
        std::cout << "[+] Decryption successful, plaintext length = " << plaintext.size() << " bytes\n";
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << "\n";
        return false;
    }
}

int main()
{
    try
    {
        // Variables to hold ML-KEM, public/private keys for both ML-KEM and ECDH.
        OQS_KEM *kem = nullptr;
        std::vector<uint8_t> pk, sk, server_mldsa_pub;
        EVP_PKEY *ecdh_priv = nullptr;
        EVP_PKEY *ecdsa_pub = nullptr;
        std::string ecdh_pub_pem;

        // Generate ML-KEM and ECDH keypairs.
        if (!generate_mlkem(kem, pk, sk))
            return 1;
        if (!generate_ecdh(ecdh_priv, ecdh_pub_pem))
            return 1;

        load_server_mldsa_key(server_mldsa_pub);
        load_server_ecdsa_key(ecdsa_pub);

        // Prepare the JSON request containing both Base64-encoded public keys.
        json request = {
            {"mlkem_public_key", b64_encode(pk)},
            {"ecdh_public_key", b64_encode(std::vector<uint8_t>(ecdh_pub_pem.begin(), ecdh_pub_pem.end()))}};

        json response;
        // Send the key exchange request to the server.
        if (!post_key_exchange("http://localhost:5000/key_exchange", request, response))
            return 1;

        // Decode server response parameters (server's public key, encrypted key material, and AES-GCM parameters).
        std::vector<uint8_t> srv_ecdh_pub = b64_decode(response["server_ecdh_public_key"].get<std::string>());
        std::vector<uint8_t> mldsa_signature = b64_decode(response["mldsa_signature"].get<std::string>());
        std::vector<uint8_t> ecdsa_signature = b64_decode(response["ecdsa_signature"].get<std::string>());
        std::vector<uint8_t> ciphertext = b64_decode(response["ciphertext"].get<std::string>());
        std::vector<uint8_t> iv = b64_decode(response["iv"].get<std::string>());
        std::vector<uint8_t> tag = b64_decode(response["tag"].get<std::string>());
        std::vector<uint8_t> encaps_key = b64_decode(response["key"].get<std::string>());

        verify_cert(server_mldsa_pub, ecdsa_pub, mldsa_signature, ecdsa_signature, srv_ecdh_pub);
        // Derive the shared secrets using ML-KEM and ECDH.
        std::vector<uint8_t> shared_mlkem, shared_ecdh;
        if (!derive_secrets(kem, sk, encaps_key, ecdh_priv, srv_ecdh_pub, shared_mlkem, shared_ecdh))
            return 1;

        // Derive a final hybrid key using HKDF.
        std::vector<uint8_t> hybrid_key;
        if (!derive_hybrid_key(shared_mlkem, shared_ecdh, hybrid_key))
            return 1;

        // Decrypt the message from the server using the hybrid key.
        std::vector<uint8_t> plaintext;
        if (!aes_gcm_decrypt(hybrid_key, iv, ciphertext, tag, plaintext))
            return 1;

        std::cout << "[+] Decrypted message from server: "
                  << std::string(plaintext.begin(), plaintext.end()) << "\n";

        // Clean up allocated resources.
        OQS_KEM_free(kem);
        EVP_PKEY_free(ecdh_priv);
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "[!] Exception: " << e.what() << "\n";
        return 1;
    }
}
