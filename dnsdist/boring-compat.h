/* DNSDIST_VARIANT=pq only: fed to boring-sys's bindgen run (BINDGEN_EXTRA_CLANG_ARGS=-include), never to
 * BoringSSL or quiche's C code. boring 4.22.0 (the newest boring quiche 0.29.3 accepts, ^4.3) still names two
 * groups in its SslCurve enum (src/ssl/mod.rs:714-786) that BoringSSL has since removed: P-224 (1cca12755)
 * and the pre-standard Kyber hybrid (188ce3c13). The values are the ones those commits deleted. Nothing on our
 * path passes them to the library (quiche has no group setter), and BoringSSL rejects both IDs if anything did.
 */
#define SSL_CURVE_SECP224R1 21
#define SSL_CURVE_X25519_KYBER768_DRAFT00 0x6399
