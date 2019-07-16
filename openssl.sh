set -x 

SOURCE_DIR=$1
TARGET=$2

if [ "${GIT_RESET}" == "true" ]; then
  pushd ${SOURCE_DIR}
    git fetch upstream
    git checkout master
    git reset --hard upstream/master
  popd
fi

if [ "$TARGET" == "RESET" ]; then
  exit
fi

BUILD_OPTIONS="
build --cxxopt -D_GLIBCXX_USE_CXX11_ABI=1
build --cxxopt -DENVOY_IGNORE_GLIBCXX_USE_CXX11_ABI_ERROR=1
build --cxxopt -D_FORTIFY_SOURCE=2
build --cxxopt -Wno-error=old-style-cast
build --cxxopt -Wno-error=deprecated-declarations
build --cxxopt -Wno-error=unused-variable
build --cxxopt -w
build --cxxopt -ldl
"
echo "${BUILD_OPTIONS}" >> ${SOURCE_DIR}/.bazelrc

if [ "$TARGET" == "BORINGSSL" ]; then
  exit
fi

/usr/bin/cp external_tests.sh ${SOURCE_DIR}
/usr/bin/cp bazelignore ${SOURCE_DIR}/.bazelignore

/usr/bin/cp -rf src/envoy/tcp/sni_verifier/* ${SOURCE_DIR}/src/envoy/tcp/sni_verifier/

cp openssl.BUILD ${SOURCE_DIR}

function replace_text() {
  START=$(grep -nr "${DELETE_START_PATTERN}" ${SOURCE_DIR}/${FILE} | cut -d':' -f1)
  START=$((${START} + ${START_OFFSET}))
  if [[ ! -z "${DELETE_STOP_PATTERN}" ]]; then
    STOP=$(tail --lines=+${START}  ${SOURCE_DIR}/${FILE} | grep -nr "${DELETE_STOP_PATTERN}" - |  cut -d':' -f1 | head -1)
    CUT=$((${START} + ${STOP} - 1))
  else
    CUT=$((${START}))
  fi
  CUT_TEXT=$(sed -n "${START},${CUT} p" ${SOURCE_DIR}/${FILE})
  sed -i "${START},${CUT} d" ${SOURCE_DIR}/${FILE}

  if [[ ! -z "${ADD_TEXT}" ]]; then
    ex -s -c "${START}i|${ADD_TEXT}" -c x ${SOURCE_DIR}/${FILE}
  fi
}

FILE="WORKSPACE"
DELETE_START_PATTERN="bind"
DELETE_STOP_PATTERN=")"
START_OFFSET="0"
ADD_TEXT="new_local_repository(
    name = \"openssl\",
    path = \"/usr/lib64/\",
    build_file = \"openssl.BUILD\"
)
"
replace_text

#sed -i "s|925810d00b0d3095a8e67fd4e04e0f597ed188bb|8912fa36acdf4367d37998d98cead376762d2b49|g" ${SOURCE_DIR}/WORKSPACE
#sed -i "s|26d1f14e881455546cf0e222ec92a8e1e5f65cb2c5761d63c66598b39cd9c47d|4a87094ef0a113a66baa5841cc19a0eb8524e2078cf9b495ce3f950705c63905|g" ${SOURCE_DIR}/WORKSPACE

OPENSSL_LIB="
envoy_cc_library(
    name = \"openssl_impl_lib\",
    srcs = [
        \"openssl_impl.cc\",
    ],
    hdrs = [
        \"openssl_impl.h\",
    ],
    external_deps = [
        \"ssl\",
        \"bssl_wrapper_lib\",
    ],
    repository = \"@envoy\",
)
"
echo "${OPENSSL_LIB}" >> ${SOURCE_DIR}/src/envoy/tcp/sni_verifier/BUILD

FILE="src/envoy/tcp/sni_verifier/BUILD"
DELETE_START_PATTERN="sni_verifier.h"
DELETE_STOP_PATTERN="@envoy//source/exe:envoy_common_lib"
START_OFFSET="4"
ADD_TEXT="        \":openssl_impl_lib\",
        \"@envoy//source/exe:envoy_common_lib\","
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="RSA_public_key_from_bytes"
DELETE_STOP_PATTERN="return EvpPkeyFromRsa"
START_OFFSET="-1"
ADD_TEXT="    RSA* rsa(RSA_new());
    const unsigned char *pp = (const unsigned char *)pkey_der.c_str();
    d2i_RSAPublicKey(&rsa, &pp, pkey_der.length());
    if (!rsa) {
      UpdateStatus(Status::PEM_PUBKEY_PARSE_ERROR);
    }
    bssl::UniquePtr<EVP_PKEY> result = EvpPkeyFromRsa(rsa);

    RSA_free(rsa);

    return result;"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="bssl::UniquePtr<BIGNUM> bn_x = BigNumFromBase64UrlString(x);"
DELETE_STOP_PATTERN="bssl::UniquePtr<BIGNUM> bn_y = BigNumFromBase64UrlString(y);"
START_OFFSET="0"
ADD_TEXT="    BIGNUM* bn_x = BigNumFromBase64UrlString(x);
    BIGNUM* bn_y = BigNumFromBase64UrlString(y);"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="if (EC_KEY_set_public_key_affine_coordinates(ec_key.get(), bn_x.get(),"
DELETE_STOP_PATTERN="return ec_key;"
START_OFFSET="0"
ADD_TEXT="    if (EC_KEY_set_public_key_affine_coordinates(ec_key.get(), bn_x,
                                                 bn_y) == 0) {
      BN_free(bn_x);
      BN_free(bn_y);

      UpdateStatus(Status::JWK_EC_PUBKEY_PARSE_ERROR);
      return nullptr;
    }

    BN_free(bn_x);
    BN_free(bn_y);

    return ec_key;"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="bssl::UniquePtr<BIGNUM> BigNumFromBase64UrlString(const std::string &s) {"
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="  BIGNUM* BigNumFromBase64UrlString(const std::string &s) {"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="return bssl::UniquePtr<BIGNUM>("
DELETE_STOP_PATTERN="BN_bin2bn(CastToUChar(s_decoded), s_decoded.length(), NULL));"
START_OFFSET="0"
ADD_TEXT="    return BN_bin2bn(CastToUChar(s_decoded), s_decoded.length(), NULL);"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="rsa->n = BigNumFromBase64UrlString(n).release();"
DELETE_STOP_PATTERN="rsa->e = BigNumFromBase64UrlString(e).release();"
START_OFFSET="0"
ADD_TEXT="    BIGNUM* rsa_n = BigNumFromBase64UrlString(n);
    BIGNUM* rsa_e = BigNumFromBase64UrlString(e);"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="if (!rsa->n || !rsa->e) {"
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="if (!rsa_n || !rsa_e) {"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="return rsa;"
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="    int result = RSA_set0_key(rsa.get(), rsa_n, rsa_e, nullptr);

    return rsa;"
replace_text

FILE="src/envoy/http/jwt_auth/jwt.cc"
DELETE_START_PATTERN="BN_bin2bn(signature, 32, ecdsa_sig->r);"
DELETE_STOP_PATTERN="return (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, ecdsa_sig.get(), key) =="
START_OFFSET="0"
ADD_TEXT="  BIGNUM* pr(BN_new());
  BIGNUM* ps(BN_new());
  BN_bin2bn(signature, 32, pr);
  BN_bin2bn(signature + 32, 32, ps);
  ECDSA_SIG_set0(ecdsa_sig.get(), pr, ps);

  return (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, ecdsa_sig.get(), key) =="
replace_text

FILE="src/envoy/http/jwt_auth/jwt.h"
DELETE_START_PATTERN="#include \"openssl/evp.h\""
DELETE_STOP_PATTERN=""
START_OFFSET="0"
ADD_TEXT="#include \"openssl/evp.h\"
#include \"bssl_wrapper/bssl_wrapper.h\""
replace_text


