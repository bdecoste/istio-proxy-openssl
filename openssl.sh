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
/usr/bin/cp -rf src/envoy/http/jwt_auth/* ${SOURCE_DIR}/src/envoy/http/jwt_auth/

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

#sed -i "s|envoyproxy/envoy|bdecoste/envoy|g" ${SOURCE_DIR}/istio_deps
#sed -i "s|b3be5713f2100ab5c40316e73ce34581245bd26a|555f02df4d4b3a59a2e54699e22ac4fa2263fdf7|g" ${SOURCE_DIR}/istio_deps
#sed -i "s|b3be5713f2100ab5c40316e73ce34581245bd26a|555f02df4d4b3a59a2e54699e22ac4fa2263fdf7|g" ${SOURCE_DIR}/WORKSPACE
#sed -i "s|79629284ae143d66b873c08883dc6382fac2e8ed45f6f3521f7e7282b6650216|b602c0c5a12107c94471c6840fa52a61236f86895f978aff811597ce0a33ee58|g" ${SOURCE_DIR}/WORKSPACE
#sed -i "s|https://github.com/envoyproxy/envoy/archive/|https://github.com/bdecoste/envoy/archive/|g" ${SOURCE_DIR}/WORKSPACE

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









