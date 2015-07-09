{
  "targets": [{
    "target_name": "secp256k1",
    "variables": {
      "with_gmp%": "<!(./utils/has_lib.sh gmpxx)"
    },
    "sources": [
      "./secp256k1.cc",
      "./secp256k1-src/src/secp256k1.c",
      "./secp256k1-src/src/ecdsa.h",
      "./secp256k1-src/src/ecdsa_impl.h",
      "./secp256k1-src/src/eckey.h",
      "./secp256k1-src/src/eckey_impl.h",
      "./secp256k1-src/src/ecmult_gen.h",
      "./secp256k1-src/src/ecmult_gen_impl.h",
      "./secp256k1-src/src/ecmult.h",
      "./secp256k1-src/src/ecmult_impl.h",
      "./secp256k1-src/src/field_10x26.h",
      "./secp256k1-src/src/field_10x26_impl.h",
      "./secp256k1-src/src/field_5x52.h",
      "./secp256k1-src/src/field_5x52_impl.h",
      "./secp256k1-src/src/field_5x52_int128_impl.h",
      "./secp256k1-src/src/field_5x52_asm_impl.h",
      "./secp256k1-src/src/field.h",
      "./secp256k1-src/src/field_impl.h",
      "./secp256k1-src/src/group.h",
      "./secp256k1-src/src/group_impl.h",
      "./secp256k1-src/src/num.h",
      "./secp256k1-src/src/num_impl.h",
      "./secp256k1-src/src/num_gmp.h",
      "./secp256k1-src/src/num_gmp_impl.h",
      "./secp256k1-src/src/scalar_4x64.h",
      "./secp256k1-src/src/scalar_4x64_impl.h",
      "./secp256k1-src/src/scalar_8x32.h",
      "./secp256k1-src/src/scalar_8x32_impl.h",
      "./secp256k1-src/src/scalar.h",
      "./secp256k1-src/src/scalar_impl.h",
      "./secp256k1-src/src/util.h"
    ],
    "cflags": [
      "--std=c1x",
      "-Wall",
      "-Wno-maybe-uninitialized",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra"
    ],
    "include_dirs": [
      "./secp256k1-src",
      "<!(node -e \"require('nan')\")"
    ],
    "conditions": [
      [
        "with_gmp=='true'", {
          "defines": [
            "HAVE_LIBGMP=1",
            "USE_NUM_GMP=1",
            "USE_FIELD_INV_NUM=1",
            "USE_SCALAR_INV_NUM=1"
          ],
          "libraries": [
            "-lgmpxx",
            "-lgmp"
          ]
        }, {
          "defines": [
            "USE_NUM_NONE=1",
            "USE_SCALAR_INV_BUILTIN=1",
            "USE_FIELD_INV_BUILTIN=1"
          ]
        }
      ],
      [
        "target_arch=='ia32'", {
          "defines": [
            "USE_FIELD_10X26=1",
            "USE_SCALAR_8X32=1"
          ]
        }
      ],
      [
        "target_arch=='x64'", {
          "defines": [
            "USE_ASM_X86_64=1",
            "USE_FIELD_5X52=1",
            "USE_FIELD_5X52_INT128=1",
            "USE_SCALAR_4X64=1"
          ]
        }
      ],

      [
        "OS=='win'", {
          "conditions": [
            [
              "target_arch=='x64'", {
                "variables": {
                  "openssl_root%": "C:/OpenSSL-Win64"
                },
              }, {
                "variables": {
                  "openssl_root%": "C:/OpenSSL-Win32"
                }
              }
            ]
          ],
          "libraries": [
            "-l<(openssl_root)/lib/libeay32.lib",
          ],
          "include_dirs": [
            "<(openssl_root)/include",
          ],
        }, {
          "conditions": [
            [
              "target_arch=='ia32'", {
                "variables": {
                  "openssl_config_path": "<(nodedir)/deps/openssl/config/piii"
                }
              }
            ],
            [
              "target_arch=='x64'", {
                "variables": {
                  "openssl_config_path": "<(nodedir)/deps/openssl/config/k8"
                },
              }
            ],
            [
              "target_arch=='arm'", {
                "variables": {
                  "openssl_config_path": "<(nodedir)/deps/openssl/config/arm"
                }
              }
            ],
          ],
          "include_dirs": [
            "<(nodedir)/deps/openssl/openssl/include",
            "<(openssl_config_path)"
          ]
        }
      ]
    ]
  }]
}
