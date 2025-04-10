#  Copyright 2019 Eneas Ulir de Queiroz
#  Copyright (c) 2025 ASPEED Technology Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 2.6 FATAL_ERROR)
project(ast_crypto_engine LANGUAGES C)

include(CheckIncludeFile)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Remove when https://gitlab.kitware.com/cmake/cmake/issues/18525 is addressed
set(OPENSSL_ENGINES_DIR "" CACHE PATH "OpenSSL Engines Directory")
if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
	include(FindPkgConfig)
	pkg_get_variable(OPENSSL_ENGINES_DIR libcrypto enginesdir)
	if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
		message( FATAL_ERROR "Unable to discover the OpenSSL engines directory. Provide the path using -DOPENSSL_ENGINES_DIR" )
	endif()
endif()

option(USE_CRYPTOUSER "Use crypto_user module to display driver information" ON)
if (USE_CRYPTOUSER)
	check_include_file(linux/cryptouser.h HAVE_CRYPTOUSER_H)
	if (NOT HAVE_CRYPTOUSER_H)
		message( WARNING "Unable to find linux/cryptouser.h, disabling display of driver information" )
		add_definitions(-DAFALG_NO_CRYPTOUSER)
	endif()
else()
	add_definitions(-DAFALG_NO_CRYPTOUSER)
endif()

option(USE_ZERO_COPY "Use zero-copy AF_ALG interface" OFF)
if (USE_ZERO_COPY)
	add_definitions(-DAFALG_ZERO_COPY)
endif()

option(UPDATE_CTR_IV "Don't rely on kernel driver to update CTR-mode IV" ON)
if (NOT UPDATE_CTR_IV)
	add_definitions(-DAFALG_KERNEL_UPDATES_CTR_IV)
endif()

option(DIGESTS "Build support for message digest operations" on)
if (DIGESTS)
	add_definitions(-DAFALG_DIGESTS)
endif()

option(FALLBACK "Fallback to using software to perform smaller cipher operations" ON)
if (NOT FALLBACK)
	add_definitions(-DAFALG_NO_FALLBACK)
endif()

add_library(ast_crypto_engine MODULE ast_crypto_engine.c)
set_target_properties(ast_crypto_engine PROPERTIES PREFIX "" OUTPUT_NAME "ast_crypto_engine")
target_link_libraries(ast_crypto_engine ${OPENSSL_CRYPTO_LIBRARY})

install(TARGETS ast_crypto_engine LIBRARY DESTINATION ${OPENSSL_ENGINES_DIR})


