cmake_minimum_required(VERSION 3.24)
project(p2p VERSION 0.3.4 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies:
#   macOS (Homebrew): brew install asio libsodium sqlcipher ftxui
#   Windows (vcpkg):  vcpkg install asio libsodium sqlcipher ftxui
#                     --triplet x64-windows-static-md
#   then configure with
#   -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
#   -DVCPKG_TARGET_TRIPLET=x64-windows-static-md

if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew" "/usr/local")
    list(APPEND CMAKE_LIBRARY_PATH "/opt/homebrew/lib" "/usr/local/lib")
endif()

# asio is header-only in Homebrew; vcpkg ships an asio::asio config.
find_package(asio CONFIG QUIET)
if(asio_FOUND)
    set(ASIO_LIBS asio::asio)
else()
    find_path(ASIO_INCLUDE_DIR NAMES asio.hpp
        HINTS /opt/homebrew/opt/asio/include /usr/local/opt/asio/include)
    if(NOT ASIO_INCLUDE_DIR)
        message(FATAL_ERROR "asio headers not found")
    endif()
    set(ASIO_LIBS "")
endif()

find_path(SODIUM_INCLUDE_DIR NAMES sodium.h
    HINTS /opt/homebrew/opt/libsodium/include /usr/local/opt/libsodium/include)
find_library(SODIUM_LIBRARY NAMES libsodium sodium
    HINTS /opt/homebrew/opt/libsodium/lib /usr/local/opt/libsodium/lib)
if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found")
endif()

# sqlcipher installs sqlite3.h under include/sqlcipher on both
# Homebrew and vcpkg.
find_path(SQLCIPHER_INCLUDE_DIR NAMES sqlite3.h PATH_SUFFIXES sqlcipher
    HINTS /opt/homebrew/opt/sqlcipher /usr/local/opt/sqlcipher)
find_library(SQLCIPHER_LIBRARY NAMES sqlcipher
    HINTS /opt/homebrew/opt/sqlcipher/lib /usr/local/opt/sqlcipher/lib)
if(NOT SQLCIPHER_INCLUDE_DIR OR NOT SQLCIPHER_LIBRARY)
    message(FATAL_ERROR "sqlcipher not found")
endif()

find_package(ftxui CONFIG REQUIRED)
find_package(OpenSSL QUIET)
find_package(Threads REQUIRED)

# Release asset picked by the auto-updater for this platform. Must match
# the artifact names produced by .github/workflows/release.yml.
if(WIN32)
    set(P2P_UPDATE_ASSET "p2p-windows-x64.zip")
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(P2P_UPDATE_ASSET "p2p-macos-arm64.zip")
    else()
        set(P2P_UPDATE_ASSET "p2p-macos-x86_64.zip")
    endif()
else()
    set(P2P_UPDATE_ASSET "")
endif()

add_executable(p2p
    src/main.cpp
    src/crypto.cpp
    src/db.cpp
    src/dht.cpp
    src/endpoint.cpp
    src/invite.cpp
    src/net.cpp
    src/selftest.cpp
    src/update.cpp
)

target_compile_definitions(p2p PRIVATE
    APP_VERSION="${PROJECT_VERSION}"
    P2P_UPDATE_REPO="immersedin/enB"
    P2P_UPDATE_ASSET="${P2P_UPDATE_ASSET}"
)

target_include_directories(p2p PRIVATE
    ${ASIO_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
    ${SQLCIPHER_INCLUDE_DIR}
)

target_link_libraries(p2p PRIVATE
    ${SODIUM_LIBRARY}
    ${SQLCIPHER_LIBRARY}
    ${ASIO_LIBS}
    ftxui::ftxui
    Threads::Threads
)

# Static sqlcipher (vcpkg) needs OpenSSL symbols at link time.
if(OpenSSL_FOUND)
    target_link_libraries(p2p PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
