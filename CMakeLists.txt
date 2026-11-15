cmake_minimum_required(VERSION 3.24)
# Fallback version for builds without git metadata (e.g. source tarballs);
# when a git checkout is available the version is taken from `git describe`
# below, so release tags drive APP_VERSION automatically.
project(radius VERSION 0.4.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# geo_macos.mm (CoreLocation) needs the Objective-C++ compiler.
if(APPLE)
    enable_language(OBJCXX)
endif()

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
    set(RADIUS_UPDATE_ASSET "radius-windows-x64.zip")
elseif(APPLE)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(RADIUS_UPDATE_ASSET "radius-macos-arm64.zip")
    else()
        set(RADIUS_UPDATE_ASSET "radius-macos-x86_64.zip")
    endif()
else()
    set(RADIUS_UPDATE_ASSET "")
endif()

add_executable(radius
    src/ai.cpp
    src/main.cpp
    src/crypto.cpp
    src/danger.cpp
    src/db.cpp
    src/dht.cpp
    src/endpoint.cpp
    src/geo.cpp
    src/invite.cpp
    src/net.cpp
    src/news.cpp
    src/selftest.cpp
    src/update.cpp
)

# Derive the app version from the nearest git tag ("v0.4.0",
# "v0.4.0-3-gdeadbee", ...). Falls back to PROJECT_VERSION for tarball
# builds or checkouts without tags.
set(RADIUS_APP_VERSION "${PROJECT_VERSION}")
execute_process(
    COMMAND git describe --tags --always --dirty
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_DESCRIBE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(GIT_DESCRIBE MATCHES "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+)")
    set(RADIUS_APP_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}")
elseif(GIT_DESCRIBE MATCHES "^v?([0-9]+)\\.([0-9]+)")
    set(RADIUS_APP_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.0")
endif()
message(STATUS "radius version: ${RADIUS_APP_VERSION} (git: '${GIT_DESCRIBE}')")

target_compile_definitions(radius PRIVATE
    APP_VERSION="${RADIUS_APP_VERSION}"
    RADIUS_UPDATE_REPO="immersedin/enB"
    RADIUS_UPDATE_ASSET="${RADIUS_UPDATE_ASSET}"
)

target_include_directories(radius PRIVATE
    ${ASIO_INCLUDE_DIR}
    ${SODIUM_INCLUDE_DIR}
    ${SQLCIPHER_INCLUDE_DIR}
)

target_link_libraries(radius PRIVATE
    ${SODIUM_LIBRARY}
    ${SQLCIPHER_LIBRARY}
    ${ASIO_LIBS}
    ftxui::ftxui
    Threads::Threads
)

# Static sqlcipher (vcpkg) needs OpenSSL symbols at link time.
if(OpenSSL_FOUND)
    target_link_libraries(radius PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(APPLE)
    target_sources(radius PRIVATE src/geo_macos.mm src/audio_macos.mm)
    find_library(CORELOCATION_LIB CoreLocation)
    find_library(COREFOUNDATION_LIB CoreFoundation)
    find_library(FOUNDATION_LIB Foundation)
    # CoreAudio HAL: notification-sound output device enumeration and
    # routing (kAudioHardwareProperty*).
    find_library(COREAUDIO_LIB CoreAudio)
    target_link_libraries(radius PRIVATE
        ${CORELOCATION_LIB} ${COREFOUNDATION_LIB} ${FOUNDATION_LIB}
        ${COREAUDIO_LIB})
else()
    target_sources(radius PRIVATE src/audio_other.cpp)
endif()

if(WIN32)
    target_sources(radius PRIVATE src/geo_windows.cpp)
    # WinRT activation (RoGetActivationFactory, WindowsCreateString).
    target_link_libraries(radius PRIVATE windowsapp combase)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # GeoClue2 over the system D-Bus (GNOME/KDE location service).
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DBUS1 REQUIRED dbus-1)
    target_sources(radius PRIVATE src/geo_linux.cpp)
    target_include_directories(radius PRIVATE ${DBUS1_INCLUDE_DIRS})
    target_link_libraries(radius PRIVATE ${DBUS1_LIBRARIES})
    target_compile_definitions(radius PRIVATE ${DBUS1_CFLAGS_OTHER})
endif()
