cmake_minimum_required(VERSION 3.24)
project(p2p CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies installed via Homebrew:
#   brew install ftxui sqlcipher libsodium asio
set(ASIO_ROOT "/opt/homebrew/opt/asio")
set(SODIUM_ROOT "/opt/homebrew/opt/libsodium")
set(SQLCIPHER_ROOT "/opt/homebrew/opt/sqlcipher")

list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew/opt/ftxui")
find_package(ftxui QUIET)

add_executable(p2p
    src/main.cpp
    src/crypto.cpp
    src/db.cpp
    src/net.cpp
)

target_include_directories(p2p PRIVATE
    ${ASIO_ROOT}/include
    ${SODIUM_ROOT}/include
    ${SQLCIPHER_ROOT}/include/sqlcipher
)

if(ftxui_FOUND)
    set(FTXUI_LIBS ftxui::ftxui)
else()
    target_include_directories(p2p PRIVATE /opt/homebrew/include)
    set(FTXUI_LIBS
        /opt/homebrew/opt/ftxui/lib/libftxui-component.dylib
        /opt/homebrew/opt/ftxui/lib/libftxui-dom.dylib
        /opt/homebrew/opt/ftxui/lib/libftxui-screen.dylib
    )
endif()

target_link_libraries(p2p PRIVATE
    ${SODIUM_ROOT}/lib/libsodium.dylib
    ${SQLCIPHER_ROOT}/lib/libsqlcipher.dylib
    ${FTXUI_LIBS}
)
