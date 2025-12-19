cmake_minimum_required(VERSION 3.12)
project(seal_test)

# ADD THIS LINE: Tell CMake to look in Homebrew's directory
list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")

# Explicitly point to the SEAL installation prefix
set(SEAL_DIR "/opt/homebrew/opt/seal/lib/cmake/SEAL-4.1") # Check your version number!

# Find the SEAL library installed by Homebrew
find_package(SEAL REQUIRED)

add_executable(seal_test seal_test.cpp)

# Link the library
target_link_libraries(seal_test PRIVATE SEAL::seal_shared)