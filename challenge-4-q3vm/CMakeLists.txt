PROJECT(challenge4)
include_directories(include)
file (GLOB SOURCES "src/*.c")
add_executable(challenge4 ${SOURCES})