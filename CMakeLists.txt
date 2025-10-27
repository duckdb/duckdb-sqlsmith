cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME sqlsmith)

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(duckdb/third_party/parquet)
include_directories(src/include)
include_directories(src/third_party/sqlsmith/include)
add_subdirectory(src/third_party/sqlsmith)


set(EXTENSION_SOURCES src/sqlsmith_extension.cpp
        src/statement_generator.cpp
        src/statement_simplifier.cpp
        src/random_nums_config.cpp
        src/fuzzyduck.cpp ${EXTENSION_OBJECT_FILES})

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
