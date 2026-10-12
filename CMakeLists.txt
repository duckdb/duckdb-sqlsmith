cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME sqlsmith)

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
        src/fuzzyduck.cpp ${EXTENSION_OBJECT_FILES})

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
