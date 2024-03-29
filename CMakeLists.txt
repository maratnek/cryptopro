cmake_minimum_required(VERSION 3.0.0)
project(cryptopro VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(cryptopro main.cpp)

target_compile_definitions(cryptopro PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    COMPACT
)
target_link_directories(cryptopro PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(cryptopro PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
)
target_link_libraries(cryptopro crypto ssp capi10 rdrsup pthread)

add_executable(signing-hash signing-hash.cpp)

target_compile_definitions(signing-hash PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    COMPACT
)
target_link_directories(signing-hash PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(signing-hash PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
)
target_link_libraries(signing-hash crypto ssp capi10 rdrsup pthread)

add_executable(signing-hash-2 signing-hash-2.cpp)

target_compile_definitions(signing-hash-2 PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    COMPACT
)
target_link_directories(signing-hash-2 PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(signing-hash-2 PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
)
target_link_libraries(signing-hash-2 crypto ssp capi10 rdrsup pthread)

add_executable(signing-hash-etalon signing-hash-etalon.cpp)

target_compile_definitions(signing-hash-etalon PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    COMPACT
)
target_link_directories(signing-hash-etalon PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(signing-hash-etalon PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
)
target_link_libraries(signing-hash-etalon crypto ssp capi10 rdrsup pthread)

add_executable(multi-sign-hash multi-sign-hash.cpp crypto.cpp)

target_compile_definitions(multi-sign-hash PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    COMPACT
)
target_link_directories(multi-sign-hash PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(multi-sign-hash PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
)
target_link_libraries(multi-sign-hash crypto ssp capi10 rdrsup pthread)

add_executable(create-cont-if-not-exist create-cont-if-not-exist.cpp)

target_compile_definitions(create-cont-if-not-exist PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    COMPACT
)
target_link_directories(create-cont-if-not-exist PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(create-cont-if-not-exist PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
)
target_link_libraries(create-cont-if-not-exist crypto ssp capi10 rdrsup pthread)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
