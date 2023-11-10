cmake_minimum_required(VERSION 3.0.0)
project(cryptopro VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_CXX_STANDARD 17)
set(CXX_STANDARD 17)

#  Main Project
# add_executable(cryptopro main.cpp)

# target_compile_definitions(cryptopro PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )
# target_link_directories(cryptopro PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(cryptopro PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
# )
# target_link_libraries(cryptopro crypto ssp capi10 rdrsup pthread)

# # Signing hash Project
# add_executable(signing-hash signing-hash.cpp)

# target_compile_definitions(signing-hash PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )
# target_link_directories(signing-hash PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(signing-hash PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
# )
# target_link_libraries(signing-hash crypto ssp capi10 rdrsup pthread)

# # Signing hash Project 2
# add_executable(signing-hash-2 signing-hash-2.cpp)

# target_compile_definitions(signing-hash-2 PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )
# target_link_directories(signing-hash-2 PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(signing-hash-2 PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
# )
# target_link_libraries(signing-hash-2 crypto ssp capi10 rdrsup pthread)

# # Signing hash etalon Project
# add_executable(signing-hash-etalon signing-hash-etalon.cpp)

# target_compile_definitions(signing-hash-etalon PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )
# target_link_directories(signing-hash-etalon PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(signing-hash-etalon PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
# )
# target_link_libraries(signing-hash-etalon crypto ssp capi10 rdrsup pthread)

# # Multi sign hash Project
# add_executable(multi-sign-hash multi-sign-hash.cpp crypto.cpp)

# target_compile_definitions(multi-sign-hash PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )
# target_link_directories(multi-sign-hash PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(multi-sign-hash PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
# )
# target_link_libraries(multi-sign-hash crypto ssp capi10 rdrsup pthread)

# # Create container if not already created
# add_executable(create-cont-if-not-exist create-cont-if-not-exist.cpp)

# target_compile_definitions(create-cont-if-not-exist PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )
# target_link_directories(create-cont-if-not-exist PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(create-cont-if-not-exist PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
# )
# target_link_libraries(create-cont-if-not-exist crypto ssp capi10 rdrsup pthread)

# #  Test Crypto lib Project
# add_executable(test-crypto test-crypto.cpp crypto.cpp)

# target_compile_definitions(test-crypto PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )
# target_link_directories(test-crypto PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(test-crypto PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
# )
# target_link_libraries(test-crypto crypto ssp capi10 rdrsup pthread)



#  Test Certificate lib Project single thread
# add_executable(test-certificate 
#     test-certificate.cpp 
#     crypto.cpp
# )

# target_compile_definitions(test-certificate PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )

# target_link_directories(test-certificate PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(test-certificate PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
#     /opt/cprocsp/include/pki 
# )
# target_link_libraries(test-certificate crypto ssp capi10 capi20 rdrsup pthread)

#  Test Create self Certificate 
# add_executable(test-self-certificate 
#     create-self-cert.cpp 
#     # crypto.cpp
# )

# target_compile_definitions(test-self-certificate PUBLIC 
#     SIZEOF_VOID_P=8 
#     UNIX
#     HAVE_LIMITS_H
#     HAVE_STD_INT_H
#     HAVE_SYS_INTTYPES_H
#     COMPACT
# )

# target_link_directories(test-self-certificate PUBLIC /opt/cprocsp/lib/amd64)
# target_include_directories(test-self-certificate PUBLIC 
#     /opt/cprocsp 
#     /opt/cprocsp/include/ 
#     /opt/cprocsp/include/cpcsp
#     /opt/cprocsp/include/pki 
# )
# target_link_libraries(test-self-certificate crypto ssp capi10 capi20 rdrsup pthread)


#  Test work with Certificate 
add_executable(test-certificate 
    certificate.cpp 
    crypto.cpp
)

target_compile_definitions(test-certificate PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    HAVE_SYS_INTTYPES_H
    COMPACT
)

target_link_directories(test-certificate PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(test-certificate PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
    /opt/cprocsp/include/pki 
)
target_link_libraries(test-certificate crypto ssp capi10 capi20 rdrsup pthread)

#  Test work with Certificate 
add_executable(test-crypto-single-thread 
    test-crypto-single-thread.cpp
    crypto.cpp
)

target_compile_definitions(test-crypto-single-thread PUBLIC 
    SIZEOF_VOID_P=8 
    UNIX
    HAVE_LIMITS_H
    HAVE_STD_INT_H
    HAVE_SYS_INTTYPES_H
    COMPACT
)

target_link_directories(test-crypto-single-thread PUBLIC /opt/cprocsp/lib/amd64)
target_include_directories(test-crypto-single-thread PUBLIC 
    /opt/cprocsp 
    /opt/cprocsp/include/ 
    /opt/cprocsp/include/cpcsp
    /opt/cprocsp/include/pki 
)
target_link_libraries(test-crypto-single-thread crypto ssp capi10 capi20 rdrsup pthread)
