# $FreeBSD$

.include <src.opts.mk>

PACKAGE=	tests

TESTSRC=	${SRCTOP}/contrib/netbsd-tests/kernel
.PATH:		${SRCTOP}/sys/kern

TESTSDIR=	${TESTSBASE}/sys/kern

ATF_TESTS_C+=	basic_signal
#ATF_TESTS_C+=	kcov
.if !${MACHINE_ABI:Mpurecap}
# Makes pointers from raw VA
ATF_TESTS_C+=	kern_copyin
.endif
ATF_TESTS_C+=	kern_descrip_test
ATF_TESTS_C+=	fdgrowtable_test
ATF_TESTS_C+=	kill_zombie
.if ${MK_OPENSSL} != "no"
ATF_TESTS_C+=	ktls_test
.endif
ATF_TESTS_C+=	module_test
ATF_TESTS_C+=	ptrace_test
TEST_METADATA.ptrace_test+=		timeout="15"
ATF_TESTS_C+=	reaper
ATF_TESTS_C+=	sigaltstack
PLAIN_TESTS_C+=	subr_unit_test
ATF_TESTS_C+=	sysctl_kern_proc
ATF_TESTS_C+=	sys_getrandom
ATF_TESTS_C+=	unix_passfd_test
ATF_TESTS_C+=	unix_seqpacket_test
TEST_METADATA.unix_seqpacket_test+=	timeout="15"
ATF_TESTS_C+=	unix_socketpair_test
ATF_TESTS_C+=	waitpid_nohang
ATF_TESTS_C+=	pdeathsig

ATF_TESTS_SH+=	coredump_phnum_test
ATF_TESTS_SH+=	sonewconn_overflow
TEST_METADATA.sonewconn_overflow+=	required_programs="python"
TEST_METADATA.sonewconn_overflow+=	required_user="root"
ATF_TESTS_SH+=	sendfile_test

${PACKAGE}FILES+=	sonewconn_overflow.py
${PACKAGE}FILESMODE_sonewconn_overflow.py=0555

BINDIR=		${TESTSDIR}
PROGS+=		coredump_phnum_helper
PROGS+=		pdeathsig_helper
PROGS+=		sendfile_helper

CFLAGS.sys_getrandom+=			-I${SRCTOP}/sys/contrib/zstd/lib
LIBADD.sys_getrandom+=			zstd
LIBADD.sys_getrandom+=			c
LIBADD.sys_getrandom+=			pthread
LIBADD.ptrace_test+=			pthread
LIBADD.unix_seqpacket_test+=		pthread
LIBADD.kcov+=				pthread
LIBADD.ktls_test+=			crypto
LIBADD.sendfile_helper+=		pthread
LIBADD.fdgrowtable_test+=		util pthread kvm procstat

NETBSD_ATF_TESTS_C+=	lockf_test
NETBSD_ATF_TESTS_C+=	mqueue_test
NETBSD_ATF_TESTS_C+=	sysv_test

CFLAGS.mqueue_test+=	-I${SRCTOP}/tests
LIBADD.mqueue_test+=	rt

ATF_TESTS_C+=	libkern_crc32
SRCS.libkern_crc32+=	libkern_crc32.c
.PATH: ${SRCTOP}/sys/libkern
SRCS.libkern_crc32+=	gsb_crc32.c
CFLAGS.libkern_crc32+=	-DTESTING
.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386"
.PATH: ${SRCTOP}/sys/libkern/x86
SRCS.libkern_crc32+=	crc32_sse42.c
.elif ${MACHINE_CPUARCH} == "aarch64"
.PATH: ${SRCTOP}/sys/libkern/arm64
SRCS.libkern_crc32+=	crc32c_armv8.S
.endif

# subr_unit.c contains functions whose prototypes lie in headers that cannot be
# included in userland.  But as far as subr_unit_test goes, they're effectively
# static.  So it's ok to disable -Wmissing-prototypes for this program.
CFLAGS.subr_unit.c+=	-Wno-missing-prototypes
SRCS.subr_unit_test+=	subr_unit.c

WARNS?=	3

TESTS_SUBDIRS+=	acct
TESTS_SUBDIRS+=	execve
TESTS_SUBDIRS+=	pipe

.include <netbsd-tests.test.mk>

.include <bsd.test.mk>
