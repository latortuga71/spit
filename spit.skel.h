/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __SPIT_BPF_SKEL_H__
#define __SPIT_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct spit_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *__bpf_usdt_specs;
		struct bpf_map *kernel_ring_buffer;
		struct bpf_map *__bpf_usdt_ip_to_spec_id;
		struct bpf_map *bss;
		struct bpf_map *rodata;
		struct bpf_map *kconfig;
	} maps;
	struct {
		struct bpf_program *uprobe_pam_get_authtok;
	} progs;
	struct {
		struct bpf_link *uprobe_pam_get_authtok;
	} links;
	struct spit_bpf__bss {
		int my_pid;
	} *bss;
	struct spit_bpf__kconfig {
		const _Bool LINUX_HAS_BPF_COOKIE;
	} *kconfig;

#ifdef __cplusplus
	static inline struct spit_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct spit_bpf *open_and_load();
	static inline int load(struct spit_bpf *skel);
	static inline int attach(struct spit_bpf *skel);
	static inline void detach(struct spit_bpf *skel);
	static inline void destroy(struct spit_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
spit_bpf__destroy(struct spit_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
spit_bpf__create_skeleton(struct spit_bpf *obj);

static inline struct spit_bpf *
spit_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct spit_bpf *obj;
	int err;

	obj = (struct spit_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = spit_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	spit_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct spit_bpf *
spit_bpf__open(void)
{
	return spit_bpf__open_opts(NULL);
}

static inline int
spit_bpf__load(struct spit_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct spit_bpf *
spit_bpf__open_and_load(void)
{
	struct spit_bpf *obj;
	int err;

	obj = spit_bpf__open();
	if (!obj)
		return NULL;
	err = spit_bpf__load(obj);
	if (err) {
		spit_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
spit_bpf__attach(struct spit_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
spit_bpf__detach(struct spit_bpf *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *spit_bpf__elf_bytes(size_t *sz);

static inline int
spit_bpf__create_skeleton(struct spit_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "spit_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 6;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "__bpf_usdt_specs";
	s->maps[0].map = &obj->maps.__bpf_usdt_specs;

	s->maps[1].name = "kernel_ring_buffer";
	s->maps[1].map = &obj->maps.kernel_ring_buffer;

	s->maps[2].name = "__bpf_usdt_ip_to_spec_id";
	s->maps[2].map = &obj->maps.__bpf_usdt_ip_to_spec_id;

	s->maps[3].name = "spit_bpf.bss";
	s->maps[3].map = &obj->maps.bss;
	s->maps[3].mmaped = (void **)&obj->bss;

	s->maps[4].name = "spit_bpf.rodata";
	s->maps[4].map = &obj->maps.rodata;

	s->maps[5].name = "spit_bp.kconfig";
	s->maps[5].map = &obj->maps.kconfig;
	s->maps[5].mmaped = (void **)&obj->kconfig;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "uprobe_pam_get_authtok";
	s->progs[0].prog = &obj->progs.uprobe_pam_get_authtok;
	s->progs[0].link = &obj->links.uprobe_pam_get_authtok;

	s->data = spit_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *spit_bpf__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x30\x24\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0d\0\
\x01\0\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x74\
\x65\x78\x74\0\x75\x70\x72\x6f\x62\x65\0\x2e\x6d\x61\x70\x73\0\x6c\x69\x63\x65\
\x6e\x73\x65\0\x2e\x62\x73\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x73\x70\x69\x74\
\x2e\x62\x70\x66\x2e\x63\0\x4c\x42\x42\x30\x5f\x33\0\x4c\x42\x42\x30\x5f\x34\0\
\x4c\x42\x42\x30\x5f\x37\0\x4c\x42\x42\x31\x5f\x33\0\x4c\x42\x42\x31\x5f\x34\0\
\x4c\x42\x42\x31\x5f\x31\x38\0\x4c\x42\x42\x31\x5f\x31\x33\0\x4c\x42\x42\x31\
\x5f\x31\x32\0\x4c\x42\x42\x31\x5f\x31\x35\0\x4c\x42\x42\x31\x5f\x31\x37\0\x4c\
\x42\x42\x32\x5f\x33\0\x4c\x42\x42\x32\x5f\x34\0\x4c\x42\x42\x32\x5f\x37\0\x4c\
\x42\x42\x33\x5f\x33\0\x75\x70\x72\x6f\x62\x65\x5f\x70\x61\x6d\x5f\x67\x65\x74\
\x5f\x61\x75\x74\x68\x74\x6f\x6b\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x62\x70\x66\
\x5f\x75\x73\x64\x74\x5f\x61\x72\x67\x5f\x63\x6e\x74\0\x4c\x49\x4e\x55\x58\x5f\
\x48\x41\x53\x5f\x42\x50\x46\x5f\x43\x4f\x4f\x4b\x49\x45\0\x5f\x5f\x62\x70\x66\
\x5f\x75\x73\x64\x74\x5f\x69\x70\x5f\x74\x6f\x5f\x73\x70\x65\x63\x5f\x69\x64\0\
\x5f\x5f\x62\x70\x66\x5f\x75\x73\x64\x74\x5f\x73\x70\x65\x63\x73\0\x62\x70\x66\
\x5f\x75\x73\x64\x74\x5f\x61\x72\x67\0\x62\x70\x66\x5f\x75\x73\x64\x74\x5f\x63\
\x6f\x6f\x6b\x69\x65\0\x75\x70\x72\x6f\x62\x65\x5f\x70\x61\x6d\x5f\x67\x65\x74\
\x5f\x61\x75\x74\x68\x74\x6f\x6b\0\x6b\x65\x72\x6e\x65\x6c\x5f\x72\x69\x6e\x67\
\x5f\x62\x75\x66\x66\x65\x72\0\x4c\x49\x43\x45\x4e\x53\x45\0\x6d\x79\x5f\x70\
\x69\x64\0\x2e\x72\x65\x6c\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x75\x70\x72\
\x6f\x62\x65\0\x2e\x42\x54\x46\0\x2e\x42\x54\x46\x2e\x65\x78\x74\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x39\0\0\0\x04\0\xf1\xff\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x44\0\0\0\0\0\x03\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4b\0\0\0\0\0\x03\0\x90\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x52\0\0\0\0\0\x03\0\x10\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x59\0\0\0\0\0\x03\0\xd0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\0\0\0\0\0\
\x03\0\xe0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x67\0\0\0\0\0\x03\0\xf8\x04\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x6f\0\0\0\0\0\x03\0\x88\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x77\0\0\0\0\0\x03\0\xf0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f\0\0\0\0\0\x03\0\
\x68\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x87\0\0\0\0\0\x03\0\xe0\x04\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x8f\0\0\0\0\0\x03\0\x90\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x96\0\0\
\0\0\0\x03\0\x98\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9d\0\0\0\0\0\x03\0\xf8\x05\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xa4\0\0\0\0\0\x04\0\x90\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xab\0\0\0\x01\0\x08\0\
\0\0\0\0\0\0\0\0\x1a\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\xca\0\0\0\x22\x02\x03\0\0\0\0\0\0\0\0\0\x20\x01\0\0\0\0\0\0\xdb\0\0\0\
\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\0\0\0\x21\0\x05\0\x30\0\0\0\0\0\
\0\0\x20\0\0\0\0\0\0\0\x09\x01\0\0\x21\0\x05\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\
\0\x1a\x01\0\0\x22\x02\x03\0\x20\x01\0\0\0\0\0\0\xe8\x03\0\0\0\0\0\0\x27\x01\0\
\0\x22\x02\x03\0\x08\x05\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\x37\x01\0\0\x12\0\x04\0\
\0\0\0\0\0\0\0\0\x98\x01\0\0\0\0\0\0\x4e\x01\0\0\x11\0\x05\0\x20\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x61\x01\0\0\x11\0\x06\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\
\x69\x01\0\0\x11\0\x07\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x18\x02\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x71\x22\0\0\0\0\0\0\x55\x02\x0d\0\0\0\0\0\x79\x11\x80\0\0\0\0\
\0\x7b\x1a\xf8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\x18\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\xbf\x01\0\0\0\0\0\0\x18\0\
\0\0\xfd\xff\xff\xff\0\0\0\0\0\0\0\0\x15\x01\x03\0\0\0\0\0\x61\x10\0\0\0\0\0\0\
\x05\0\x01\0\0\0\0\0\x85\0\0\0\xae\0\0\0\x18\x06\0\0\xfd\xff\xff\xff\0\0\0\0\0\
\0\0\0\x63\x0a\xf4\xff\0\0\0\0\x67\0\0\0\x20\0\0\0\xc7\0\0\0\x20\0\0\0\xb7\x01\
\0\0\0\0\0\0\x6d\x01\x09\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf4\xff\xff\
\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x03\0\0\0\0\
\0\x69\x06\xc8\0\0\0\0\0\x67\x06\0\0\x30\0\0\0\xc7\x06\0\0\x30\0\0\0\xbf\x60\0\
\0\0\0\0\0\x95\0\0\0\0\0\0\0\xbf\x27\0\0\0\0\0\0\xbf\x19\0\0\0\0\0\0\xb7\x01\0\
\0\0\0\0\0\x7b\x3a\xe8\xff\0\0\0\0\x7b\x13\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x71\x11\0\0\0\0\0\0\x55\x01\x0d\0\0\0\0\0\x79\x91\x80\0\0\0\0\0\
\x7b\x1a\xf8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\x18\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\xbf\x01\0\0\0\0\0\0\x18\0\
\0\0\xfd\xff\xff\xff\0\0\0\0\0\0\0\0\x15\x01\x04\0\0\0\0\0\x61\x10\0\0\0\0\0\0\
\x05\0\x02\0\0\0\0\0\xbf\x91\0\0\0\0\0\0\x85\0\0\0\xae\0\0\0\x18\x06\0\0\xfd\
\xff\xff\xff\0\0\0\0\0\0\0\0\x63\x0a\xf4\xff\0\0\0\0\x67\0\0\0\x20\0\0\0\xc7\0\
\0\0\x20\0\0\0\xb7\x01\0\0\0\0\0\0\x6d\x01\x5c\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\
\x07\x02\0\0\xf4\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\
\0\0\0\xbf\x08\0\0\0\0\0\0\x15\x08\x55\0\0\0\0\0\x18\x06\0\0\xfe\xff\xff\xff\0\
\0\0\0\0\0\0\0\x25\x07\x52\0\x0b\0\0\0\x69\x81\xc8\0\0\0\0\0\x67\x01\0\0\x30\0\
\0\0\xc7\x01\0\0\x30\0\0\0\x3d\x17\x4e\0\0\0\0\0\xbf\x71\0\0\0\0\0\0\x67\x01\0\
\0\x04\0\0\0\xbf\x82\0\0\0\0\0\0\x0f\x12\0\0\0\0\0\0\x61\x21\x08\0\0\0\0\0\x15\
\x01\x1a\0\x02\0\0\0\x15\x01\x06\0\x01\0\0\0\x18\x06\0\0\xea\xff\xff\xff\0\0\0\
\0\0\0\0\0\x55\x01\x44\0\0\0\0\0\x79\x21\0\0\0\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\
\x05\0\x2f\0\0\0\0\0\xbf\x71\0\0\0\0\0\0\x67\x01\0\0\x04\0\0\0\xbf\x82\0\0\0\0\
\0\0\x0f\x12\0\0\0\0\0\0\x69\x21\x0c\0\0\0\0\0\x67\x01\0\0\x30\0\0\0\xc7\x01\0\
\0\x30\0\0\0\x0f\x19\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xf8\xff\xff\
\xff\xb7\x02\0\0\x08\0\0\0\xbf\x93\0\0\0\0\0\0\x85\0\0\0\x71\0\0\0\xbf\x06\0\0\
\0\0\0\0\xbf\x61\0\0\0\0\0\0\x67\x01\0\0\x20\0\0\0\x77\x01\0\0\x20\0\0\0\x15\
\x01\x1d\0\0\0\0\0\x05\0\x2e\0\0\0\0\0\x69\x21\x0c\0\0\0\0\0\x67\x01\0\0\x30\0\
\0\0\xc7\x01\0\0\x30\0\0\0\x0f\x19\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\
\xf8\xff\xff\xff\xbf\x26\0\0\0\0\0\0\xb7\x02\0\0\x08\0\0\0\xbf\x93\0\0\0\0\0\0\
\x85\0\0\0\x71\0\0\0\xbf\x62\0\0\0\0\0\0\xbf\x06\0\0\0\0\0\0\xbf\x61\0\0\0\0\0\
\0\x67\x01\0\0\x20\0\0\0\x77\x01\0\0\x20\0\0\0\x55\x01\x1e\0\0\0\0\0\x79\x21\0\
\0\0\0\0\0\x79\xa3\xf8\xff\0\0\0\0\x0f\x13\0\0\0\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\
\x01\0\0\xf8\xff\xff\xff\xb7\x02\0\0\x08\0\0\0\x85\0\0\0\x70\0\0\0\xbf\x06\0\0\
\0\0\0\0\xbf\x61\0\0\0\0\0\0\x67\x01\0\0\x20\0\0\0\x77\x01\0\0\x20\0\0\0\x55\
\x01\x12\0\0\0\0\0\x67\x07\0\0\x04\0\0\0\x0f\x78\0\0\0\0\0\0\x71\x81\x0f\0\0\0\
\0\0\x67\x01\0\0\x38\0\0\0\xc7\x01\0\0\x38\0\0\0\x67\x01\0\0\x20\0\0\0\x77\x01\
\0\0\x20\0\0\0\x79\xa2\xf8\xff\0\0\0\0\x6f\x12\0\0\0\0\0\0\xbf\x23\0\0\0\0\0\0\
\x7f\x13\0\0\0\0\0\0\x71\x84\x0e\0\0\0\0\0\x15\x04\x02\0\0\0\0\0\xcf\x12\0\0\0\
\0\0\0\xbf\x23\0\0\0\0\0\0\x79\xa1\xe8\xff\0\0\0\0\x7b\x31\0\0\0\0\0\0\xb7\x06\
\0\0\0\0\0\0\xbf\x60\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x18\x02\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x71\x22\0\0\0\0\0\0\x55\x02\x0d\0\0\0\0\0\x79\x11\x80\0\0\0\0\0\x7b\
\x1a\xf8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf8\xff\xff\xff\x18\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\xbf\x01\0\0\0\0\0\0\x18\0\0\0\
\xfd\xff\xff\xff\0\0\0\0\0\0\0\0\x15\x01\x03\0\0\0\0\0\x61\x10\0\0\0\0\0\0\x05\
\0\x01\0\0\0\0\0\x85\0\0\0\xae\0\0\0\x63\x0a\xf4\xff\0\0\0\0\x67\0\0\0\x20\0\0\
\0\xc7\0\0\0\x20\0\0\0\xb7\x06\0\0\0\0\0\0\x6d\x06\x07\0\0\0\0\0\xbf\xa2\0\0\0\
\0\0\0\x07\x02\0\0\xf4\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\
\0\x01\0\0\0\x15\0\x01\0\0\0\0\0\x79\x06\xc0\0\0\0\0\0\xbf\x60\0\0\0\0\0\0\x95\
\0\0\0\0\0\0\0\xb7\0\0\0\0\0\0\0\x79\x12\x70\0\0\0\0\0\x15\x02\x2f\0\0\0\0\0\
\x79\x17\x70\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x7b\x1a\xf8\xff\0\0\0\0\x7b\x1a\xf0\
\xff\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x1a\0\0\0\xb7\x03\
\0\0\0\0\0\0\xb7\x04\0\0\0\0\0\0\x85\0\0\0\x06\0\0\0\x85\0\0\0\x0e\0\0\0\xbf\
\x06\0\0\0\0\0\0\xbf\x73\0\0\0\0\0\0\x07\x03\0\0\x30\0\0\0\xbf\xa1\0\0\0\0\0\0\
\x07\x01\0\0\xf8\xff\xff\xff\xb7\x02\0\0\x08\0\0\0\x85\0\0\0\x04\0\0\0\xbf\xa1\
\0\0\0\0\0\0\x07\x01\0\0\xf0\xff\xff\xff\xb7\x02\0\0\x08\0\0\0\xbf\x73\0\0\0\0\
\0\0\x85\0\0\0\x04\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x04\
\x04\0\0\xb7\x03\0\0\0\0\0\0\x85\0\0\0\x83\0\0\0\xbf\x07\0\0\0\0\0\0\xb7\0\0\0\
\x01\0\0\0\x15\x07\x10\0\0\0\0\0\x77\x06\0\0\x20\0\0\0\x63\x67\0\0\0\0\0\0\x79\
\xa3\xf0\xff\0\0\0\0\xbf\x71\0\0\0\0\0\0\x07\x01\0\0\x04\x02\0\0\xb7\x02\0\0\0\
\x02\0\0\x85\0\0\0\x04\0\0\0\x79\xa3\xf8\xff\0\0\0\0\xbf\x71\0\0\0\0\0\0\x07\
\x01\0\0\x04\0\0\0\xb7\x02\0\0\0\x02\0\0\x85\0\0\0\x04\0\0\0\xbf\x71\0\0\0\0\0\
\0\xb7\x02\0\0\0\0\0\0\x85\0\0\0\x84\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x44\x75\x61\x6c\x20\x42\x53\x44\x2f\x47\x50\x4c\0\0\0\0\x55\x73\x65\x72\
\x6e\x61\x6d\x65\x3a\x20\x25\x73\x20\x50\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\
\x25\x73\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x15\0\0\0\x40\0\0\0\0\0\0\0\
\x01\0\0\0\x16\0\0\0\xd8\0\0\0\0\0\0\0\x01\0\0\0\x17\0\0\0\x48\x01\0\0\0\0\0\0\
\x01\0\0\0\x15\0\0\0\x88\x01\0\0\0\0\0\0\x01\0\0\0\x16\0\0\0\x28\x02\0\0\0\0\0\
\0\x01\0\0\0\x17\0\0\0\x08\x05\0\0\0\0\0\0\x01\0\0\0\x15\0\0\0\x48\x05\0\0\0\0\
\0\0\x01\0\0\0\x16\0\0\0\xd0\x05\0\0\0\0\0\0\x01\0\0\0\x17\0\0\0\x38\0\0\0\0\0\
\0\0\x01\0\0\0\x13\0\0\0\xd0\0\0\0\0\0\0\0\x01\0\0\0\x1b\0\0\0\x9f\xeb\x01\0\
\x18\0\0\0\0\0\0\0\xe4\x05\0\0\xe4\x05\0\0\x6a\x09\0\0\0\0\0\0\0\0\0\x02\x03\0\
\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\
\0\0\x04\0\0\0\x02\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\
\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\x02\x02\0\0\0\0\0\0\0\0\0\0\x02\x09\0\0\0\x19\0\0\0\x03\0\0\x04\xd0\0\0\
\0\x29\0\0\0\x12\0\0\0\0\0\0\0\x2e\0\0\0\x0b\0\0\0\0\x06\0\0\x3a\0\0\0\x0e\0\0\
\0\x40\x06\0\0\x42\0\0\0\x05\0\0\x04\x10\0\0\0\x56\0\0\0\x0b\0\0\0\0\0\0\0\x5e\
\0\0\0\x0d\0\0\0\x40\0\0\0\x67\0\0\0\x0e\0\0\0\x60\0\0\0\x6f\0\0\0\x0f\0\0\0\
\x70\0\0\0\x7a\0\0\0\x11\0\0\0\x78\0\0\0\x87\0\0\0\0\0\0\x08\x0c\0\0\0\x8d\0\0\
\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\xa0\0\0\0\x03\0\0\x06\x04\0\0\0\xb4\0\0\0\0\0\
\0\0\xc7\0\0\0\x01\0\0\0\xd8\0\0\0\x02\0\0\0\xef\0\0\0\0\0\0\x01\x02\0\0\0\x10\
\0\0\x01\xf5\0\0\0\0\0\0\x08\x10\0\0\0\xfa\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\
\x04\0\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x0a\0\
\0\0\x04\0\0\0\x0c\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x05\x01\0\0\x01\0\0\0\0\
\0\0\0\x0a\x01\0\0\x05\0\0\0\x40\0\0\0\x16\x01\0\0\x07\0\0\0\x80\0\0\0\x1a\x01\
\0\0\x08\0\0\0\xc0\0\0\0\x20\x01\0\0\0\0\0\x0e\x13\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\x02\x16\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x1b\0\0\0\0\0\0\
\0\0\0\0\x02\x18\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\0\x04\0\
\0\0\0\0\x02\0\0\x04\x10\0\0\0\x05\x01\0\0\x15\0\0\0\0\0\0\0\x0a\x01\0\0\x17\0\
\0\0\x40\0\0\0\x31\x01\0\0\0\0\0\x0e\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x1c\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\x02\x1e\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\0\x04\0\0\0\0\0\0\
\0\0\0\x02\x20\0\0\0\x44\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\x01\0\0\0\0\0\0\0\
\x02\x22\0\0\0\x49\x01\0\0\0\0\0\x08\x23\0\0\0\x4f\x01\0\0\0\0\0\x01\x04\0\0\0\
\x20\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x05\x01\0\0\x1b\0\0\0\0\0\0\0\x0a\x01\
\0\0\x1d\0\0\0\x40\0\0\0\x16\x01\0\0\x1f\0\0\0\x80\0\0\0\x1a\x01\0\0\x21\0\0\0\
\xc0\0\0\0\x5c\x01\0\0\0\0\0\x0e\x24\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x27\0\0\
\0\x75\x01\0\0\x15\0\0\x04\xa8\0\0\0\x7d\x01\0\0\x28\0\0\0\0\0\0\0\x81\x01\0\0\
\x28\0\0\0\x40\0\0\0\x85\x01\0\0\x28\0\0\0\x80\0\0\0\x89\x01\0\0\x28\0\0\0\xc0\
\0\0\0\x8d\x01\0\0\x28\0\0\0\0\x01\0\0\x90\x01\0\0\x28\0\0\0\x40\x01\0\0\x93\
\x01\0\0\x28\0\0\0\x80\x01\0\0\x97\x01\0\0\x28\0\0\0\xc0\x01\0\0\x9b\x01\0\0\
\x28\0\0\0\0\x02\0\0\x9e\x01\0\0\x28\0\0\0\x40\x02\0\0\xa1\x01\0\0\x28\0\0\0\
\x80\x02\0\0\xa4\x01\0\0\x28\0\0\0\xc0\x02\0\0\xa7\x01\0\0\x28\0\0\0\0\x03\0\0\
\xaa\x01\0\0\x28\0\0\0\x40\x03\0\0\xad\x01\0\0\x28\0\0\0\x80\x03\0\0\xb0\x01\0\
\0\x28\0\0\0\xc0\x03\0\0\xb8\x01\0\0\x28\0\0\0\0\x04\0\0\xbb\x01\0\0\x28\0\0\0\
\x40\x04\0\0\xbe\x01\0\0\x28\0\0\0\x80\x04\0\0\xc4\x01\0\0\x28\0\0\0\xc0\x04\0\
\0\xc7\x01\0\0\x28\0\0\0\0\x05\0\0\xca\x01\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\
\0\0\0\x01\0\0\x0d\x02\0\0\0\xd8\x01\0\0\x26\0\0\0\xdc\x01\0\0\x01\0\0\x0c\x29\
\0\0\0\0\0\0\0\x03\0\0\x0d\x02\0\0\0\xd8\x01\0\0\x26\0\0\0\xed\x01\0\0\x0b\0\0\
\0\xf5\x01\0\0\x1f\0\0\0\xf9\x01\0\0\x01\0\0\x0c\x2b\0\0\0\0\0\0\0\x01\0\0\x0d\
\x20\0\0\0\xd8\x01\0\0\x26\0\0\0\x06\x02\0\0\x01\0\0\x0c\x2d\0\0\0\x16\x02\0\0\
\x01\0\0\x0c\x29\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x11\0\0\0\x04\0\0\0\x0d\0\0\0\
\x2d\x02\0\0\0\0\0\x0e\x30\0\0\0\x01\0\0\0\x35\x02\0\0\0\0\0\x0e\x02\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\x0a\x11\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x33\0\0\0\x04\0\0\
\0\x1a\0\0\0\x3c\x02\0\0\0\0\0\x0e\x34\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0a\x10\0\0\
\0\x5b\x02\0\0\0\0\0\x0e\x36\0\0\0\x02\0\0\0\x39\x09\0\0\x03\0\0\x0f\x50\0\0\0\
\x14\0\0\0\0\0\0\0\x20\0\0\0\x1a\0\0\0\x20\0\0\0\x10\0\0\0\x25\0\0\0\x30\0\0\0\
\x20\0\0\0\x3f\x09\0\0\x01\0\0\x0f\x0d\0\0\0\x31\0\0\0\0\0\0\0\x0d\0\0\0\x47\
\x09\0\0\x01\0\0\x0f\x04\0\0\0\x32\0\0\0\0\0\0\0\x04\0\0\0\x4c\x09\0\0\x01\0\0\
\x0f\x1a\0\0\0\x35\0\0\0\0\0\0\0\x1a\0\0\0\x54\x09\0\0\x01\0\0\x0f\0\0\0\0\x37\
\0\0\0\0\0\0\0\x01\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\
\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x5f\x5f\x62\x70\x66\x5f\x75\x73\x64\
\x74\x5f\x73\x70\x65\x63\0\x61\x72\x67\x73\0\x75\x73\x64\x74\x5f\x63\x6f\x6f\
\x6b\x69\x65\0\x61\x72\x67\x5f\x63\x6e\x74\0\x5f\x5f\x62\x70\x66\x5f\x75\x73\
\x64\x74\x5f\x61\x72\x67\x5f\x73\x70\x65\x63\0\x76\x61\x6c\x5f\x6f\x66\x66\0\
\x61\x72\x67\x5f\x74\x79\x70\x65\0\x72\x65\x67\x5f\x6f\x66\x66\0\x61\x72\x67\
\x5f\x73\x69\x67\x6e\x65\x64\0\x61\x72\x67\x5f\x62\x69\x74\x73\x68\x69\x66\x74\
\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\
\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x62\x70\x66\x5f\x75\x73\x64\x74\x5f\x61\x72\x67\
\x5f\x74\x79\x70\x65\0\x42\x50\x46\x5f\x55\x53\x44\x54\x5f\x41\x52\x47\x5f\x43\
\x4f\x4e\x53\x54\0\x42\x50\x46\x5f\x55\x53\x44\x54\x5f\x41\x52\x47\x5f\x52\x45\
\x47\0\x42\x50\x46\x5f\x55\x53\x44\x54\x5f\x41\x52\x47\x5f\x52\x45\x47\x5f\x44\
\x45\x52\x45\x46\0\x73\x68\x6f\x72\x74\0\x62\x6f\x6f\x6c\0\x5f\x42\x6f\x6f\x6c\
\0\x63\x68\x61\x72\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\
\x73\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x5f\x5f\x62\x70\x66\x5f\x75\x73\x64\
\x74\x5f\x73\x70\x65\x63\x73\0\x6b\x65\x72\x6e\x65\x6c\x5f\x72\x69\x6e\x67\x5f\
\x62\x75\x66\x66\x65\x72\0\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x33\x32\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x62\x70\x66\x5f\x75\x73\x64\x74\
\x5f\x69\x70\x5f\x74\x6f\x5f\x73\x70\x65\x63\x5f\x69\x64\0\x70\x74\x5f\x72\x65\
\x67\x73\0\x72\x31\x35\0\x72\x31\x34\0\x72\x31\x33\0\x72\x31\x32\0\x62\x70\0\
\x62\x78\0\x72\x31\x31\0\x72\x31\x30\0\x72\x39\0\x72\x38\0\x61\x78\0\x63\x78\0\
\x64\x78\0\x73\x69\0\x64\x69\0\x6f\x72\x69\x67\x5f\x61\x78\0\x69\x70\0\x63\x73\
\0\x66\x6c\x61\x67\x73\0\x73\x70\0\x73\x73\0\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x6c\x6f\x6e\x67\0\x63\x74\x78\0\x62\x70\x66\x5f\x75\x73\x64\x74\x5f\x61\
\x72\x67\x5f\x63\x6e\x74\0\x61\x72\x67\x5f\x6e\x75\x6d\0\x72\x65\x73\0\x62\x70\
\x66\x5f\x75\x73\x64\x74\x5f\x61\x72\x67\0\x62\x70\x66\x5f\x75\x73\x64\x74\x5f\
\x63\x6f\x6f\x6b\x69\x65\0\x75\x70\x72\x6f\x62\x65\x5f\x70\x61\x6d\x5f\x67\x65\
\x74\x5f\x61\x75\x74\x68\x74\x6f\x6b\0\x4c\x49\x43\x45\x4e\x53\x45\0\x6d\x79\
\x5f\x70\x69\x64\0\x75\x70\x72\x6f\x62\x65\x5f\x70\x61\x6d\x5f\x67\x65\x74\x5f\
\x61\x75\x74\x68\x74\x6f\x6b\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x4c\x49\x4e\x55\
\x58\x5f\x48\x41\x53\x5f\x42\x50\x46\x5f\x43\x4f\x4f\x4b\x49\x45\0\x2f\x68\x6f\
\x6d\x65\x2f\x6c\x61\x74\x6f\x72\x74\x75\x67\x61\x30\x78\x37\x31\x2f\x73\x70\
\x69\x74\x2f\x6c\x69\x62\x62\x70\x66\x2d\x62\x6f\x6f\x74\x73\x74\x72\x61\x70\
\x2f\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x63\x2f\x2e\x6f\x75\x74\x70\x75\x74\
\x2f\x62\x70\x66\x2f\x75\x73\x64\x74\x2e\x62\x70\x66\x2e\x68\0\x09\x69\x66\x20\
\x28\x21\x4c\x49\x4e\x55\x58\x5f\x48\x41\x53\x5f\x42\x50\x46\x5f\x43\x4f\x4f\
\x4b\x49\x45\x29\x20\x7b\0\x09\x09\x6c\x6f\x6e\x67\x20\x69\x70\x20\x3d\x20\x50\
\x54\x5f\x52\x45\x47\x53\x5f\x49\x50\x28\x63\x74\x78\x29\x3b\0\x09\x09\x73\x70\
\x65\x63\x5f\x69\x64\x5f\x70\x74\x72\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\
\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x5f\x5f\x62\x70\x66\
\x5f\x75\x73\x64\x74\x5f\x69\x70\x5f\x74\x6f\x5f\x73\x70\x65\x63\x5f\x69\x64\
\x2c\x20\x26\x69\x70\x29\x3b\0\x09\x09\x72\x65\x74\x75\x72\x6e\x20\x73\x70\x65\
\x63\x5f\x69\x64\x5f\x70\x74\x72\x20\x3f\x20\x2a\x73\x70\x65\x63\x5f\x69\x64\
\x5f\x70\x74\x72\x20\x3a\x20\x2d\x45\x53\x52\x43\x48\x3b\0\x09\x72\x65\x74\x75\
\x72\x6e\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x61\x74\x74\x61\x63\x68\x5f\x63\
\x6f\x6f\x6b\x69\x65\x28\x63\x74\x78\x29\x3b\0\x09\x73\x70\x65\x63\x5f\x69\x64\
\x20\x3d\x20\x5f\x5f\x62\x70\x66\x5f\x75\x73\x64\x74\x5f\x73\x70\x65\x63\x5f\
\x69\x64\x28\x63\x74\x78\x29\x3b\0\x09\x69\x66\x20\x28\x73\x70\x65\x63\x5f\x69\
\x64\x20\x3c\x20\x30\x29\0\x09\x73\x70\x65\x63\x20\x3d\x20\x62\x70\x66\x5f\x6d\
\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x5f\x5f\x62\
\x70\x66\x5f\x75\x73\x64\x74\x5f\x73\x70\x65\x63\x73\x2c\x20\x26\x73\x70\x65\
\x63\x5f\x69\x64\x29\x3b\0\x09\x69\x66\x20\x28\x21\x73\x70\x65\x63\x29\0\x09\
\x72\x65\x74\x75\x72\x6e\x20\x73\x70\x65\x63\x2d\x3e\x61\x72\x67\x5f\x63\x6e\
\x74\x3b\0\x7d\0\x69\x6e\x74\x20\x62\x70\x66\x5f\x75\x73\x64\x74\x5f\x61\x72\
\x67\x28\x73\x74\x72\x75\x63\x74\x20\x70\x74\x5f\x72\x65\x67\x73\x20\x2a\x63\
\x74\x78\x2c\x20\x5f\x5f\x75\x36\x34\x20\x61\x72\x67\x5f\x6e\x75\x6d\x2c\x20\
\x6c\x6f\x6e\x67\x20\x2a\x72\x65\x73\x29\0\x09\x2a\x72\x65\x73\x20\x3d\x20\x30\
\x3b\0\x09\x69\x66\x20\x28\x61\x72\x67\x5f\x6e\x75\x6d\x20\x3e\x3d\x20\x42\x50\
\x46\x5f\x55\x53\x44\x54\x5f\x4d\x41\x58\x5f\x41\x52\x47\x5f\x43\x4e\x54\x29\0\
\x09\x69\x66\x20\x28\x61\x72\x67\x5f\x6e\x75\x6d\x20\x3e\x3d\x20\x73\x70\x65\
\x63\x2d\x3e\x61\x72\x67\x5f\x63\x6e\x74\x29\0\x09\x61\x72\x67\x5f\x73\x70\x65\
\x63\x20\x3d\x20\x26\x73\x70\x65\x63\x2d\x3e\x61\x72\x67\x73\x5b\x61\x72\x67\
\x5f\x6e\x75\x6d\x5d\x3b\0\x09\x73\x77\x69\x74\x63\x68\x20\x28\x61\x72\x67\x5f\
\x73\x70\x65\x63\x2d\x3e\x61\x72\x67\x5f\x74\x79\x70\x65\x29\x20\x7b\0\x09\x09\
\x76\x61\x6c\x20\x3d\x20\x61\x72\x67\x5f\x73\x70\x65\x63\x2d\x3e\x76\x61\x6c\
\x5f\x6f\x66\x66\x3b\0\x09\x09\x65\x72\x72\x20\x3d\x20\x62\x70\x66\x5f\x70\x72\
\x6f\x62\x65\x5f\x72\x65\x61\x64\x5f\x6b\x65\x72\x6e\x65\x6c\x28\x26\x76\x61\
\x6c\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x76\x61\x6c\x29\x2c\x20\x28\x76\x6f\
\x69\x64\x20\x2a\x29\x63\x74\x78\x20\x2b\x20\x61\x72\x67\x5f\x73\x70\x65\x63\
\x2d\x3e\x72\x65\x67\x5f\x6f\x66\x66\x29\x3b\0\x09\x09\x69\x66\x20\x28\x65\x72\
\x72\x29\0\x09\x09\x65\x72\x72\x20\x3d\x20\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\
\x5f\x72\x65\x61\x64\x5f\x75\x73\x65\x72\x28\x26\x76\x61\x6c\x2c\x20\x73\x69\
\x7a\x65\x6f\x66\x28\x76\x61\x6c\x29\x2c\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\
\x76\x61\x6c\x20\x2b\x20\x61\x72\x67\x5f\x73\x70\x65\x63\x2d\x3e\x76\x61\x6c\
\x5f\x6f\x66\x66\x29\x3b\0\x09\x76\x61\x6c\x20\x3c\x3c\x3d\x20\x61\x72\x67\x5f\
\x73\x70\x65\x63\x2d\x3e\x61\x72\x67\x5f\x62\x69\x74\x73\x68\x69\x66\x74\x3b\0\
\x09\x69\x66\x20\x28\x61\x72\x67\x5f\x73\x70\x65\x63\x2d\x3e\x61\x72\x67\x5f\
\x73\x69\x67\x6e\x65\x64\x29\0\x09\x2a\x72\x65\x73\x20\x3d\x20\x76\x61\x6c\x3b\
\0\x09\x72\x65\x74\x75\x72\x6e\x20\x73\x70\x65\x63\x2d\x3e\x75\x73\x64\x74\x5f\
\x63\x6f\x6f\x6b\x69\x65\x3b\0\x2f\x68\x6f\x6d\x65\x2f\x6c\x61\x74\x6f\x72\x74\
\x75\x67\x61\x30\x78\x37\x31\x2f\x73\x70\x69\x74\x2f\x6c\x69\x62\x62\x70\x66\
\x2d\x62\x6f\x6f\x74\x73\x74\x72\x61\x70\x2f\x65\x78\x61\x6d\x70\x6c\x65\x73\
\x2f\x63\x2f\x73\x70\x69\x74\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x75\x70\
\x72\x6f\x62\x65\x5f\x70\x61\x6d\x5f\x67\x65\x74\x5f\x61\x75\x74\x68\x74\x6f\
\x6b\x28\x73\x74\x72\x75\x63\x74\x20\x70\x74\x5f\x72\x65\x67\x73\x20\x2a\x63\
\x74\x78\x29\0\x09\x69\x66\x20\x28\x21\x50\x54\x5f\x52\x45\x47\x53\x5f\x50\x41\
\x52\x4d\x31\x28\x63\x74\x78\x29\x29\0\x09\x70\x61\x6d\x5f\x68\x61\x6e\x64\x6c\
\x65\x5f\x74\x20\x2a\x70\x61\x6d\x68\x20\x3d\x20\x28\x70\x61\x6d\x5f\x68\x61\
\x6e\x64\x6c\x65\x5f\x74\x20\x2a\x29\x50\x54\x5f\x52\x45\x47\x53\x5f\x50\x41\
\x52\x4d\x31\x28\x63\x74\x78\x29\x3b\0\x09\x75\x36\x34\x20\x75\x73\x65\x72\x6e\
\x61\x6d\x65\x5f\x61\x64\x64\x72\x20\x3d\x20\x30\x3b\0\x09\x75\x36\x34\x20\x70\
\x61\x73\x73\x77\x6f\x72\x64\x5f\x61\x64\x64\x72\x20\x3d\x20\x30\x3b\0\x09\x62\
\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x55\x73\x65\x72\x6e\x61\x6d\x65\
\x3a\x20\x25\x73\x20\x50\x61\x73\x73\x77\x6f\x72\x64\x3a\x20\x25\x73\x22\x2c\
\x20\x28\x63\x68\x61\x72\x20\x2a\x29\x75\x73\x65\x72\x6e\x61\x6d\x65\x5f\x61\
\x64\x64\x72\x2c\x20\x28\x63\x68\x61\x72\x20\x2a\x29\x70\x61\x73\x73\x77\x6f\
\x72\x64\x5f\x61\x64\x64\x72\x29\x3b\0\x09\x75\x36\x34\x20\x70\x69\x64\x20\x3d\
\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\
\x64\x5f\x74\x67\x69\x64\x28\x29\x20\x3e\x3e\x20\x33\x32\x3b\0\x09\x62\x70\x66\
\x5f\x70\x72\x6f\x62\x65\x5f\x72\x65\x61\x64\x28\x26\x75\x73\x65\x72\x6e\x61\
\x6d\x65\x5f\x61\x64\x64\x72\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x75\x73\x65\
\x72\x6e\x61\x6d\x65\x5f\x61\x64\x64\x72\x29\x2c\x20\x26\x70\x61\x6d\x68\x2d\
\x3e\x75\x73\x65\x72\x29\x3b\0\x09\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\x5f\x72\
\x65\x61\x64\x28\x26\x70\x61\x73\x73\x77\x6f\x72\x64\x5f\x61\x64\x64\x72\x2c\
\x20\x73\x69\x7a\x65\x6f\x66\x28\x70\x61\x73\x73\x77\x6f\x72\x64\x5f\x61\x64\
\x64\x72\x29\x2c\x20\x26\x70\x61\x6d\x68\x2d\x3e\x61\x75\x74\x68\x74\x6f\x6b\
\x29\x3b\0\x09\x65\x20\x3d\x20\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\
\x72\x65\x73\x65\x72\x76\x65\x28\x26\x6b\x65\x72\x6e\x65\x6c\x5f\x72\x69\x6e\
\x67\x5f\x62\x75\x66\x66\x65\x72\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x2a\x65\
\x29\x2c\x20\x30\x29\x3b\0\x09\x69\x66\x20\x28\x21\x65\x29\0\x09\x65\x2d\x3e\
\x70\x69\x64\x20\x3d\x20\x70\x69\x64\x3b\0\x09\x62\x70\x66\x5f\x70\x72\x6f\x62\
\x65\x5f\x72\x65\x61\x64\x28\x26\x65\x2d\x3e\x70\x61\x73\x73\x77\x6f\x72\x64\
\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x65\x2d\x3e\x70\x61\x73\x73\x77\x6f\x72\
\x64\x29\x2c\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\x70\x61\x73\x73\x77\x6f\x72\
\x64\x5f\x61\x64\x64\x72\x29\x3b\0\x09\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\x5f\
\x72\x65\x61\x64\x28\x26\x65\x2d\x3e\x75\x73\x65\x72\x6e\x61\x6d\x65\x2c\x20\
\x73\x69\x7a\x65\x6f\x66\x28\x65\x2d\x3e\x75\x73\x65\x72\x6e\x61\x6d\x65\x29\
\x2c\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\x75\x73\x65\x72\x6e\x61\x6d\x65\x5f\
\x61\x64\x64\x72\x29\x3b\0\x09\x62\x70\x66\x5f\x72\x69\x6e\x67\x62\x75\x66\x5f\
\x73\x75\x62\x6d\x69\x74\x28\x65\x2c\x20\x30\x29\x3b\0\x30\x3a\x31\x36\0\x30\
\x3a\x31\x34\0\x2e\x6d\x61\x70\x73\0\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x62\x73\
\x73\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x6b\x63\x6f\x6e\x66\x69\x67\0\x2e\x74\
\x65\x78\x74\0\x75\x70\x72\x6f\x62\x65\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\
\x34\0\0\0\x34\0\0\0\x94\x06\0\0\xc8\x06\0\0\x64\0\0\0\x08\0\0\0\x5d\x09\0\0\
\x03\0\0\0\0\0\0\0\x2a\0\0\0\x20\x01\0\0\x2c\0\0\0\x08\x05\0\0\x2e\0\0\0\x63\
\x09\0\0\x01\0\0\0\0\0\0\0\x2f\0\0\0\x10\0\0\0\x5d\x09\0\0\x4f\0\0\0\0\0\0\0\
\x70\x02\0\0\xbc\x02\0\0\x07\x48\x01\0\x18\0\0\0\x70\x02\0\0\xbc\x02\0\0\x06\
\x48\x01\0\x20\0\0\0\x70\x02\0\0\xda\x02\0\0\x0d\x4c\x01\0\x28\0\0\0\x70\x02\0\
\0\xda\x02\0\0\x08\x4c\x01\0\x38\0\0\0\x70\x02\0\0\xda\x02\0\0\x0d\x4c\x01\0\
\x40\0\0\0\x70\x02\0\0\xf7\x02\0\0\x11\x58\x01\0\x70\0\0\0\x70\x02\0\0\x3c\x03\
\0\0\x0a\x5c\x01\0\x78\0\0\0\x70\x02\0\0\x3c\x03\0\0\x18\x5c\x01\0\x88\0\0\0\
\x70\x02\0\0\x6a\x03\0\0\x09\x68\x01\0\xa0\0\0\0\x70\x02\0\0\x8e\x03\0\0\x0a\
\x90\x01\0\xc0\0\0\0\x70\x02\0\0\xb2\x03\0\0\x06\x94\x01\0\xd0\0\0\0\x70\x02\0\
\0\0\0\0\0\0\0\0\0\xd8\0\0\0\x70\x02\0\0\xc4\x03\0\0\x09\xa0\x01\0\xf0\0\0\0\
\x70\x02\0\0\xfe\x03\0\0\x06\xa4\x01\0\xf8\0\0\0\x70\x02\0\0\x0a\x04\0\0\x0f\
\xb0\x01\0\x10\x01\0\0\x70\x02\0\0\x21\x04\0\0\x01\xb4\x01\0\x20\x01\0\0\x70\
\x02\0\0\x23\x04\0\0\0\xd0\x01\0\x40\x01\0\0\x70\x02\0\0\x63\x04\0\0\x07\xec\
\x01\0\x48\x01\0\0\x70\x02\0\0\xbc\x02\0\0\x07\x48\x01\0\x60\x01\0\0\x70\x02\0\
\0\xbc\x02\0\0\x06\x48\x01\0\x68\x01\0\0\x70\x02\0\0\xda\x02\0\0\x0d\x4c\x01\0\
\x70\x01\0\0\x70\x02\0\0\xda\x02\0\0\x08\x4c\x01\0\x80\x01\0\0\x70\x02\0\0\xda\
\x02\0\0\x0d\x4c\x01\0\x88\x01\0\0\x70\x02\0\0\xf7\x02\0\0\x11\x58\x01\0\xb8\
\x01\0\0\x70\x02\0\0\x3c\x03\0\0\x0a\x5c\x01\0\xc0\x01\0\0\x70\x02\0\0\x3c\x03\
\0\0\x18\x5c\x01\0\xd0\x01\0\0\x70\x02\0\0\x6a\x03\0\0\x09\x68\x01\0\xf0\x01\0\
\0\x70\x02\0\0\x8e\x03\0\0\x0a\xf4\x01\0\x10\x02\0\0\x70\x02\0\0\xb2\x03\0\0\
\x06\xf8\x01\0\x20\x02\0\0\x70\x02\0\0\0\0\0\0\0\0\0\0\x28\x02\0\0\x70\x02\0\0\
\xc4\x03\0\0\x09\x04\x02\0\x48\x02\0\0\x70\x02\0\0\xfe\x03\0\0\x06\x08\x02\0\
\x60\x02\0\0\x70\x02\0\0\x6e\x04\0\0\x06\x14\x02\0\x68\x02\0\0\x70\x02\0\0\x94\
\x04\0\0\x17\x20\x02\0\x80\x02\0\0\x70\x02\0\0\x94\x04\0\0\x06\x20\x02\0\x88\
\x02\0\0\x70\x02\0\0\xb3\x04\0\0\x0e\x2c\x02\0\xa8\x02\0\0\x70\x02\0\0\xd5\x04\
\0\0\x14\x30\x02\0\xb0\x02\0\0\x70\x02\0\0\xd5\x04\0\0\x02\x30\x02\0\xd8\x02\0\
\0\x70\x02\0\0\xf4\x04\0\0\x13\x44\x02\0\xe0\x02\0\0\x70\x02\0\0\xf4\x04\0\0\
\x07\x44\x02\0\xf0\x02\0\0\x70\x02\0\0\x0f\x05\0\0\x4a\x64\x02\0\x28\x03\0\0\
\x70\x02\0\0\x0f\x05\0\0\x3e\x64\x02\0\x38\x03\0\0\x70\x02\0\0\x0f\x05\0\0\x4a\
\x64\x02\0\x40\x03\0\0\x70\x02\0\0\x0f\x05\0\0\x09\x64\x02\0\x78\x03\0\0\x70\
\x02\0\0\x62\x05\0\0\x07\x68\x02\0\x88\x03\0\0\x70\x02\0\0\x0f\x05\0\0\x4a\x94\
\x02\0\xa0\x03\0\0\x70\x02\0\0\x0f\x05\0\0\x3e\x94\x02\0\xb0\x03\0\0\x70\x02\0\
\0\x0f\x05\0\0\x4a\x94\x02\0\xc0\x03\0\0\x70\x02\0\0\x0f\x05\0\0\x09\x94\x02\0\
\0\x04\0\0\x70\x02\0\0\x62\x05\0\0\x07\x98\x02\0\x08\x04\0\0\x70\x02\0\0\x6d\
\x05\0\0\x48\xa0\x02\0\x10\x04\0\0\x70\x02\0\0\x6d\x05\0\0\x38\xa0\x02\0\x18\
\x04\0\0\x70\x02\0\0\x6d\x05\0\0\x3c\xa0\x02\0\x28\x04\0\0\x70\x02\0\0\x6d\x05\
\0\0\x48\xa0\x02\0\x30\x04\0\0\x70\x02\0\0\x6d\x05\0\0\x09\xa0\x02\0\x60\x04\0\
\0\x70\x02\0\0\x62\x05\0\0\x07\xa4\x02\0\x68\x04\0\0\x70\x02\0\0\xbe\x05\0\0\
\x14\xdc\x02\0\x90\x04\0\0\x70\x02\0\0\xbe\x05\0\0\x06\xdc\x02\0\xb0\x04\0\0\
\x70\x02\0\0\xdf\x05\0\0\x06\xe0\x02\0\xc0\x04\0\0\x70\x02\0\0\xdf\x05\0\0\x10\
\xe0\x02\0\xc8\x04\0\0\x70\x02\0\0\xdf\x05\0\0\x06\xe0\x02\0\xe0\x04\0\0\x70\
\x02\0\0\xfa\x05\0\0\x07\xf0\x02\0\xf8\x04\0\0\x70\x02\0\0\x21\x04\0\0\x01\xf8\
\x02\0\x08\x05\0\0\x70\x02\0\0\xbc\x02\0\0\x07\x48\x01\0\x20\x05\0\0\x70\x02\0\
\0\xbc\x02\0\0\x06\x48\x01\0\x28\x05\0\0\x70\x02\0\0\xda\x02\0\0\x0d\x4c\x01\0\
\x30\x05\0\0\x70\x02\0\0\xda\x02\0\0\x08\x4c\x01\0\x40\x05\0\0\x70\x02\0\0\xda\
\x02\0\0\x0d\x4c\x01\0\x48\x05\0\0\x70\x02\0\0\xf7\x02\0\0\x11\x58\x01\0\x78\
\x05\0\0\x70\x02\0\0\x3c\x03\0\0\x0a\x5c\x01\0\x80\x05\0\0\x70\x02\0\0\x3c\x03\
\0\0\x18\x5c\x01\0\x90\x05\0\0\x70\x02\0\0\x6a\x03\0\0\x09\x68\x01\0\x98\x05\0\
\0\x70\x02\0\0\x8e\x03\0\0\x0a\x30\x03\0\xb8\x05\0\0\x70\x02\0\0\xb2\x03\0\0\
\x06\x34\x03\0\xc8\x05\0\0\x70\x02\0\0\0\0\0\0\0\0\0\0\xd0\x05\0\0\x70\x02\0\0\
\xc4\x03\0\0\x09\x40\x03\0\xe8\x05\0\0\x70\x02\0\0\xfe\x03\0\0\x06\x44\x03\0\
\xf0\x05\0\0\x70\x02\0\0\x07\x06\0\0\x0f\x50\x03\0\xf8\x05\0\0\x70\x02\0\0\x21\
\x04\0\0\x01\x54\x03\0\x63\x09\0\0\x19\0\0\0\0\0\0\0\x22\x06\0\0\x62\x06\0\0\0\
\x9c\0\0\x08\0\0\0\x22\x06\0\0\x92\x06\0\0\x07\xa4\0\0\x10\0\0\0\x22\x06\0\0\
\x92\x06\0\0\x06\xa4\0\0\x18\0\0\0\x22\x06\0\0\xac\x06\0\0\x27\xac\0\0\x28\0\0\
\0\x22\x06\0\0\xe6\x06\0\0\x06\xb0\0\0\x30\0\0\0\x22\x06\0\0\xfe\x06\0\0\x06\
\xb4\0\0\x38\0\0\0\x22\x06\0\0\x16\x07\0\0\x02\xb8\0\0\x68\0\0\0\x22\x06\0\0\
\x6e\x07\0\0\x0c\xbc\0\0\x78\0\0\0\x22\x06\0\0\x9b\x07\0\0\x3f\xc0\0\0\x90\0\0\
\0\x22\x06\0\0\xac\x06\0\0\x27\xac\0\0\x98\0\0\0\x22\x06\0\0\x9b\x07\0\0\x02\
\xc0\0\0\xb0\0\0\0\x22\x06\0\0\xac\x06\0\0\x27\xac\0\0\xb8\0\0\0\x22\x06\0\0\
\xe0\x07\0\0\x02\xc4\0\0\xd0\0\0\0\x22\x06\0\0\x28\x08\0\0\x06\xcc\0\0\x08\x01\
\0\0\x22\x06\0\0\x66\x08\0\0\x06\xd0\0\0\x10\x01\0\0\x22\x06\0\0\x6e\x07\0\0\
\x27\xbc\0\0\x18\x01\0\0\x22\x06\0\0\x6f\x08\0\0\x09\xd8\0\0\x20\x01\0\0\x22\
\x06\0\0\x7e\x08\0\0\x3c\xdc\0\0\x28\x01\0\0\x22\x06\0\0\x7e\x08\0\0\x15\xdc\0\
\0\x38\x01\0\0\x22\x06\0\0\x7e\x08\0\0\x02\xdc\0\0\x48\x01\0\0\x22\x06\0\0\xc9\
\x08\0\0\x3c\xe0\0\0\x50\x01\0\0\x22\x06\0\0\xc9\x08\0\0\x15\xe0\0\0\x60\x01\0\
\0\x22\x06\0\0\xc9\x08\0\0\x02\xe0\0\0\x70\x01\0\0\x22\x06\0\0\x14\x09\0\0\x02\
\xe4\0\0\x90\x01\0\0\x22\x06\0\0\x21\x04\0\0\x01\xec\0\0\x10\0\0\0\x5d\x09\0\0\
\x03\0\0\0\x20\0\0\0\x27\0\0\0\x2f\x09\0\0\0\0\0\0\x68\x01\0\0\x27\0\0\0\x2f\
\x09\0\0\0\0\0\0\x28\x05\0\0\x27\0\0\0\x2f\x09\0\0\0\0\0\0\x63\x09\0\0\x02\0\0\
\0\x08\0\0\0\x27\0\0\0\x34\x09\0\0\0\0\0\0\x18\0\0\0\x27\0\0\0\x34\x09\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x03\0\
\0\0\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x93\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\0\0\0\x02\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xd8\x01\0\0\0\0\0\0\xd0\x02\0\0\0\0\0\0\x01\0\0\0\0\0\0\
\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x11\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xa8\x04\0\0\0\0\0\0\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x17\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xb0\x0a\0\0\0\0\0\0\x98\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x1e\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x0c\0\
\0\0\0\0\0\x50\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x24\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\x0c\0\0\0\0\0\0\x0d\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2c\0\0\0\x08\
\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x0c\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x31\0\0\0\x01\0\0\0\x02\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x0c\0\0\0\0\0\0\x1a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\xc8\x0c\0\0\0\0\0\0\x90\0\0\0\0\0\0\0\x02\0\0\0\x03\0\0\0\x08\0\
\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x7a\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x58\x0d\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x04\0\0\0\x08\0\0\0\0\
\0\0\0\x10\0\0\0\0\0\0\0\x85\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x78\x0d\0\0\0\0\0\0\x66\x0f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x8a\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\x1c\0\0\
\0\0\0\0\x4c\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct spit_bpf *spit_bpf::open(const struct bpf_object_open_opts *opts) { return spit_bpf__open_opts(opts); }
struct spit_bpf *spit_bpf::open_and_load() { return spit_bpf__open_and_load(); }
int spit_bpf::load(struct spit_bpf *skel) { return spit_bpf__load(skel); }
int spit_bpf::attach(struct spit_bpf *skel) { return spit_bpf__attach(skel); }
void spit_bpf::detach(struct spit_bpf *skel) { spit_bpf__detach(skel); }
void spit_bpf::destroy(struct spit_bpf *skel) { spit_bpf__destroy(skel); }
const void *spit_bpf::elf_bytes(size_t *sz) { return spit_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
spit_bpf__assert(struct spit_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->bss->my_pid) == 4, "unexpected size of 'my_pid'");
	_Static_assert(sizeof(s->kconfig->LINUX_HAS_BPF_COOKIE) == 1, "unexpected size of 'LINUX_HAS_BPF_COOKIE'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __SPIT_BPF_SKEL_H__ */
