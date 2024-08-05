/*
 * Based on execlog
 * Copyright (C) 2021, Alexandre Iooss <erdnaxe@crans.org>
 * Copyright (C) 2024, Daniel Palmer <daniel@thingy.jp>
 *
 * Log instruction execution with memory access.
 * Trap when shit goes wrong!
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <typedefs.h>
#include <qemu-plugin.h>

//#include <addr2line.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* File to log to */
static FILE *fp;
static const char *file_name = "tcgmmu.json";

/* For symbol look up */
static const char *kernel_elf = "linux/vmlinux";

/* Store last executed instruction on each vCPU as a GString */
static GPtrArray *last_exec;
static GRWLock expand_array_lock;

static Dwarf_Debug dwfdbg;

static void flush_buffer(GString *s)
{
    if (s->len) {
        fwrite(s->str, 1, s->len, fp);
        fputs("\n", fp);
    }
}

/*
 * Expand last_exec array.
 *
 * As we could have multiple threads trying to do this we need to
 * serialise the expansion under a lock.
 */
static void expand_last_exec(int cpu_index)
{
    g_rw_lock_writer_lock(&expand_array_lock);
    while (cpu_index >= last_exec->len) {
        GString *s = g_string_new(NULL);
        g_ptr_array_add(last_exec, s);
    }
    g_rw_lock_writer_unlock(&expand_array_lock);
}

/**
 * Add memory read or write information to current instruction log
 */
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata)
{
    GString *s;

    /* Find vCPU in array */
    g_rw_lock_reader_lock(&expand_array_lock);
    g_assert(cpu_index < last_exec->len);
    s = g_ptr_array_index(last_exec, cpu_index);
    g_rw_lock_reader_unlock(&expand_array_lock);

    /* Indicate type of memory access */
    if (qemu_plugin_mem_is_store(info)) {
        g_string_append(s, ", store");
    } else {
        g_string_append(s, ", load");
    }

    /* If full system emulation log physical address and device name */
    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
        const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
        g_string_append_printf(s, ", 0x%08"PRIx64", %s", addr, name);
    } else {
        g_string_append_printf(s, ", 0x%08"PRIx64, vaddr);
    }
}

/**
 * Log instruction execution
 */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    GString *s;

    /* Find or create vCPU in array */
    g_rw_lock_reader_lock(&expand_array_lock);
    if (cpu_index >= last_exec->len) {
        g_rw_lock_reader_unlock(&expand_array_lock);
        expand_last_exec(cpu_index);
        g_rw_lock_reader_lock(&expand_array_lock);
    }
    s = g_ptr_array_index(last_exec, cpu_index);
    g_rw_lock_reader_unlock(&expand_array_lock);

    /* Print previous instruction in cache */
    flush_buffer(s);

    /* Store new instruction in cache */
    /* vcpu_mem will add memory access information to last_exec */
    g_string_printf(s, "%u, ", cpu_index);
    g_string_append(s, (char *)udata);
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;

    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        char *insn_disas;
        uint64_t insn_vaddr;

        /*
         * `insn` is shared between translations in QEMU, copy needed data here.
         * `output` is never freed as it might be used multiple times during
         * the emulation lifetime.
         * We only consider the first 32 bits of the instruction, this may be
         * a limitation for CISC architectures.
         */
        insn = qemu_plugin_tb_get_insn(tb, i);
        insn_disas = qemu_plugin_insn_disas(insn);
        insn_vaddr = qemu_plugin_insn_vaddr(insn);

	uint32_t insn_opcode;
	insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));

	//if (insn_vaddr != 0)
	//	lookup_pc(&dwfdbg, 0, insn_vaddr);

	char *output = g_strdup_printf("0x%"PRIx64", 0x%"PRIx32", \"%s\"",
					insn_vaddr, insn_opcode, insn_disas);

	/* Register callback on memory read or write */
	qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
					QEMU_PLUGIN_CB_NO_REGS,
					QEMU_PLUGIN_MEM_RW, NULL);

	/* Register callback on instruction */
	qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
						QEMU_PLUGIN_CB_NO_REGS, output);
    }
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    guint i;
    GString *s;
    for (i = 0; i < last_exec->len; i++) {
        s = g_ptr_array_index(last_exec, i);
        flush_buffer(s);
    }

    fclose(fp);
}

void err_handler(Dwarf_Error err, Dwarf_Ptr errarg)
{

}

void fail_exit(const char *msg)
{

}

static int plugin_init(void)
{
    fp = fopen(file_name, "wb");
    if (!fp)
        return -1;

    //int ret = dwarf_addr2line_init_path(kernel_elf, &dwfdbg, err_handler, fail_exit);
    //if (ret) {
    //	printf("dang! %d\n", ret);
    //	return -1;
    //}

    return 0;
}

/**
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
	int ret;

    /*
     * Initialize dynamic array to cache vCPU instruction. In user mode
     * we don't know the size before emulation.
     */
    if (info->system_emulation) {
        last_exec = g_ptr_array_sized_new(info->system.max_vcpus);
    } else {
        last_exec = g_ptr_array_new();
    }

    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "filename") == 0) {
                      file_name = g_strdup(tokens[1]);
        } else if (g_strcmp0(tokens[0], "kernel_elf") == 0) {
                      kernel_elf = g_strdup(tokens[1]);
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    ret = plugin_init();
    if (ret)
    	return ret;

    /* Register translation block and exit callbacks */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
