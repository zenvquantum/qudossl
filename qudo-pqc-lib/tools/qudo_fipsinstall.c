/* SPDX-License-Identifier: Apache-2.0 AND MIT */

#include "qudo_fips_hmac.h"
#include "qudo_fipskey.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZE     4096
#define MAX_MD_SIZE 64

static int quiet = 0;

static void fips_cleanse(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
        *p++ = 0;
}

static char *fips_buf2hexstr(const unsigned char *buf, size_t len)
{
    size_t i;
    char *hex = (char *)malloc(len * 3);
    if (hex == NULL)
        return NULL;
    for (i = 0; i < len; i++) {
        sprintf(hex + i * 3, "%02X%s", buf[i], (i < len - 1) ? ":" : "");
    }
    return hex;
}

static unsigned char *fips_hexstr2buf(const char *hex, size_t *out_len)
{
    size_t nbytes = 0;
    const char *p;
    unsigned char *buf, *out;
    unsigned int val;

    for (p = hex; *p; p++) {
        if (*p != ':')
            nbytes++;
    }
    if (nbytes == 0 || (nbytes % 2) != 0)
        return NULL;
    nbytes /= 2;

    buf = (unsigned char *)malloc(nbytes);
    if (buf == NULL)
        return NULL;

    out = buf;
    p = hex;
    while (*p) {
        if (*p == ':') {
            p++;
            continue;
        }
        if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1])
            || sscanf(p, "%2x", &val) != 1) {
            free(buf);
            return NULL;
        }
        *out++ = (unsigned char)val;
        p += 2;
    }
    *out_len = nbytes;
    return buf;
}

static int compute_file_hmac(const char *filename, unsigned char *out,
                             size_t *out_len)
{
    int ret = 0;
    FILE *fp = NULL;
    unsigned char buf[BUFSIZE];
    unsigned char key[32] = {QUDO_FIPS_KEY_ELEMENTS};
    size_t bytes_read;
    qudo_fips_hmac_ctx_t ctx;

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error: cannot open file '%s'\n", filename);
        goto err;
    }

    qudo_fips_hmac_init(&ctx, key, sizeof(key));

    while ((bytes_read = fread(buf, 1, sizeof(buf), fp)) > 0) {
        qudo_fips_hmac_update(&ctx, buf, bytes_read);
    }
    if (ferror(fp)) {
        fprintf(stderr, "Error: reading file '%s'\n", filename);
        goto err;
    }

    qudo_fips_hmac_final(&ctx, out);
    *out_len = 32;

    ret = 1;
err:
    fips_cleanse(key, sizeof(key));
    fips_cleanse(buf, sizeof(buf));
    fips_cleanse(&ctx, sizeof(ctx));
    if (fp != NULL)
        fclose(fp);
    return ret;
}

static int write_config(const char *outfile, const char *section,
                        const unsigned char *module_mac, size_t module_mac_len,
                        const unsigned char *library_mac,
                        size_t library_mac_len, const char *module_path,
                        const char *library_path)
{
    int ret = 0;
    FILE *fp = NULL;
    char *module_hex = NULL;
    char *library_hex = NULL;

    module_hex = fips_buf2hexstr(module_mac, module_mac_len);
    if (module_hex == NULL) {
        fprintf(stderr, "Error: hex encoding module MAC\n");
        goto err;
    }

    if (library_path != NULL) {
        library_hex = fips_buf2hexstr(library_mac, library_mac_len);
        if (library_hex == NULL) {
            fprintf(stderr, "Error: hex encoding library MAC\n");
            goto err;
        }
    }

    fp = fopen(outfile, "w");
    if (fp == NULL) {
        fprintf(stderr, "Error: cannot open output file '%s'\n", outfile);
        goto err;
    }

    fprintf(fp, "[%s]\n", section);
    fprintf(fp, "activate = 1\n");
    fprintf(fp, "conditional-errors = 1\n");
    fprintf(fp, "module = %s\n", module_path);
    fprintf(fp, "module-mac = %s\n", module_hex);
    if (library_path != NULL) {
        fprintf(fp, "library-mac = %s\n", library_hex);
        fprintf(fp, "library-path = %s\n", library_path);
    }

    if (!quiet)
        printf("QUDO FIPS config written to %s\n", outfile);

    ret = 1;
err:
    free(module_hex);
    free(library_hex);
    if (fp != NULL)
        fclose(fp);
    return ret;
}

static char *read_config_value(const char *filename, const char *section,
                               const char *key)
{
    FILE *fp;
    char line[4096];
    int in_section = 0;
    char section_header[256];
    char *result = NULL;

    fp = fopen(filename, "r");
    if (fp == NULL)
        return NULL;

    snprintf(section_header, sizeof(section_header), "[%s]", section);

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        if (line[0] == '[') {
            in_section = (strcmp(line, section_header) == 0);
            continue;
        }

        if (!in_section)
            continue;

        char *eq = strchr(line, '=');
        if (eq == NULL)
            continue;

        *eq = '\0';
        char *k = line;
        while (*k == ' ' || *k == '\t')
            k++;
        char *ke = eq - 1;
        while (ke > k && (*ke == ' ' || *ke == '\t'))
            *ke-- = '\0';

        if (strcmp(k, key) != 0)
            continue;

        char *v = eq + 1;
        while (*v == ' ' || *v == '\t')
            v++;

        result = strdup(v);
        break;
    }

    fclose(fp);
    return result;
}

static int do_verify(const char *module_path, const char *library_path,
                     const char *config_file, const char *section)
{
    int ret = 0;
    unsigned char module_mac[MAX_MD_SIZE], library_mac[MAX_MD_SIZE];
    size_t module_mac_len = 0, library_mac_len = 0;
    char *expected_module_hex = NULL;
    char *expected_library_hex = NULL;
    unsigned char *expected_module = NULL;
    unsigned char *expected_library = NULL;
    size_t exp_mod_len = 0, exp_lib_len = 0;
    char *computed_module_hex = NULL;
    char *computed_library_hex = NULL;

    expected_module_hex = read_config_value(config_file, section, "module-mac");
    if (expected_module_hex == NULL) {
        fprintf(stderr, "Error: 'module-mac' not found in [%s]\n", section);
        goto err;
    }

    expected_module = fips_hexstr2buf(expected_module_hex, &exp_mod_len);
    if (expected_module == NULL) {
        fprintf(stderr, "Error: malformed hex in module-mac\n");
        goto err;
    }

    if (!compute_file_hmac(module_path, module_mac, &module_mac_len))
        goto err;

    if ((size_t)exp_mod_len != module_mac_len
        || memcmp(expected_module, module_mac, module_mac_len) != 0) {
        computed_module_hex = fips_buf2hexstr(module_mac, module_mac_len);
        fprintf(stderr, "VERIFY FAILED: module-mac mismatch\n");
        fprintf(stderr, "  Expected: %s\n", expected_module_hex);
        fprintf(stderr, "  Computed: %s\n",
                computed_module_hex ? computed_module_hex : "(null)");
        goto err;
    }

    expected_library_hex
        = read_config_value(config_file, section, "library-mac");
    if (expected_library_hex != NULL) {
        if (library_path == NULL) {
            fprintf(
                stderr,
                "Error: config has 'library-mac' but -library not provided\n");
            goto err;
        }

        expected_library = fips_hexstr2buf(expected_library_hex, &exp_lib_len);
        if (expected_library == NULL) {
            fprintf(stderr, "Error: malformed hex in library-mac\n");
            goto err;
        }

        if (!compute_file_hmac(library_path, library_mac, &library_mac_len))
            goto err;

        if ((size_t)exp_lib_len != library_mac_len
            || memcmp(expected_library, library_mac, library_mac_len) != 0) {
            computed_library_hex
                = fips_buf2hexstr(library_mac, library_mac_len);
            fprintf(stderr, "VERIFY FAILED: library-mac mismatch\n");
            fprintf(stderr, "  Expected: %s\n", expected_library_hex);
            fprintf(stderr, "  Computed: %s\n",
                    computed_library_hex ? computed_library_hex : "(null)");
            goto err;
        }
    }

    if (!quiet)
        printf("VERIFY PASSED\n");
    ret = 1;

err:
    fips_cleanse(module_mac, sizeof(module_mac));
    fips_cleanse(library_mac, sizeof(library_mac));
    free(expected_module_hex);
    free(expected_library_hex);
    free(expected_module);
    free(expected_library);
    free(computed_module_hex);
    free(computed_library_hex);
    return ret;
}

typedef struct {
    uint64_t vaddr;
    uint64_t file_offset;
    uint64_t size;
    int found;
} fips_sym_info_t;

#define QELF_MAGIC \
    "\x7f"         \
    "ELF"
#define QELF_CLASS64      2
#define QELF_SHT_SYMTAB   2
#define QELF_SHT_DYNSYM   11
#define QELF_SHT_PROGBITS 1
#define QELF_SHT_NOBITS   8
#define QELF_SHN_UNDEF    0
#define QELF_SHN_ABS      0xFFF1

#pragma pack(push, 1)
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} qelf64_ehdr_t;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} qelf64_shdr_t;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} qelf64_sym_t;
#pragma pack(pop)

static int elf64_lookup_symbols(FILE *fp, const char **sym_names,
                                fips_sym_info_t *sym_info, int num_syms)
{
    qelf64_ehdr_t ehdr;
    qelf64_shdr_t *shdrs = NULL;
    int found_count = 0;
    int i;
    uint16_t si;

    for (i = 0; i < num_syms; i++)
        sym_info[i].found = 0;

    fseek(fp, 0, SEEK_SET);
    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1)
        return 0;

    if (memcmp(ehdr.e_ident, QELF_MAGIC, 4) != 0
        || ehdr.e_ident[4] != QELF_CLASS64)
        return 0;

    if (ehdr.e_shnum == 0 || ehdr.e_shoff == 0)
        return 0;

    shdrs = (qelf64_shdr_t *)malloc(ehdr.e_shnum * sizeof(qelf64_shdr_t));
    if (shdrs == NULL)
        return 0;

    fseek(fp, (long)ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, sizeof(qelf64_shdr_t), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        free(shdrs);
        return 0;
    }

    for (si = 0; si < ehdr.e_shnum && found_count < num_syms; si++) {
        qelf64_shdr_t *symtab_sh = &shdrs[si];
        qelf64_shdr_t *strtab_sh;
        char *strtab = NULL;
        qelf64_sym_t *syms = NULL;
        uint64_t num_entries, j;

        if (symtab_sh->sh_type != QELF_SHT_SYMTAB
            && symtab_sh->sh_type != QELF_SHT_DYNSYM)
            continue;

        if (symtab_sh->sh_link >= ehdr.e_shnum || symtab_sh->sh_entsize == 0)
            continue;
        strtab_sh = &shdrs[symtab_sh->sh_link];

        strtab = (char *)malloc((size_t)strtab_sh->sh_size);
        if (strtab == NULL)
            continue;
        fseek(fp, (long)strtab_sh->sh_offset, SEEK_SET);
        if (fread(strtab, 1, (size_t)strtab_sh->sh_size, fp)
            != (size_t)strtab_sh->sh_size) {
            free(strtab);
            continue;
        }

        num_entries = symtab_sh->sh_size / symtab_sh->sh_entsize;
        syms = (qelf64_sym_t *)malloc(
            (size_t)(num_entries * sizeof(qelf64_sym_t)));
        if (syms == NULL) {
            free(strtab);
            continue;
        }
        fseek(fp, (long)symtab_sh->sh_offset, SEEK_SET);
        if (fread(syms, sizeof(qelf64_sym_t), (size_t)num_entries, fp)
            != (size_t)num_entries) {
            free(syms);
            free(strtab);
            continue;
        }

        for (j = 0; j < num_entries && found_count < num_syms; j++) {
            const char *name;
            if (syms[j].st_name >= strtab_sh->sh_size)
                continue;
            name = strtab + syms[j].st_name;

            for (i = 0; i < num_syms; i++) {
                if (sym_info[i].found || strcmp(name, sym_names[i]) != 0)
                    continue;

                sym_info[i].vaddr = syms[j].st_value;
                sym_info[i].size = syms[j].st_size;

                if (syms[j].st_shndx < ehdr.e_shnum
                    && syms[j].st_shndx != QELF_SHN_UNDEF
                    && syms[j].st_shndx != QELF_SHN_ABS) {
                    qelf64_shdr_t *sec = &shdrs[syms[j].st_shndx];
                    sym_info[i].file_offset
                        = sec->sh_offset + (syms[j].st_value - sec->sh_addr);
                } else {
                    uint16_t k;
                    sym_info[i].file_offset = 0;
                    for (k = 0; k < ehdr.e_shnum; k++) {
                        if ((shdrs[k].sh_type == QELF_SHT_PROGBITS
                             || shdrs[k].sh_type == QELF_SHT_NOBITS)
                            && syms[j].st_value >= shdrs[k].sh_addr
                            && syms[j].st_value
                                   < shdrs[k].sh_addr + shdrs[k].sh_size) {
                            sym_info[i].file_offset
                                = shdrs[k].sh_offset
                                  + (syms[j].st_value - shdrs[k].sh_addr);
                            break;
                        }
                    }
                }
                sym_info[i].found = 1;
                found_count++;
                break;
            }
        }
        free(syms);
        free(strtab);
    }

    free(shdrs);
    return (found_count >= num_syms);
}

#define QMH_MAGIC_64      0xFEEDFACF
#define QMH_CIGAM_64      0xCFFAEDFE
#define QMH_LC_SYMTAB     0x02
#define QMH_LC_SEGMENT_64 0x19

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} qmacho64_header_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} qmacho_load_cmd_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} qmacho64_segment_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} qmacho_symtab_cmd_t;

typedef struct {
    uint32_t n_strx;
    uint8_t n_type;
    uint8_t n_sect;
    uint16_t n_desc;
    uint64_t n_value;
} qmacho64_nlist_t;

typedef struct {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} qmacho64_section_t;
#pragma pack(pop)

static int macho64_lookup_symbols(FILE *fp, const char **sym_names,
                                  fips_sym_info_t *sym_info, int num_syms)
{
    qmacho64_header_t mhdr;
    qmacho_symtab_cmd_t symtab_cmd;
    qmacho64_nlist_t *nlist = NULL;
    char *strtab = NULL;
    int found_count = 0;
    int has_symtab = 0;
    uint32_t ci;
    long cmd_offset;
    int i;

    uint64_t seg_vmaddr[32], seg_fileoff[32], seg_vmsize[32];
    uint64_t sect_addr[256], sect_fileoff[256];
    uint64_t sect_size[256];
    int num_sects = 0;
    int num_segs = 0;

    for (i = 0; i < num_syms; i++)
        sym_info[i].found = 0;

    fseek(fp, 0, SEEK_SET);
    if (fread(&mhdr, sizeof(mhdr), 1, fp) != 1)
        return 0;

    if (mhdr.magic != QMH_MAGIC_64)
        return 0;

    memset(&symtab_cmd, 0, sizeof(symtab_cmd));
    cmd_offset = (long)sizeof(qmacho64_header_t);

    for (ci = 0; ci < mhdr.ncmds; ci++) {
        qmacho_load_cmd_t lc;

        fseek(fp, cmd_offset, SEEK_SET);
        if (fread(&lc, sizeof(lc), 1, fp) != 1)
            break;

        if (lc.cmd == QMH_LC_SYMTAB) {
            fseek(fp, cmd_offset, SEEK_SET);
            if (fread(&symtab_cmd, sizeof(symtab_cmd), 1, fp) == 1)
                has_symtab = 1;
        } else if (lc.cmd == QMH_LC_SEGMENT_64 && num_segs < 32) {
            qmacho64_segment_t seg;
            uint32_t si;

            fseek(fp, cmd_offset, SEEK_SET);
            if (fread(&seg, sizeof(seg), 1, fp) == 1) {
                seg_vmaddr[num_segs] = seg.vmaddr;
                seg_fileoff[num_segs] = seg.fileoff;
                seg_vmsize[num_segs] = seg.vmsize;
                num_segs++;

                for (si = 0; si < seg.nsects && num_sects < 256; si++) {
                    qmacho64_section_t sect;
                    if (fread(&sect, sizeof(sect), 1, fp) == 1) {
                        sect_addr[num_sects] = sect.addr;
                        sect_fileoff[num_sects] = sect.offset;
                        sect_size[num_sects] = sect.size;
                        num_sects++;
                    }
                }
            }
        }

        cmd_offset += lc.cmdsize;
    }

    if (!has_symtab || symtab_cmd.nsyms == 0) {
        if (!quiet)
            fprintf(stderr, "Mach-O: no symbol table found\n");
        return 0;
    }

    strtab = (char *)malloc(symtab_cmd.strsize);
    if (strtab == NULL)
        return 0;
    fseek(fp, (long)symtab_cmd.stroff, SEEK_SET);
    if (fread(strtab, 1, symtab_cmd.strsize, fp) != symtab_cmd.strsize) {
        free(strtab);
        return 0;
    }

    nlist = (qmacho64_nlist_t *)malloc(symtab_cmd.nsyms
                                       * sizeof(qmacho64_nlist_t));
    if (nlist == NULL) {
        free(strtab);
        return 0;
    }
    fseek(fp, (long)symtab_cmd.symoff, SEEK_SET);
    if (fread(nlist, sizeof(qmacho64_nlist_t), symtab_cmd.nsyms, fp)
        != symtab_cmd.nsyms) {
        free(nlist);
        free(strtab);
        return 0;
    }

    for (ci = 0; ci < symtab_cmd.nsyms && found_count < num_syms; ci++) {
        const char *name;

        if (nlist[ci].n_strx >= symtab_cmd.strsize)
            continue;
        name = strtab + nlist[ci].n_strx;

        if (name[0] == '_')
            name++;

        for (i = 0; i < num_syms; i++) {
            int si;

            if (sym_info[i].found || strcmp(name, sym_names[i]) != 0)
                continue;

            sym_info[i].vaddr = nlist[ci].n_value;
            sym_info[i].size = 0;

            sym_info[i].file_offset = 0;
            for (si = 0; si < num_sects; si++) {
                if (nlist[ci].n_value >= sect_addr[si]
                    && nlist[ci].n_value < sect_addr[si] + sect_size[si]) {
                    sym_info[i].file_offset
                        = sect_fileoff[si]
                          + (nlist[ci].n_value - sect_addr[si]);
                    break;
                }
            }
            if (sym_info[i].file_offset == 0) {
                for (si = 0; si < num_segs; si++) {
                    if (nlist[ci].n_value >= seg_vmaddr[si]
                        && nlist[ci].n_value
                               < seg_vmaddr[si] + seg_vmsize[si]) {
                        sym_info[i].file_offset
                            = seg_fileoff[si]
                              + (nlist[ci].n_value - seg_vmaddr[si]);
                        break;
                    }
                }
            }

            sym_info[i].found = 1;
            found_count++;
            break;
        }
    }

    free(nlist);
    free(strtab);

    if (found_count < num_syms) {
        for (i = 0; i < num_syms; i++) {
            if (!sym_info[i].found)
                fprintf(stderr, "Error: symbol '%s' not found in Mach-O\n",
                        sym_names[i]);
        }
    }
    return (found_count >= num_syms);
}

#define QPE_DOS_MAGIC    0x5A4D
#define QPE_SIGNATURE    0x00004550
#define QPE_OPT_MAGIC_64 0x020B
#define QPE_OPT_MAGIC_32 0x010B

#pragma pack(push, 1)
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
} qpe_dos_header_t;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} qpe_coff_header_t;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} qpe_section_header_t;

typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } Long;
    } Name;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} qpe_coff_symbol_t;
#pragma pack(pop)

static int pe_lookup_symbols(FILE *fp, const char **sym_names,
                             fips_sym_info_t *sym_info, int num_syms)
{
    qpe_dos_header_t dos_hdr;
    uint32_t pe_sig;
    qpe_coff_header_t coff_hdr;
    qpe_section_header_t *sections = NULL;
    qpe_coff_symbol_t *sym_table = NULL;
    char *strtab = NULL;
    uint32_t strtab_size = 0;
    long opt_hdr_end;
    int found_count = 0;
    uint32_t si;
    int i;

    for (i = 0; i < num_syms; i++)
        sym_info[i].found = 0;

    fseek(fp, 0, SEEK_SET);
    if (fread(&dos_hdr, sizeof(dos_hdr), 1, fp) != 1)
        return 0;
    if (dos_hdr.e_magic != QPE_DOS_MAGIC)
        return 0;

    fseek(fp, dos_hdr.e_lfanew, SEEK_SET);
    if (fread(&pe_sig, sizeof(pe_sig), 1, fp) != 1)
        return 0;
    if (pe_sig != QPE_SIGNATURE)
        return 0;

    if (fread(&coff_hdr, sizeof(coff_hdr), 1, fp) != 1)
        return 0;

    if (coff_hdr.PointerToSymbolTable == 0 || coff_hdr.NumberOfSymbols == 0) {
        if (!quiet)
            fprintf(stderr,
                    "PE: no COFF symbol table (binary may be stripped)\n");
        return 0;
    }

    opt_hdr_end = dos_hdr.e_lfanew + 4 + (long)sizeof(qpe_coff_header_t)
                  + coff_hdr.SizeOfOptionalHeader;

    sections = (qpe_section_header_t *)malloc(coff_hdr.NumberOfSections
                                              * sizeof(qpe_section_header_t));
    if (sections == NULL)
        return 0;

    fseek(fp, opt_hdr_end, SEEK_SET);
    if (fread(sections, sizeof(qpe_section_header_t), coff_hdr.NumberOfSections,
              fp)
        != coff_hdr.NumberOfSections) {
        free(sections);
        return 0;
    }

    sym_table = (qpe_coff_symbol_t *)malloc(coff_hdr.NumberOfSymbols
                                            * sizeof(qpe_coff_symbol_t));
    if (sym_table == NULL) {
        free(sections);
        return 0;
    }

    fseek(fp, (long)coff_hdr.PointerToSymbolTable, SEEK_SET);
    if (fread(sym_table, sizeof(qpe_coff_symbol_t), coff_hdr.NumberOfSymbols,
              fp)
        != coff_hdr.NumberOfSymbols) {
        free(sym_table);
        free(sections);
        return 0;
    }

    {
        long strtab_off
            = (long)coff_hdr.PointerToSymbolTable
              + (long)(coff_hdr.NumberOfSymbols * sizeof(qpe_coff_symbol_t));
        fseek(fp, strtab_off, SEEK_SET);
        if (fread(&strtab_size, sizeof(strtab_size), 1, fp) == 1
            && strtab_size > 4) {
            strtab = (char *)malloc(strtab_size);
            if (strtab != NULL) {
                fseek(fp, strtab_off, SEEK_SET);
                if (fread(strtab, 1, strtab_size, fp) != strtab_size) {
                    free(strtab);
                    strtab = NULL;
                }
            }
        }
    }

    for (si = 0; si < coff_hdr.NumberOfSymbols && found_count < num_syms;
         si++) {
        const char *name;
        char short_name[9];

        if (sym_table[si].NumberOfAuxSymbols > 0) {
            si += sym_table[si].NumberOfAuxSymbols;
            continue;
        }

        if (sym_table[si].Name.Long.Zeroes == 0) {
            if (strtab == NULL || sym_table[si].Name.Long.Offset >= strtab_size)
                continue;
            name = strtab + sym_table[si].Name.Long.Offset;
        } else {
            memcpy(short_name, sym_table[si].Name.ShortName, 8);
            short_name[8] = '\0';
            name = short_name;
        }

        if (name[0] == '_')
            name++;

        for (i = 0; i < num_syms; i++) {
            if (sym_info[i].found || strcmp(name, sym_names[i]) != 0)
                continue;

            sym_info[i].vaddr = sym_table[si].Value;
            sym_info[i].size = 0;

            if (sym_table[si].SectionNumber > 0
                && sym_table[si].SectionNumber
                       <= (int16_t)coff_hdr.NumberOfSections) {
                qpe_section_header_t *sec
                    = &sections[sym_table[si].SectionNumber - 1];
                sym_info[i].file_offset
                    = sec->PointerToRawData + sym_table[si].Value;
                sym_info[i].vaddr = sec->VirtualAddress + sym_table[si].Value;
            } else {
                sym_info[i].file_offset = sym_table[si].Value;
            }

            sym_info[i].found = 1;
            found_count++;
            break;
        }
    }

    free(sym_table);
    free(sections);
    free(strtab);

    if (found_count < num_syms) {
        for (i = 0; i < num_syms; i++) {
            if (!sym_info[i].found)
                fprintf(stderr, "Error: symbol '%s' not found in PE/COFF\n",
                        sym_names[i]);
        }
    }
    return (found_count >= num_syms);
}

typedef enum {
    BINFORMAT_UNKNOWN = 0,
    BINFORMAT_ELF64,
    BINFORMAT_MACHO64,
    BINFORMAT_PE
} bin_format_t;

static bin_format_t detect_format(FILE *fp)
{
    unsigned char magic[4];
    qpe_dos_header_t dos_hdr;

    fseek(fp, 0, SEEK_SET);
    if (fread(magic, 1, 4, fp) != 4)
        return BINFORMAT_UNKNOWN;

    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L'
        && magic[3] == 'F') {
        unsigned char elf_class;
        if (fread(&elf_class, 1, 1, fp) != 1)
            return BINFORMAT_UNKNOWN;
        return (elf_class == 2) ? BINFORMAT_ELF64 : BINFORMAT_UNKNOWN;
    }

    {
        uint32_t mh_magic;
        memcpy(&mh_magic, magic, 4);
        if (mh_magic == QMH_MAGIC_64)
            return BINFORMAT_MACHO64;
    }

    if (magic[0] == 'M' && magic[1] == 'Z') {
        uint32_t pe_sig;
        fseek(fp, 0, SEEK_SET);
        if (fread(&dos_hdr, sizeof(dos_hdr), 1, fp) != 1)
            return BINFORMAT_UNKNOWN;
        fseek(fp, dos_hdr.e_lfanew, SEEK_SET);
        if (fread(&pe_sig, sizeof(pe_sig), 1, fp) != 1)
            return BINFORMAT_UNKNOWN;
        if (pe_sig == QPE_SIGNATURE)
            return BINFORMAT_PE;
    }

    return BINFORMAT_UNKNOWN;
}

static int compute_region_hmac(FILE *fp, uint64_t file_offset, uint64_t length,
                               unsigned char *out, size_t *out_len)
{
    unsigned char key[32] = {QUDO_FIPS_KEY_ELEMENTS};
    qudo_fips_hmac_ctx_t ctx;
    unsigned char buf[BUFSIZE];
    uint64_t remaining = length;
    int ret = 0;

    qudo_fips_hmac_init(&ctx, key, sizeof(key));

    fseek(fp, (long)file_offset, SEEK_SET);

    while (remaining > 0) {
        size_t to_read = (remaining > BUFSIZE) ? BUFSIZE : (size_t)remaining;
        size_t n = fread(buf, 1, to_read, fp);
        if (n == 0) {
            if (ferror(fp))
                fprintf(stderr, "Error: reading file at offset %lu\n",
                        (unsigned long)file_offset);
            goto err;
        }
        qudo_fips_hmac_update(&ctx, buf, n);
        remaining -= n;
    }

    qudo_fips_hmac_final(&ctx, out);
    *out_len = 32;

    ret = 1;
err:
    fips_cleanse(&ctx, sizeof(ctx));
    fips_cleanse(key, sizeof(key));
    fips_cleanse(buf, sizeof(buf));
    return ret;
}

static int do_embed_symbols(const char *filename)
{
    FILE *fp = NULL;
    const char *sym_names[3];
    fips_sym_info_t sym_info[3];
    bin_format_t fmt;
    uint64_t region_start, region_end, region_size;
    uint64_t hmac_offset;
    unsigned char hmac[MAX_MD_SIZE];
    size_t hmac_len = 0;
    int lookup_ok;
    int ret = 0;
    const char *fmt_name;

    sym_names[0] = "qudo_fips_module_start";
    sym_names[1] = "qudo_fips_module_end";
    sym_names[2] = "qudo_fips_integrity_hmac";

    fp = fopen(filename, "r+b");
    if (fp == NULL) {
        fprintf(stderr, "Error: cannot open '%s' for read/write\n", filename);
        return 0;
    }

    fmt = detect_format(fp);
    switch (fmt) {
    case BINFORMAT_ELF64:
        fmt_name = "ELF64";
        lookup_ok = elf64_lookup_symbols(fp, sym_names, sym_info, 3);
        break;
    case BINFORMAT_MACHO64:
        fmt_name = "Mach-O 64";
        lookup_ok = macho64_lookup_symbols(fp, sym_names, sym_info, 3);
        break;
    case BINFORMAT_PE:
        fmt_name = "PE/COFF";
        lookup_ok = pe_lookup_symbols(fp, sym_names, sym_info, 3);
        break;
    default:
        if (!quiet)
            fprintf(stderr, "Unknown binary format in %s\n", filename);
        fclose(fp);
        return 0;
    }

    if (!lookup_ok) {
        fprintf(stderr, "Error: required symbols not found in %s (%s)\n",
                filename, fmt_name);
        fprintf(
            stderr,
            "Binary must be built with QUDO_FIPS_MODULE and boundary files.\n");
        goto err;
    }

    region_start = sym_info[0].file_offset;
    region_end = sym_info[1].file_offset;
    hmac_offset = sym_info[2].file_offset;

    if (region_end <= region_start) {
        fprintf(stderr, "Error: module_end (0x%lx) <= module_start (0x%lx)\n",
                (unsigned long)region_end, (unsigned long)region_start);
        fprintf(stderr,
                "Check link order: boundary_start.c must be linked first.\n");
        goto err;
    }

    region_size = region_end - region_start;

    if (region_size < 1024) {
        fprintf(stderr, "Error: FIPS code region too small (%lu bytes)\n",
                (unsigned long)region_size);
        goto err;
    }

    if (!quiet) {
        printf("Binary format:        %s\n", fmt_name);
        printf("FIPS module boundary:\n");
        printf("  module_start:       vaddr=0x%lx  file=0x%lx\n",
               (unsigned long)sym_info[0].vaddr,
               (unsigned long)sym_info[0].file_offset);
        printf("  module_end:         vaddr=0x%lx  file=0x%lx\n",
               (unsigned long)sym_info[1].vaddr,
               (unsigned long)sym_info[1].file_offset);
        printf("  integrity_hmac:     vaddr=0x%lx  file=0x%lx\n",
               (unsigned long)sym_info[2].vaddr,
               (unsigned long)sym_info[2].file_offset);
        printf("  Code region size:   %lu bytes\n", (unsigned long)region_size);
    }

    if (!compute_region_hmac(fp, region_start, region_size, hmac, &hmac_len)) {
        fprintf(stderr, "Error: failed to compute HMAC of code region\n");
        goto err;
    }

    if (fseek(fp, (long)hmac_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Error: cannot seek to HMAC offset\n");
        goto err;
    }
    if (fwrite(hmac, 1, 32, fp) != 32) {
        fprintf(stderr, "Error: cannot write HMAC to binary\n");
        goto err;
    }
    fflush(fp);

    if (!quiet) {
        size_t i;
        printf("Embedded in-memory HMAC into %s\n", filename);
        printf("  HMAC: ");
        for (i = 0; i < 32; i++)
            printf("%02x", hmac[i]);
        printf("\n");
    }

    ret = 1;
err:
    fips_cleanse(hmac, sizeof(hmac));
    if (fp != NULL)
        fclose(fp);
    return ret;
}

static int do_verify_embed(const char *filename)
{
    FILE *fp = NULL;
    const char *sym_names[3];
    fips_sym_info_t sym_info[3];
    bin_format_t fmt;
    uint64_t region_start, region_end, region_size, hmac_offset;
    unsigned char computed[MAX_MD_SIZE];
    unsigned char stored[32];
    size_t computed_len = 0;
    int lookup_ok;
    int ret = 0;
    const char *fmt_name = "unknown";

    sym_names[0] = "qudo_fips_module_start";
    sym_names[1] = "qudo_fips_module_end";
    sym_names[2] = "qudo_fips_integrity_hmac";

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error: cannot open '%s' for read\n", filename);
        return 0;
    }

    fmt = detect_format(fp);
    switch (fmt) {
    case BINFORMAT_ELF64:
        fmt_name = "ELF64";
        lookup_ok = elf64_lookup_symbols(fp, sym_names, sym_info, 3);
        break;
    case BINFORMAT_MACHO64:
        fmt_name = "Mach-O 64";
        lookup_ok = macho64_lookup_symbols(fp, sym_names, sym_info, 3);
        break;
    case BINFORMAT_PE:
        fmt_name = "PE/COFF";
        lookup_ok = pe_lookup_symbols(fp, sym_names, sym_info, 3);
        break;
    default:
        fprintf(stderr, "Error: unknown binary format in %s\n", filename);
        goto err;
    }

    if (!lookup_ok) {
        fprintf(stderr, "Error: required symbols not found in %s (%s)\n",
                filename, fmt_name);
        goto err;
    }

    region_start = sym_info[0].file_offset;
    region_end = sym_info[1].file_offset;
    hmac_offset = sym_info[2].file_offset;

    if (region_end <= region_start) {
        fprintf(stderr, "Error: module_end <= module_start\n");
        goto err;
    }
    region_size = region_end - region_start;

    if (!compute_region_hmac(fp, region_start, region_size, computed,
                             &computed_len)
        || computed_len != 32) {
        fprintf(stderr, "Error: failed to compute HMAC of code region\n");
        goto err;
    }

    if (fseek(fp, (long)hmac_offset, SEEK_SET) != 0
        || fread(stored, 1, 32, fp) != 32) {
        fprintf(stderr, "Error: cannot read embedded HMAC\n");
        goto err;
    }

    {
        int all_zero = 1;
        size_t j;
        for (j = 0; j < 32; j++) {
            if (stored[j] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            fprintf(stderr,
                    "Error: embedded HMAC is not patched (placeholder). "
                    "Run: %s -embed -module %s\n",
                    "qudo_fipsinstall", filename);
            goto err;
        }
    }

    if (memcmp(computed, stored, 32) != 0) {
        if (!quiet) {
            size_t k;
            printf("VERIFY-EMBED FAILED\n");
            printf("  stored:   ");
            for (k = 0; k < 32; k++)
                printf("%02x", stored[k]);
            printf("\n  computed: ");
            for (k = 0; k < 32; k++)
                printf("%02x", computed[k]);
            printf("\n");
        }
        goto err;
    }

    if (!quiet)
        printf("VERIFY-EMBED PASSED\n");
    ret = 1;

err:
    fips_cleanse(computed, sizeof(computed));
    fips_cleanse(stored, sizeof(stored));
    if (fp != NULL)
        fclose(fp);
    return ret;
}

static void print_usage(const char *prog)
{
    fprintf(
        stderr,
        "Usage:\n"
        "  Generate config:\n"
        "    %s -module <module.so> [-library <lib.so>] -out <config.cnf>\n"
        "\n"
        "  Verify config:\n"
        "    %s -verify -module <module.so> [-library <lib.so>] -in <config.cnf>\n"
        "\n"
        "  Embed HMAC (in-memory verification):\n"
        "    %s -embed -module <module.so>\n"
        "\n"
        "  Verify embedded HMAC:\n"
        "    %s -verify-embed -module <module.so>\n"
        "\n"
        "Options:\n"
        "  -section_name <name>  Config section name (default: qudo_pqc_sect)\n"
        "  -quiet                Suppress informational output\n",
        prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    int i;
    int verify_mode = 0;
    int embed_mode = 0;
    int verify_embed_mode = 0;
    const char *module_path = NULL;
    const char *library_path = NULL;
    const char *outfile = NULL;
    const char *infile = NULL;
    const char *section = "qudo_pqc_sect";
    unsigned char module_mac[MAX_MD_SIZE], library_mac[MAX_MD_SIZE];
    size_t module_mac_len = 0, library_mac_len = 0;
    int ret = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-module") == 0 && i + 1 < argc) {
            module_path = argv[++i];
        } else if (strcmp(argv[i], "-library") == 0 && i + 1 < argc) {
            library_path = argv[++i];
        } else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            outfile = argv[++i];
        } else if (strcmp(argv[i], "-in") == 0 && i + 1 < argc) {
            infile = argv[++i];
        } else if (strcmp(argv[i], "-section_name") == 0 && i + 1 < argc) {
            section = argv[++i];
        } else if (strcmp(argv[i], "-verify") == 0) {
            verify_mode = 1;
        } else if (strcmp(argv[i], "-embed") == 0) {
            embed_mode = 1;
        } else if (strcmp(argv[i], "-verify-embed") == 0) {
            verify_embed_mode = 1;
        } else if (strcmp(argv[i], "-quiet") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-help") == 0
                   || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (module_path == NULL) {
        fprintf(stderr, "Error: -module is required\n");
        print_usage(argv[0]);
        return 1;
    }

    if (embed_mode) {
        ret = do_embed_symbols(module_path) ? 0 : 1;
        return ret;
    }

    if (verify_embed_mode) {
        ret = do_verify_embed(module_path) ? 0 : 1;
        return ret;
    }

    if (verify_mode) {
        if (infile == NULL) {
            fprintf(stderr, "Error: -in is required for verify mode\n");
            print_usage(argv[0]);
            return 1;
        }
        ret = do_verify(module_path, library_path, infile, section) ? 0 : 1;
    } else {
        if (outfile == NULL) {
            fprintf(stderr, "Error: -out is required for generate mode\n");
            print_usage(argv[0]);
            return 1;
        }

        if (!compute_file_hmac(module_path, module_mac, &module_mac_len))
            goto end;

        if (library_path != NULL) {
            if (!compute_file_hmac(library_path, library_mac, &library_mac_len))
                goto end;
        }

        if (!write_config(outfile, section, module_mac, module_mac_len,
                          library_mac, library_mac_len, module_path,
                          library_path))
            goto end;

        ret = 0;
    }

end:
    fips_cleanse(module_mac, sizeof(module_mac));
    fips_cleanse(library_mac, sizeof(library_mac));
    return ret;
}
