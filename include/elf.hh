#include <linux/types.h>
#include <iostream>
#include <string>
#include <sys/mman.h>
#include <elf.h>
#include <list>
#include "./utils.h"

#define Elf_Ehdr	Elf64_Ehdr
#define Elf_Phdr	Elf64_Phdr
#define Elf_Shdr	Elf64_Shdr
#define Elf_Dyn		Elf64_Dyn
#define Elf_Rel		Elf64_Rel
#define Elf_Rela	Elf64_Rela
#define Elf_Sym		Elf64_Sym
#define Elf_Off		Elf64_Off
#define Elf_Verneed	Elf64_Verneed
#define Elf_Vernaux	Elf64_Vernaux

typedef struct {
	__u8	t;
	Elf_Shdr	*sec;
	__u64		off, size;
	__u8	*str;
	union {
		void	*ptr;
		Elf_Rela	*rela;
		Elf_Rel		*rel;
	};
} elf_rela_t;

typedef struct {
	__u16		t;
	struct {
		Elf_Shdr	*sec;
		__u64		off;
	} src;
	Elf_Sym		*tab;
	__u8 		*str;
	Elf_Shdr	*str_sec;
} elf_symtab_t;

struct ElfX_Phdr : Elf_Phdr {
	bool hasOff(__u64 off);
	bool hasVirt(__u64 virt);
	void operator++();
	bool operator<(Elf_Phdr *p);
	bool Is(__u8 perm);
	__u64 Offset();
};

struct ElfX_Shdr : Elf_Shdr {
	bool hasOff(__u64 off);
	bool hasVirt(__u64 virt);
	void operator++();
	bool operator<(Elf_Shdr *s);
	bool Is(__u8 perm);
	__u64 Offset();
};

typedef struct {
	__u64 sym_off;
	__u16			*sym;
	Elf_Verneed		*need;
	__u64 num;
} gnu_ver_t;


	#define N_PHDR(n)	(sizeof(Elf_Phdr)	* n)
	#define N_SHDR(n)	(sizeof(Elf_Shdr)	* n)
	#define N_SYM(n)	(sizeof(Elf_Sym)	* n)

	#define ELF_N_PHDR(elf, n) (elf->ehdr->e_phentsize * n)
	#define ELF_N_SHDR(elf, n) (elf->ehdr->e_shentsize * n)

	#define _elf_dynamic_sz(elf)	(!(elf)->dynamic.mm.t	? (elf)->dynamic.hdr_sz : ((elf)->dynamic.mm.sz))
	#define _elf_symtab_sz(stab)	(stab)->mm_tab.sz
	#define _elf_rela_t_sz(rtab)	(rtab)->mm.sz

	// #define _elf_off(elf, ptr)		\
	// 		((_contain_((elf)->map, (elf)->size, (void*)(ptr))) ? ((void*)(ptr) - (void*)(elf)->map) : 0)


	#define foreach_shdr(elf, s)							\
			for (ElfX_Shdr *s = (ElfX_Shdr *)((elf)->shdr);	\
				!!s && (Elf_Shdr*)s < &(elf)->shdr[(elf)->ehdr->e_shnum]; s++)

	#define foreach_phdr(elf, p)							\
			for (ElfX_Phdr *p = (ElfX_Phdr *)((elf)->phdr);	\
				!!p && (Elf_Phdr*)p < &(elf)->phdr[(elf)->ehdr->e_phnum]; p++)


	#define foreach_dynamic(elf, e)			\
			for (Elf_Dyn *e = (elf)->dyn.tab;	\
				(__u64)e < ((__u64)(elf)->dyn.tab + elf->dyn.src.size); e++)

	// #define foreach_dynamic_ptr(elf, dyn)			\
	// 		foreach_dynamic(elf, dyn) if (elf_dtag_is_addr(dyn->d_tag))

	/**
	 *	Symbols
	 **/
	#define foreach_ll_symtab(elf, stab)		\
				foreach_ll_T((&(elf)->ll_sym), stab, symtab_t)

	#define foreach_sym(stab, sym)		\
			for (Elf_Sym *sym = (stab)->tab; (__u64)sym < (__u64)(stab)->tab + (__u64)(stab)->src.sec->sh_size; sym++)
	
	#define foreach_sym_tab(elf, stab, sym) for (auto& stab : (elf)->symtab) foreach_sym(&stab, sym)
	// #define foreach_sym(elf, stab, sym)			\
	// 		foreach_ll_symtab((elf), stab)		\
	// 			feech_syms(stab, sym)

	#define foreach_dynsym(elf, stab, sym)			\
			foreach_ll_symtab((elf), stab) if (stab->t == SHT_DYNSYM)	\
				feech_syms(stab, sym)

	#define foreach_symtab(elf, stab, sym)			\
			foreach_ll_symtab((elf), stab) if (stab->t == SHT_SYMTAB)	\
				feech_syms(stab, sym)

	/**
	 *	Rel/Rela
	 **/
	#define foreach_rela(rtab, e)				\
			for (Elf_Rela *e = (rtab)->rela; !!e && (void*)e < (void*)((__u64)(rtab)->rela + (rtab)->size); e++)

	#define foreach_rela_tab(elf, rtab, r) for (auto& rtab : (elf)->relatab) foreach_rela(&rtab, r)

	#define foreach_rel(rtab, e)				\
			for (Elf_Rel *e = (rtab)->rel; !!e && (void*)e < (void*)((__u64)(rtab)->rel + (rtab)->size); e++)
	// #define foreach_ll_rela(ll, rtab)	foreach_ll_T((ll), (rtab), rela_t)
	#define foreach_rel_tab(elf, rtab, r) for (auto& rtab : (elf)->reltab) foreach_rel(&rtab, r)
	// #define foreach_rela_t(rtab, e, T)				\
	// 		for (T *e = (rtab)->ptr; !!e && (void*)e < (rtab)->ptr + (rtab)->size; e++)

	// #define foreach_rel(elf, rtab, rel)				\
	// 		foreach_ll_rela((&(elf)->ll_rel), rtab)	\
	// 			foreach_rela_t(rtab, rel, Elf_Rel)

	// #define foreach_rela(elf, rtab, rela)			\
	// 		foreach_ll_rela((&(elf)->ll_rela), rtab)	\
	// 			foreach_rela_t(rtab, rela, Elf_Rela)

	// #define _rel_check(rel) ((rel)->ptr && (rel)->mm.sz)

	// #define elf_get_ll_rel(elf, t)											\
	// 		(((t) == DT_REL || (t) == SHT_REL)	? (&(elf)->ll_rel)	:		\
	// 		((t) == DT_RELA || (t) == SHT_RELA)	? (&(elf)->ll_rela)	: NULL)	\


	#define for_each_gnu_verneed(elf, e)						\
			for (Elf_Verneed *i = 0, *e = (elf)->gnu_ver.need ;	\
				i < (elf)->gnu_ver.num ;						\
				i = (void*)i + 1, e = (void*)e + e->vn_next)

	#define for_each_gnu_vernaux(vn, e)								\
			for (Elf_Vernaux *i = 0, *e = (void*)vn + vn->vn_aux;	\
				i < vn->vn_cnt;										\
				i = (void*)i + 1, e = (void*)e + e->vna_next)
// #endif

// int new_elf(__u8 *f, elf_t *elf);
// int load_elf(__u8 *, elf_t *);

// Elf_Phdr *shdr_get_phdr(elf_t *elf, Elf_Shdr *sec);
// Elf_Phdr *get_last_PT_LOAD(Elf_Phdr *phdr, __u16 num);
// Elf_Shdr *sec_by_shtype(__u32 t, elf_t *elf);
// Elf_Sym *elf_sym_by_name(elf_t *elf, __u8 *str);

// __u64 elf_off_to_virt(elf_t *elf, __u64 off);
// __u64 elf_virt_to_off(elf_t *elf, __u64 virt);
// #define elf_ftov	elf_off_to_virt
// #define elf_vtof	elf_virt_to_off

// Elf_Shdr *elf_sec_by_name(elf_t *elf, __u8 *str);
// void pr_sec(elf_t *elf, Elf_Shdr *sec);
// void pr_sym(elf_t *elf, Elf_Sym *sym);
// Elf_Phdr *phdr_by_ptype(__u32 t, elf_t *elf);
// rela_t *elf_get_plt_rela(elf_t *elf);

// __s32 get_phdr_ndx(elf_t *elf, Elf_Phdr *phdr);
// __s32 get_shdr_ndx(elf_t *elf, Elf_Shdr *sec);

// void elf_alloc_all(elf_t *elf);

// symtab_t *elf_get_symtab(elf_t *elf);
// symtab_t *elf_get_dyntab(elf_t *elf);
// symtab_t *elf_get_symtab_t(elf_t *elf, __u64 t);
// __u8 *elf_sec_name(elf_t *elf, Elf_Shdr *sec);
// __u8 *elf_sym_name(symtab_t *stab, Elf_Sym *sym);
// __u8 *elf_find_sym_name(elf_t *elf, Elf_Sym *sym);
// __u8 *elf_rela_name(symtab_t *stab, Elf_Rela *rela);
// __u8 *elf_rel_name(symtab_t *stab, Elf_Rel *rel);

// Elf_Phdr *elf_virt_to_phdr(elf_t *elf, __u64 virt);
// Elf_Phdr *elf_off_to_phdr(elf_t *elf, __u64 off);
// Elf_Shdr *elf_virt_to_shdr(elf_t *elf, __u64 virt);
// Elf_Shdr *elf_off_to_shdr(elf_t *elf, __u64 off);
// Elf_Sym *elf_off_to_sym(elf_t *elf, __u64 v_off, __u64 v_sz);

// __s8 elf_dtag_is_addr(__s64 dtag);
// Elf_Dyn *elf_get_got_plt(elf_t *elf);
// __u8 sym_fits_phdr(Elf_Sym *sym, Elf_Phdr *p);

// __u64 get_unknown_sz_sym_sz(elf_t *elf, Elf_Sym *sym);
// sym_obj *get_sym(elf_t *elf, __u8 *str);
// sym_obj *make_sym_obj(elf_t *elf, Elf_Sym *sym);

typedef struct elf_t {
	char	*file;
	__u64	size;
	union {
		Elf_Ehdr	*ehdr;
		void		*map;
	};
	Elf_Phdr	*phdr;

	Elf_Shdr	*shdr;
	struct {
		__u8 		*str;
		Elf_Shdr	*str_sec;
	} sec;

	struct {
		struct {
			Elf_Phdr	*phdr;
			Elf_Shdr	*sec;
			__u64		off, size;
		} src;
		Elf_Dyn		*tab;
	} dyn;

	std::list<elf_symtab_t> 	symtab;
	std::list<elf_rela_t>		relatab;
	std::list<elf_rela_t>		reltab;

	template<typename T, typename X> T off(X v) {
		return (T)((__u64)map + (__u64)v);
	}
	template<typename T, typename X> T virt(X v) {
		return (T)((__u64)map + (__u64)vtof(v));
	}

	__u64 vtof(__u64 virt);
	__u64 ftov(__u64 off);
	ElfX_Phdr *vtoph(__u64 virt);
	ElfX_Phdr *ftoph(__u64 off);
	ElfX_Shdr *ftosh(__u64 off);
	ElfX_Shdr *vtosh(__u64 virt);

	std::string sec_name(Elf_Shdr *s);
	template<typename R>
	__u8 *_rel_name(elf_t *elf, elf_rela_t& rtab, R *r);
	__u8 *rela_name(elf_rela_t& rtab, Elf_Rela *r);
	__u8 *rel_name(elf_rela_t& rtab, Elf_Rel *r);

	__s8 has_phdr() { return !!ehdr->e_phnum; }
	__s8 has_shdr() { return !!ehdr->e_shnum; }

	void add_reltab(elf_rela_t& st);
	void add_symtab(elf_symtab_t& sym);
	ElfX_Shdr *PLT() { return sec_by_name(".plt"); }
	ElfX_Shdr *GOT() { return sec_by_name(".got"); }
	bool dyn_is_ptr(Elf_Dyn *dyn);
	elf_symtab_t *dynsym();

	template<typename T>
	ElfX_Shdr *sec_by_name(T str) {
		foreach_shdr(this, s) if (sec_name(s) == (char *)(str)) return s;
		return nullptr;
	}
} elf_t;

// #ifdef ELF_INTERNAL_H

namespace ParseElf {
	static __s8 set_dynamic(elf_t *elf);
	static __s8 init_reltab(elf_t *elf);
	static __s8 init_symtab(elf_t *elf);
	__s8 init_elf(elf_t *elf, char *f);
	__s8 load_elf(elf_t *elf, char *file);
	__u8 ShdrPerms(Elf_Shdr *sec);
};


class Elf : public elf_t {
public:
	bool is_ok{false};
	__u8	bits;
	__u16	endian;

	// Elf(Elf&&)			= default;
	// Elf& operator=(Elf&)= default;
	template<typename T>
	Elf(T *file) {
		if ((ParseElf::load_elf(this, (char*)file) == -1) ||
			(ParseElf::init_elf(this, (char*)file) == -1))
		{
			perror("[ELF] - ");
			return;
		}
		is_ok = true;
	}
	~Elf() {
		printf("---\n");
		munmap(map, size);
		delete file;
	}

	bool ok() { return this->is_ok; }
	__u8 OffPerm(__u64 off);
	__u8 VirtPerm(__u64 v);
	bool IsOff_R(__u64 x) { return OffPerm(x) & PF_R; }
	bool IsOff_W(__u64 x) { return OffPerm(x) & PF_W; }
	bool IsOff_X(__u64 x) { return OffPerm(x) & PF_X; }
	bool IsVirt_R(__u64 x) { return VirtPerm(x) & PF_R; }
	bool IsVirt_W(__u64 x) { return VirtPerm(x) & PF_W; }
	bool IsVirt_X(__u64 x) { return VirtPerm(x) & PF_X; }
	// void *ptr(__u64 off) {
	// 	return _contains_(0, elf->size, off) ? elf->ptr + off : NULL;
	// }
	elf_t *raw() {
		return dynamic_cast<elf_t*>(this);
	}

	// template<typename F> void each_rela(F fn);
	// template<typename F> void each_rel(F fn);
	// template<typename F> void each_sym(F fn);
	
private:
	__u8 PhdrOffPerm(__u64 off);
	__u8 ShdrOffPerm(__u64 off);
};
