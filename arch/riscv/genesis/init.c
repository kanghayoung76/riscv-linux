#include <linux/init.h>
#include <linux/gfp.h>
#include <linux/memblock.h>

#include <asm/genesis.h>
#include <asm/vmlinux.lds.h>
#include <asm/page.h>
#include <asm/set_memory.h>

#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/scs.h>
#include <linux/seq_file.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include <asm/softirq_stack.h>
#include <asm/stacktrace.h>
#include <asm/insn-def.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <asm/asm-extable.h>   // _ASM_EXTABLE 사용


int genesis_enabled __ro_after_init = 0;

/* FIXME: Use a unused hole
 * Refer: Documentation/riscv/vm-layout.rst
 * */
#ifdef CONFIG_KASAN
#error "Disable KASAN to be compatible with GENESIS!"
#endif

//unsigned long shadow_offset_base __ro_after_init = MODULES_LOWEST_VADDR - SZ_8G;
unsigned long shadow_offset_base __ro_after_init = _AC(0xffffaf9000000000, UL);

/* PRIVINST Section */
extern char __privinst_begin[], __privinst_end[];

/* GENESIS Inner kernel Section */
extern char __genesis_text_begin[], __genesis_text_end[];

#undef pr_fmt
#define pr_fmt(fmt) "[GENESIS] " fmt

#define _PAGE_VALID   _AC(0x1,UL)
#define gstage_pgd_size    (1UL << (HGATP_PAGE_SHIFT + 2))

// arch/riscv/include/asm or 적당한 C파일 상단
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <asm/csr.h>
#include <asm/pgtable.h>

#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) \
	(((~0ULL) - (1ULL << (l)) + 1) & \
	 (~0ULL >> (64 - 1 - (h))))
#endif

/* HGATP decode helpers */
static inline int hgatp_mode(void)
{
	return (csr_read(CSR_HGATP) >> HGATP_MODE_SHIFT) & 0xF;
}
static inline phys_addr_t hgatp_root_pa(void)
{
	unsigned long hgatp = csr_read(CSR_HGATP);
	u64 ppn = hgatp & GENMASK_ULL(43, 0);  /* 44-bit PPN */
	return (phys_addr_t)(ppn << PAGE_SHIFT);
}

/* x4 모드에서 루트 4페이지 중 은행 선택 */
static inline unsigned gstage_bank(unsigned long gpa, int mode)
{
	/* Sv39x4 → GPA[41:40], Sv48x4 → GPA[53:52] */
	return (mode == HGATP_MODE_SV39X4) ? ((gpa >> 40) & 3) : ((gpa >> 52) & 3);
}
static inline unsigned sstage_bank(unsigned long hva, int mode)
{
	/* Sv39x4 → GPA[41:40], Sv48x4 → GPA[53:52] */
	return (mode == HGATP_MODE_SV39X4) ? ((hva >> 40) & 3) : ((hva >> 52) & 3);
}

/* 엔트리 공통 비트 프린트 */
static inline void print_pte_bits(const char *tag, unsigned long e)
{
	pr_info("%s entry=%#lx (V=%d R=%d W=%d X=%d A=%d D=%d)\n",
		tag, e,
		!!(e & _PAGE_VALID),
		!!(e & _PAGE_READ),
		!!(e & _PAGE_WRITE),
		!!(e & _PAGE_EXEC),
		!!(e & _PAGE_ACCESSED),
		!!(e & _PAGE_DIRTY));
}

/* GPA가 leaf로 매핑될 때 물리주소 계산 (leaf 레벨에 따라 오프셋 포함) */
static phys_addr_t leaf_map_pa(unsigned long leaf_e, unsigned long gpa, int leaf_level_is)
{
	/* leaf_level_is: 0=PTE(4KiB), 1=PMD(2MiB), 2=PUD(1GiB), 3=P4D(512GiB) */
	phys_addr_t base = (phys_addr_t)((leaf_e >> 10) << PAGE_SHIFT);
	switch (leaf_level_is) {
	case 0: /* PTE(4KiB)  */ return base | (gpa & ((1UL << 12) - 1));
	case 1: /* PMD(2MiB)  */ return base | (gpa & ((1UL << 21) - 1));
	case 2: /* PUD(1GiB)  */ return base | (gpa & ((1UL << 30) - 1));
	case 3: /* P4D(512GiB)*/ return base | (gpa & ((1UL << 39) - 1));
	default: return base;
	}
}

/*
 * G-stage 테이블 “읽기 전용” 워커:
 *  - HGATP에서 루트 PA 읽음
 *  - x4 은행 선택
 *  - Sv39x4 / Sv48x4에 따라 인덱스 분해
 *  - 각 레벨: (해당 테이블의 PA/KVA, 엔트리 값) 출력
 *  - leaf면 매핑된 PA까지 계산해서 출력
 */
static inline phys_addr_t next_table_pa(unsigned long e)
{
  return (phys_addr_t)((e >> 10) << PAGE_SHIFT);
}
static inline bool is_leaf(unsigned long e)
{
  return e & (_PAGE_READ | _PAGE_WRITE | _PAGE_EXEC);
}

/* ===== SATP 헬퍼 ===== */
static inline phys_addr_t satp_root_pa(void)
{
  unsigned long satp = csr_read(CSR_SATP);
  u64 ppn = satp & GENMASK_ULL(43, 0);      /* Sv48: PPN[43:0] */
  return (phys_addr_t)(ppn << PAGE_SHIFT);
}

/* ===== Sv48(S-stage) KVA 워크 덤프: PGD→PUD→PMD→PTE, p4d 없음 ===== */
void sstage_dump_walk_kva_sv48(unsigned long kva)
{
    /* 커널 전역 변수 satp_mode 와 함수 이름 충돌 피하기 위해 직접 CSR에서 모드 추출 */
    unsigned long satp = csr_read(CSR_SATP);
    int mode = (satp >> 60) & 0xF;           /* MODE[63:60] */
    if (mode != 9) {                         /* 9 == Sv48 */
        pr_err("[SSTAGE] SATP.MODE=%d (Sv48 아님)\n", mode);
        return;
    }

    /* 루트 PA는 기존에 정의되어 있는 satp_root_pa() 재사용 */
    phys_addr_t root_pa = satp_root_pa();
    pgd_t *pgd = phys_to_virt(root_pa);

    /* Sv48 인덱스 분해 (p4d 접힘) */
    unsigned vpn3 = (kva >> 39) & 0x1FF; // PGD
    unsigned vpn2 = (kva >> 30) & 0x1FF; // PUD
    unsigned vpn1 = (kva >> 21) & 0x1FF; // PMD
    unsigned vpn0 = (kva >> 12) & 0x1FF; // PTE

    pr_info("[SSTAGE] Sv48 dump kva=%px root_pa=%pa va(root)=%px\n",
            (void *)kva, &root_pa, pgd);

    /* PGD */
    unsigned long e3 = pgd_val(pgd[vpn3]);
    pr_info(" PGD[%u] kva=%px ", vpn3, &pgd[vpn3]);
    print_pte_bits("", e3);                  /* 이미 있는 출력 헬퍼 사용 */
    if (!(e3 & _PAGE_VALID)) { pr_err("  PGD miss\n"); return; }
    if (is_leaf(e3)) {
        phys_addr_t mpa = leaf_map_pa(e3, kva, 3);   /* 512GiB leaf */
        pr_info("  LEAF@PGD (512GiB) map_pa=%pa\n", &mpa);
        return;
    }

    /* PUD table */
    phys_addr_t pud_pa = next_table_pa(e3);
    pud_t *pud = phys_to_virt(pud_pa);
    pr_info(" PUD page: pa=%pa va=%px\n", &pud_pa, pud);

    /* PUD */
    unsigned long e2 = pud_val(pud[vpn2]);
    pr_info(" PUD[%u] kva=%px ", vpn2, &pud[vpn2]);
    print_pte_bits("", e2);
    if (!(e2 & _PAGE_VALID)) { pr_err("  PUD miss\n"); return; }
    if (is_leaf(e2)) {
        phys_addr_t mpa = leaf_map_pa(e2, kva, 2);   /* 1GiB leaf */
        pr_info("  LEAF@PUD (1GiB) map_pa=%pa\n", &mpa);
        return;
    }

    /* PMD table */
    phys_addr_t pmd_pa = next_table_pa(e2);
    pmd_t *pmd = phys_to_virt(pmd_pa);
    pr_info(" PMD page: pa=%pa va=%px\n", &pmd_pa, pmd);

    /* PMD */
    unsigned long e1 = pmd_val(pmd[vpn1]);
    pr_info(" PMD[%u] kva=%px ", vpn1, &pmd[vpn1]);
    print_pte_bits("", e1);
    if (!(e1 & _PAGE_VALID)) { pr_err("  PMD miss\n"); return; }
    if (is_leaf(e1)) {
        phys_addr_t mpa = leaf_map_pa(e1, kva, 1);   /* 2MiB leaf */
        pr_info("  LEAF@PMD (2MiB) map_pa=%pa\n", &mpa);
        return;
    }

    /* PTE table */
    phys_addr_t pte_pa = next_table_pa(e1);
    pte_t *pt = phys_to_virt(pte_pa);
    pr_info(" PTE page: pa=%pa va=%px\n", &pte_pa, pt);

    /* PTE */
    unsigned long e0 = pte_val(pt[vpn0]);
    pr_info(" PTE[%u] kva=%px ", vpn0, &pt[vpn0]);
    print_pte_bits("", e0);
    if (!(e0 & _PAGE_VALID)) { pr_err("  PTE miss\n"); return; }
    if (!is_leaf(e0))        { pr_err("  PTE not leaf\n"); return; }

    phys_addr_t mpa = leaf_map_pa(e0, kva, 0);       /* 4KiB leaf */
    pr_info("  LEAF@PTE (4KiB) map_pa=%pa\n", &mpa);
}

void gstage_dump_walk_gpa_sv48x4(unsigned long gpa)
{
  int mode = hgatp_mode();                   // 기대: 9 (Sv48x4)
  if (mode != HGATP_MODE_SV48X4) {
    pr_err("[GSTAGE] MODE=%d (Sv48x4 아님)\n", mode);
    return;
  }
  phys_addr_t root_pa = hgatp_root_pa();
  //unsigned bank = gstage_bank(gpa, mode);
  //phys_addr_t bank_root_pa = root_pa + (phys_addr_t)bank * PAGE_SIZE;
  pgd_t *pgd = phys_to_virt(root_pa);

  unsigned vpn3 = (gpa >> 39) & 0x1FF; // PGD
  unsigned vpn2 = (gpa >> 30) & 0x1FF; // PUD
  unsigned vpn1 = (gpa >> 21) & 0x1FF; // PMD
  unsigned vpn0 = (gpa >> 12) & 0x1FF; // PTE

  pr_info("[GSTAGE] Sv48x4 dump gpa=%#lx root_pa=%pa va=%px\n",
          gpa, &root_pa, pgd);

  /* PGD */
  unsigned long e3 = pgd_val(pgd[vpn3]);
  pr_info(" PGD[%u] kva=%px ", vpn3, &pgd[vpn3]); print_pte_bits("", e3);
  if (!(e3 & _PAGE_VALID)) { pr_err("  PGD miss\n"); return; }
  if (is_leaf(e3)) { pr_err("  PGD leaf는 비정상(512GiB)\n"); return; }

  /* PUD table */
  pud_t *pud = phys_to_virt(next_table_pa(e3));
  pr_info(" PUD page: pa=%pa va=%px\n", (phys_addr_t[]){ next_table_pa(e3) }, pud);

  /* PUD */
  unsigned long e2 = pud_val(pud[vpn2]);
  pr_info(" PUD[%u] kva=%px ", vpn2, &pud[vpn2]); print_pte_bits("", e2);
  if (!(e2 & _PAGE_VALID)) { pr_err("  PUD miss\n"); return; }
  if (is_leaf(e2)) { pr_info("  LEAF@PUD (1GiB)\n"); return; } // 의도치 않으면 버그

  /* PMD table */
  pmd_t *pmd = phys_to_virt(next_table_pa(e2));
  pr_info(" PMD page: pa=%pa va=%px\n", (phys_addr_t[]){ next_table_pa(e2) }, pmd);

  /* PMD */
  unsigned long e1 = pmd_val(pmd[vpn1]);
  pr_info(" PMD[%u] kva=%px ", vpn1, &pmd[vpn1]); print_pte_bits("", e1);
  if (!(e1 & _PAGE_VALID)) { pr_err("  PMD miss\n"); return; }
  if (is_leaf(e1)) { pr_info("  LEAF@PMD (2MiB)\n"); return; } // 2MiB 의도면 여기서 끝

  /* PTE table */
  pte_t *pt = phys_to_virt(next_table_pa(e1));
  pr_info(" PTE page: pa=%pa va=%px\n", (phys_addr_t[]){ next_table_pa(e1) }, pt);

  /* PTE */
  unsigned long e0 = pte_val(pt[vpn0]);
  pr_info(" PTE[%u] kva=%px ", vpn0, &pt[vpn0]); print_pte_bits("", e0);
  if (!(e0 & _PAGE_VALID)) { pr_err("  PTE miss\n"); return; }
  if (!is_leaf(e0)) { pr_err("  PTE not leaf\n"); return; }
  pr_info("  LEAF@PTE (4KiB)\n");
}

static __always_inline int safe_hlvx_wu(u32 *out, unsigned long gpa)
{
    unsigned long val;
    long err;

    asm volatile(
        "0: .option push\n"
        "   .option norvc\n"
        "   hlvx.wu %0, (%2)\n"
        "   .option pop\n"
        "1:\n"
        "   li %1, 0\n"
        "2:\n"

        ".pushsection .fixup,\"ax\"\n"
        "3:\n"
        "   li %1, %3\n"
        "   j 2b\n"
        ".popsection\n"

        _ASM_EXTABLE(0b, 3b)

        : "=&r"(val), "=&r"(err)
        : "r"(gpa), "i"(-EFAULT)
        : "memory");

    if (!err)
        *out = (u32)val;
    return (int)err;
}

static __always_inline int safe_hsv_d(unsigned long gpa, u64 val)
{
    long err;

    asm volatile(
        "0: .option push\n"
        "   .option norvc\n"
        "   hsv.d %1, (%2)\n"
        "   .option pop\n"
        "1:\n"
        "   li %0, 0\n"
        "2:\n"

        ".pushsection .fixup,\"ax\"\n"
        "3:\n"
        "   li %0, %3\n"
        "   j 2b\n"
        ".popsection\n"

        _ASM_EXTABLE(0b, 3b)

        : "=&r"(err)                  /* %0: 오류코드 */
        : "r"(val),                   /* %1: 저장할 값 */
          "r"(gpa),                   /* %2: guest PA */
          "i"(-EFAULT)                /* %3: 에러 상수 */
        : "memory");

    return (int)err;
}

static __always_inline int safe_hlv_d(u64 *out, unsigned long gpa)
{
    u64 val;
    long err;

    asm volatile(
        "0: .option push\n"
        "   .option norvc\n"
        "   hlv.d %0, (%2)\n"
        "   .option pop\n"
        "1:\n"
        "   li %1, 0\n"
        "2:\n"

        ".pushsection .fixup,\"ax\"\n"
        "3:\n"
        "   li %1, %3\n"
        "   j 2b\n"
        ".popsection\n"

        _ASM_EXTABLE(0b, 3b)

        : "=&r"(val), "=&r"(err)
        : "r"(gpa), "i"(-EFAULT)
        : "memory");

    if (!err)
        *out = val;
    return (int)err;
}

void __init genesis_test(void)
{
	void *p, *p2;
	int *p5, *shadow_p5;

	struct page *pgd_page;
        pgd_page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
                                get_order(gstage_pgd_size));
	pgd_t *gpgd = page_address(pgd_page);
	unsigned long ppn = page_to_phys(pgd_page) >> PAGE_SHIFT;

	unsigned long hgatp = (HGATP_MODE_SV48X4 << HGATP_MODE_SHIFT)
                    | (ppn & GENMASK_ULL(43, 0));  // 44b 마스크
	csr_write(CSR_HGATP, hgatp);

	csr_write(CSR_VSSTATUS, 0);
	csr_write(CSR_VSATP, 0);

	/* HGATP 쓴 직후와, 매핑 쓴 직후 모두 hfence.gvma */
	asm volatile("hfence.gvma x0, x0" ::: "memory");
	asm volatile("hfence.vvma x0, x0" ::: "memory");
	asm volatile("sfence.vma x0, x0" ::: "memory");


	pr_info("[GENESIS] TEST CODE START\n");
	pr_info("[GENESIS] TEST 1. GFP_GENESIS ");
	p = (void *)__get_free_page(GFP_KERNEL);
	pr_info("p1 va: 0x%px pa: 0x%lx (GFP_KERNEL)\n", p, __pa(p));
	p2 = (void *)__get_free_page(GFP_KERNEL);
	pr_info("p2 va: 0x%px pa: 0x%lx (GFP_KERNEL)\n", p2, __pa(p2));
	free_page((unsigned long int)p);
	free_page((unsigned long int)p2);

	p5 = (int *)__get_free_page(__GFP_GENESIS);
	pr_info("p5 va: 0x%px pa: 0x%lx (GFP_GENESIS)\n", p5, __pa(p5));

	pr_info("[GENESIS] TEST 2. SHADOW MAPPING ");
	pr_info("addr: %px, shadow_addr: %lx\n", p5, __virt_to_shadow(p5));
	*p5 = 1234; // okay
	shadow_p5 = (int *)__virt_to_shadow(p5);
	__enable_user_access();
	*shadow_p5 = 12345;
	pr_info("addr val: %d, shadow val: %d\n", *p5, *shadow_p5);
	__disable_user_access();
	free_page((unsigned long int)p5);

	pr_info("[GENESIS] TEST CODE END\n");

	pr_info("[DITO] GUEST ADDRESS SPACE TEST\n");
	unsigned long gpa = 0x1000UL;
	int mode = (csr_read(CSR_HGATP) >> HGATP_MODE_SHIFT) & 0xF;
	pgprot_t prot = __pgprot(0x0dfUL);
	create_pgd_mapping(gpgd, gpa, 0x100000000, PUD_SIZE, prot);
	u64 data = 0x12345ULL;
	u64 val = 0;
	safe_hsv_d(gpa, data);
	safe_hlv_d(&val, gpa);
	pr_info("[DITO] HLV.D result : val=%#llx\n", val);
	gstage_dump_walk_gpa_sv48x4(gpa);

	/*
	void *p3 = (void *)__get_free_page(GFP_KERNEL | GFP_DMA32 | __GFP_ZERO);
	phys_addr_t pa = __pa(p3);
	unsigned long gpa = 0x8000000000UL;

	int mode = (csr_read(CSR_HGATP) >> HGATP_MODE_SHIFT) & 0xF;
	unsigned bank = (mode == HGATP_MODE_SV39X4) ? ((gpa >> 40) & 3) : ((gpa >> 52) & 3);
	pgd_t *gpgd_bank = (pgd_t *)((char *)gpgd + bank * PAGE_SIZE);
	pgprot_t prot = __pgprot(0x0dfUL);
	create_pgd_mapping(gpgd_bank, gpa, pa, PAGE_SIZE,
                   prot);
	asm volatile("hfence.gvma x0, x0" ::: "memory");
	asm volatile("hfence.vvma x0, x0" ::: "memory");
	asm volatile("sfence.vma x0, x0" ::: "memory");
	pr_info("[DITO] pa=%#llx gpa=%#lx hva=%#lx\n", (unsigned long long)pa, gpa, (unsigned long long)p3);

	*(u64 *)p3 = 0x111111111ULL;
	u64 val = 0;
	u32 val32 = 0;
	unsigned long sc = csr_read(CSR_SCAUSE);
	unsigned long sv = csr_read(CSR_STVAL);
	unsigned long hv = csr_read(CSR_HTVAL);
	unsigned long hs = csr_read(CSR_HSTATUS);
	unsigned long vsatp = csr_read(CSR_VSATP);
	unsigned long hg = csr_read(CSR_HGATP);
	unsigned long satp = csr_read(CSR_SATP);
	pr_info("[DITO] before HSV HLV fault: scause=%#lx stval=%#lx htval=%#lx hstatus=%#lx vsatp=%#lx hgatp=%#lx satp=%#lx\n", sc, sv, hv, hs, vsatp, hg, satp);
	u64 data = 0xdeadbeefcafebabeULL;
	if (safe_hsv_d(gpa, data))
    		pr_err("HSV.D fault!\n");
	else
    		pr_info("HSV.D success\n");
	sc = csr_read(CSR_SCAUSE);
	sv = csr_read(CSR_STVAL);
	hv = csr_read(CSR_HTVAL);
	hs = csr_read(CSR_HSTATUS);
	vsatp = csr_read(CSR_VSATP);
	hg = csr_read(CSR_HGATP);
	satp = csr_read(CSR_SATP);
	pr_info("[DITO] after HSV fault: scause=%#lx stval=%#lx htval=%#lx hstatus=%#lx vsatp=%#lx hgatp=%#lx satp=%#lx\n", sc, sv, hv, hs, vsatp, hg, satp);
	int rc = safe_hlv_d(&val, gpa);
	if (rc)
	    pr_err("HLV.D fault again: rc=%d gpa=%#lx (expect PTE above)\n", rc, gpa);
	else
	    pr_info("HLV.D OK: val=%#llx\n", val);
	sc = csr_read(CSR_SCAUSE);
	sv = csr_read(CSR_STVAL);
	hv = csr_read(CSR_HTVAL);
	hs = csr_read(CSR_HSTATUS);
	vsatp = csr_read(CSR_VSATP);
	hg = csr_read(CSR_HGATP);
	satp = csr_read(CSR_SATP);
	pr_info("[DITO] after HLV fault: scause=%#lx stval=%#lx htval=%#lx hstatus=%#lx vsatp=%#lx hgatp=%#lx satp=%#lx\n", sc, sv, hv, hs, vsatp, hg, satp);
	rc = safe_hlvx_wu(&val32, gpa);
        if (rc)
            pr_err("HLV.D fault again: rc=%d gpa=%#lx (expect PTE above)\n", rc, gpa);
        else
            pr_info("HLV.D OK: val=%#llx\n", val);
        sc = csr_read(CSR_SCAUSE);
        sv = csr_read(CSR_STVAL);
        hv = csr_read(CSR_HTVAL);
        hs = csr_read(CSR_HSTATUS);
        vsatp = csr_read(CSR_VSATP);
        hg = csr_read(CSR_HGATP);
        satp = csr_read(CSR_SATP);
        pr_info("[DITO] after HLVX fault: scause=%#lx stval=%#lx htval=%#lx hstatus=%#lx vsatp=%#lx hgatp=%#lx satp=%#lx\n", sc, sv, hv, hs, vsatp, hg, satp);

	sstage_dump_walk_kva_sv48((unsigned long)p3);
	gstage_dump_walk_gpa_sv48x4(gpa);
	*/
}

void __init genesis_zone_set_readonly(void)
{
	unsigned long base;
	int numpages;
	int ret;

	base = (unsigned long)__va(0x100000000);
	numpages = GENESIS_ZONE_SZ + DITO_ZONE_SZ;

#if (GENESIS_DEBUG)
	pr_info("[GENESIS] Mark GENESIS_ZONE as read-only "
		"0x%lx - 0x%lx\n", base, base + (numpages << PAGE_SHIFT));
#endif

	ret = set_memory_rw(base, numpages);
	if (ret)
		panic("[GENESIS] failed to mark readonly!");
}

void __init genesis_init(void)
{
	pr_info("[GENESIS] TEXT BEGIN: %px, END: %px\n", __genesis_text_begin,
					       __genesis_text_end);

#if (GENESIS_DEBUG)
	genesis_test();
#endif

#if (0) // Disable in QEMU
	set_kernel_memory(__privinst_begin, __privinst_end,
			  set_memory_u_x);
#endif

	genesis_enabled = 1;

	genesis_zone_set_readonly();
}
