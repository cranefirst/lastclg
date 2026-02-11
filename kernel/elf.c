#include "elf.h"
#include "string.h"
#include "riscv.h"
#include "vmm.h"
#include "pmm.h"
#include "vfs.h"
#include "spike_interface/spike_utils.h"

typedef struct elf_info_t {
  struct file *f;
  process *p;
} elf_info;

//
// the implementation of allocater. allocates memory space for later segment loading.
// this allocater is heavily modified @lab2_1, where we do NOT work in bare mode.
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size) {
  elf_info *msg = (elf_info *)ctx->info;
  // we assume that size of proram segment is smaller than a page.
  kassert(size < PGSIZE);
  void *pa = alloc_page();
  if (pa == 0) panic("uvmalloc mem alloc falied\n");

  memset((void *)pa, 0, PGSIZE);
  user_vm_map((pagetable_t)msg->p->pagetable, elf_va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ | PROT_EXEC, 1));

  return pa;
}

//
// actual file reading, using the vfs file interface.
//
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
  elf_info *msg = (elf_info *)ctx->info;
  vfs_lseek(msg->f, offset, SEEK_SET);
  return vfs_read(msg->f, dest, nb);
}

//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info) {
  ctx->info = info;

  // load the elf header
  if (elf_fpread(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr)) return EL_EIO;

  // check the signature (magic value) of the elf
  if (ctx->ehdr.magic != ELF_MAGIC) return EL_NOTELF;

  return EL_OK;
}

//
// load the elf segments to memory regions.
//
elf_status elf_load(elf_ctx *ctx) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr __attribute__((aligned(16)));
  int i, off;

  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;

    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    // allocate memory block before elf loading
    // 检查是否已经存在映射，如果存在则先取消映射（针对 exec 场景的二次检查）
    if (lookup_pa(((process*)(((elf_info*)(ctx->info))->p))->pagetable, ph_addr.vaddr) != 0) {
      user_vm_unmap(((process*)(((elf_info*)(ctx->info))->p))->pagetable, ph_addr.vaddr, PGSIZE, 1);
    }
    void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

    // actual loading
    if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;

    // record the vm region in proc->mapped_info. added @lab3_1
    int j;
    for( j=0; j<PGSIZE/sizeof(mapped_region); j++ ) //seek the last mapped region
      if( (process*)(((elf_info*)(ctx->info))->p)->mapped_info[j].va == 0x0 ) break;

    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].va = ph_addr.vaddr;
    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].npages = 1;

    // SEGMENT_READABLE, SEGMENT_EXECUTABLE, SEGMENT_WRITABLE are defined in kernel/elf.h
    if( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = CODE_SEGMENT;
      sprint( "CODE_SEGMENT added at mapped info offset:%d\n", j );
    }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = DATA_SEGMENT;
      sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
    }else
      panic( "unknown program segment encountered, segment flag:%d.\n", ph_addr.flags );

    ((process*)(((elf_info*)(ctx->info))->p))->total_mapped_region ++;
  }

  return EL_OK;
}

//
// load the elf of user application, by using the spike file interface.
void load_bincode_from_host_elf(process *p, char *filename, char *para) {
  sprint("Application: %s\n", filename);

  // 【修复】elfloader 增加对齐，防止 Misaligned AMO!
  elf_ctx elfloader __attribute__((aligned(16)));
  elf_info info;

  info.f = vfs_open(filename, O_RDONLY);
  info.p = p;
  if (IS_ERR_VALUE(info.f)) panic("Fail on openning the input application program.\n");

  if (elf_init(&elfloader, &info) != EL_OK) panic("fail to init elfloader.\n");
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  p->trapframe->epc = elfloader.ehdr.entry;
  vfs_close(info.f);

  // --- 【关键修复：构造标准 argv 数组】 ---
  uint64 sp = p->trapframe->regs.sp;

  // a. 首先将参数字符串和文件名字符串压入栈顶
  // 我们预留空间并确保 16 字节对齐
  sp -= 256; 
  sp &= ~0xF;

  // 物理地址转换，用于内核写入
  char *stack_pa = (char *)user_va_to_pa(p->pagetable, (void *)sp);
  
  // 在栈上分配空间存放字符串内容
  char *argv0_str = stack_pa;           // argv[0] 放在前面
  char *argv1_str = stack_pa + 128;     // argv[1] 放在后面
  strcpy(argv0_str, filename);
  if (para) strcpy(argv1_str, para);

  // 计算这些字符串在用户态的虚拟地址
  uint64 argv0_va = sp;
  uint64 argv1_va = sp + 128;

  // b. 构造指针数组 argv[] = {argv0_va, argv1_va, NULL}
  sp -= 32; 
  sp &= ~0xF;
  uint64 *argv_array_pa = (uint64 *)user_va_to_pa(p->pagetable, (void *)sp);
  
  argv_array_pa[0] = argv0_va;
  if (para) {
    argv_array_pa[1] = argv1_va;
    argv_array_pa[2] = 0;
    p->trapframe->regs.a0 = 2;
  } else {
    argv_array_pa[1] = 0;
    p->trapframe->regs.a0 = 1;
  }

  // c. 正确设置寄存器：a0=argc, a1=argv(数组首地址)
  p->trapframe->regs.a1 = sp;             // argv (指向指针数组的指针)
  p->trapframe->regs.sp = sp;             // 更新用户栈指针

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}