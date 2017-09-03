#ifndef MM_H
#define MM_H

struct file;

typedef struct {
  unsigned long pgprot;
} pgprot_t;

struct rb_node {
	unsigned long  __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

struct vm_area_struct {

	unsigned long vm_start;
	unsigned long vm_end;
	struct vm_area_struct *vm_next, *vm_prev;
	struct rb_node vm_rb;
	unsigned long rb_subtree_gap;
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	unsigned long vm_flags;

};

void *get_remap_pfn_range_address(void);

#endif /* MM_H */