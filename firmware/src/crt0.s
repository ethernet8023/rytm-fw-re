/* crt0.s - Analog Rytm MKII replacement OS entry
 *
 * Boot contract (RE'd from stock OS 1.74 + bootstrap):
 *  1. bootstrap decompresses image to 0x40000400
 *  2. bootstrap fills the 1KB vector region at 0x40000000 with its default
 *     handler and sets VBR = 0x40000000
 *  3. bootstrap does: a0 = *(u32*)0x40000400; push arg; jsr (a0)
 *
 * Stock OS entry (0x40000870) then:
 *  - saves the stack arg, switches SP to 0x48000000
 *  - refills the 256 vectors at 0x40000000 with ITS default handler
 *    (fn_14ae @0x400014ae), re-sets VBR (fn_14cc)
 *  - initializes INTC/GPIO (fn_690 @0x40000690)
 *  - jumps into kernel bring-up and never returns
 *
 * This crt0 mirrors that sequence with our own tables/handlers.
 */

    .section .header.entry, "ax"
    .long _start            /* image word[0]: bootstrap calls this */

    .text
    .globl _start
    .type _start, @function
_start:
    /* we are called: return addr on stack, arg at sp@(4) */
    move.w  #0x2700, %sr

    /* own stack: stock OS uses 0x48000000 (top of the upper DDR region) */
    move.l  #0x48000000, %sp

    /* refill the 256 vectors at 0x40000000 with our default handler,
       mirroring stock fn_14ae */
    move.l  #0x40000000, %a0
    move.l  #default_handler, %d1
    moveq   #0, %d0
1:  move.l  %d1, (%a0,%d0:l*4)
    addq.l  #1, %d0
    cmpi.l  #256, %d0
    jne     1b

    /* install specific vectors (v[1] reset PC, v[2] bus err, v[3] addr err) */
    move.l  #0x40000000, %a0
    move.l  #_start, %d1
    move.l  %d1, 4(%a0)               /* v[1] */
    move.l  #fault_bus, %d1
    move.l  %d1, 8(%a0)               /* v[2] */
    move.l  #fault_addr, %d1
    move.l  %d1, 12(%a0)              /* v[3] */

    /* VBR = 0x40000000 (stock fn_14cc) */
    move.l  #0x40000000, %d0
    movec   %d0, %vbr

    /* zero .bss */
    move.l  #__bss_start, %a0
    move.l  #__bss_end, %a1
2:  cmp.l   %a0, %a1
    jbeq    3f
    clr.l   (%a0)+
    jra     2b

3:  /* run static constructors (.init_array) */
    move.l  #__init_array_start, %a0
    move.l  #__init_array_end, %a1
4:  cmp.l   %a0, %a1
    jbeq    5f
    move.l  (%a0)+, %a2
    jsr     (%a2)
    jra     4b

5:  jbsr    main
    /* main must not return; if it does: safe halt */
6:  move.w  #0x2700, %sr
    stop    #0x2700
    jra     6b

    .size _start, . - _start

/* ---- exception handlers ---- */
    .text
    .globl default_handler
default_handler:
    rte

    .globl fault_bus
fault_bus:
    /* park on a known value so a crash is diagnosable: spin with d0=0xBADC0DE */
    move.l  #0x0badc0de, %d0
1:  jra 1b

    .globl fault_addr
fault_addr:
    move.l  #0x0addc0de, %d0
1:  jra 1b
