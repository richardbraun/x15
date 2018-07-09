/*
 * Copyright (c) 2011-2018 Richard Braun.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <kern/init.h>
#include <machine/asm.h>
#include <machine/cpu.h>

#define CPU_RED_ZONE_SIZE 128

.text

#ifdef __LP64__

.macro cpu_ll_exc_store_registers
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rdi
    pushq %rsi
    pushq %rbp
    pushq %rdx
    pushq %rcx
    pushq %rbx
    pushq %rax
.endm

.macro cpu_ll_exc_load_registers
    popq %rax
    popq %rbx
    popq %rcx
    popq %rdx
    popq %rbp
    popq %rsi
    popq %rdi
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    addq $16, %rsp              /* skip vector and error */
.endm

.macro cpu_ll_exc_push_word source offset buffer
    movq -\offset(\source), \buffer
    pushq \buffer
.endm

.macro cpu_ll_exc_push source nr_words buffer
.set offset, 8
.rept \nr_words
    cpu_ll_exc_push_word \source offset \buffer
.set offset, offset + 8
.endr
.endm

.macro cpu_ll_exc_enter vector
    pushq %rbx                  /* save registers used for stack switching */
    pushq %rax
    leaq 64(%rsp), %rbx         /* point to the top of the exception frame */
    movq -16(%rbx), %rsp        /* point to the thread stack */
    subq $CPU_RED_ZONE_SIZE, %rsp
    cpu_ll_exc_push %rbx 6 %rax
    movq -64(%rbx), %rax        /* restore registers used for stack switching */
    movq -56(%rbx), %rbx
    pushq $\vector
    cpu_ll_exc_store_registers
    xorq %rbp, %rbp             /* block stack tracing */
    movq %rsp, %rbx             /* save frame */
.endm

.macro cpu_ll_exc_leave
    movq %rbx, %rsp             /* restore stack */
    call thread_schedule        /* schedule threads */
    cpu_ll_exc_load_registers
    iretq
.endm

.macro cpu_ll_exc_handle vector
    cpu_ll_exc_enter \vector
    movq %rbx, %rdi
    call cpu_exc_main
    cpu_ll_exc_leave
.endm

.macro cpu_ll_intr_handle vector
    cpu_ll_exc_enter \vector
    call cpu_get_intr_stack_ptr
    movq %rax, %rsp             /* switch to interrupt stack */
    movq %rbx, %rdi
    call cpu_intr_main
    cpu_ll_exc_leave
.endm

#else /* __LP64__ */

.macro cpu_ll_exc_store_registers
    pushw %gs
    pushw %fs
    pushw %es
    pushw %ds
    pushl %edi
    pushl %esi
    pushl %ebp
    pushl %edx
    pushl %ecx
    pushl %ebx
    pushl %eax
.endm

/* XXX Don't load segment registers for now */
.macro cpu_ll_exc_load_registers
    popl %eax
    popl %ebx
    popl %ecx
    popl %edx
    popl %ebp
    popl %esi
    popl %edi
    addl $16, %esp              /* skip segment registers, vector and error */
.endm

.macro cpu_ll_exc_enter vector
    pushl $\vector
    cpu_ll_exc_store_registers
    xorl %ebp, %ebp             /* block stack tracing */
    movl %esp, %ebx             /* save frame */
.endm

.macro cpu_ll_exc_leave
    movl %ebx, %esp             /* restore stack */
    call thread_schedule        /* schedule threads */
    cpu_ll_exc_load_registers
    iretl
.endm

.macro cpu_ll_exc_handle vector
    cpu_ll_exc_enter \vector
    pushl %ebx
    call cpu_exc_main
    cpu_ll_exc_leave
.endm

.macro cpu_ll_intr_handle vector
    cpu_ll_exc_enter \vector
    call cpu_get_intr_stack_ptr
    movl %eax, %esp             /* switch to interrupt stack */
    pushl %ebx
    call cpu_intr_main
    cpu_ll_exc_leave
.endm

#endif /* __LP64__ */

#define CPU_LL_EXC_HANDLER(vector, name)            \
ASM_ENTRY(name)                                     \
    push $0;                                        \
    cpu_ll_exc_handle vector;                       \
ASM_END(name)

#define CPU_LL_EXC_HANDLER_WITH_ERROR(vector, name) \
ASM_ENTRY(name)                                     \
    cpu_ll_exc_handle vector;                       \
ASM_END(name)

#define CPU_LL_INTR_HANDLER(vector, name)           \
ASM_ENTRY(name)                                     \
    push $0;                                        \
    cpu_ll_intr_handle vector;                      \
ASM_END(name)

/*
 * Low level handlers for architectural exceptions.
 */
CPU_LL_EXC_HANDLER(CPU_EXC_DE, cpu_ll_exc_divide_error)
CPU_LL_EXC_HANDLER(CPU_EXC_DB, cpu_ll_exc_debug)
CPU_LL_INTR_HANDLER(CPU_EXC_NMI, cpu_ll_exc_nmi)
CPU_LL_EXC_HANDLER(CPU_EXC_BP, cpu_ll_exc_breakpoint)
CPU_LL_EXC_HANDLER(CPU_EXC_OF, cpu_ll_exc_overflow)
CPU_LL_EXC_HANDLER(CPU_EXC_BR, cpu_ll_exc_bound_range)
CPU_LL_EXC_HANDLER(CPU_EXC_UD, cpu_ll_exc_undefined_opcode)
CPU_LL_EXC_HANDLER(CPU_EXC_NM, cpu_ll_exc_no_math_coprocessor)
CPU_LL_EXC_HANDLER_WITH_ERROR(CPU_EXC_DF, cpu_ll_exc_double_fault)
CPU_LL_EXC_HANDLER_WITH_ERROR(CPU_EXC_TS, cpu_ll_exc_invalid_tss)
CPU_LL_EXC_HANDLER_WITH_ERROR(CPU_EXC_NP, cpu_ll_exc_segment_not_present)
CPU_LL_EXC_HANDLER_WITH_ERROR(CPU_EXC_SS, cpu_ll_exc_stack_segment_fault)
CPU_LL_EXC_HANDLER_WITH_ERROR(CPU_EXC_GP, cpu_ll_exc_general_protection)
CPU_LL_EXC_HANDLER_WITH_ERROR(CPU_EXC_PF, cpu_ll_exc_page_fault)
CPU_LL_EXC_HANDLER(CPU_EXC_MF, cpu_ll_exc_math_fault)
CPU_LL_EXC_HANDLER_WITH_ERROR(CPU_EXC_AC, cpu_ll_exc_alignment_check)
CPU_LL_INTR_HANDLER(CPU_EXC_MC, cpu_ll_exc_machine_check)
CPU_LL_EXC_HANDLER(CPU_EXC_XM, cpu_ll_exc_simd_fp_exception)

/*
 * Low level handlers for reserved exceptions.
 *
 * These exceptions should normally never occur, but have handlers ready just
 * in case.
 */
CPU_LL_EXC_HANDLER(9, cpu_ll_exc_9)
CPU_LL_EXC_HANDLER(15, cpu_ll_exc_15)
CPU_LL_EXC_HANDLER(20, cpu_ll_exc_20)
CPU_LL_EXC_HANDLER(21, cpu_ll_exc_21)
CPU_LL_EXC_HANDLER(22, cpu_ll_exc_22)
CPU_LL_EXC_HANDLER(23, cpu_ll_exc_23)
CPU_LL_EXC_HANDLER(24, cpu_ll_exc_24)
CPU_LL_EXC_HANDLER(25, cpu_ll_exc_25)
CPU_LL_EXC_HANDLER(26, cpu_ll_exc_26)
CPU_LL_EXC_HANDLER(27, cpu_ll_exc_27)
CPU_LL_EXC_HANDLER(28, cpu_ll_exc_28)
CPU_LL_EXC_HANDLER(29, cpu_ll_exc_29)
CPU_LL_EXC_HANDLER(30, cpu_ll_exc_30)
CPU_LL_EXC_HANDLER(31, cpu_ll_exc_31)

/* Generic low level interrupt handlers */
CPU_LL_INTR_HANDLER(32, cpu_ll_exc_32)
CPU_LL_INTR_HANDLER(33, cpu_ll_exc_33)
CPU_LL_INTR_HANDLER(34, cpu_ll_exc_34)
CPU_LL_INTR_HANDLER(35, cpu_ll_exc_35)
CPU_LL_INTR_HANDLER(36, cpu_ll_exc_36)
CPU_LL_INTR_HANDLER(37, cpu_ll_exc_37)
CPU_LL_INTR_HANDLER(38, cpu_ll_exc_38)
CPU_LL_INTR_HANDLER(39, cpu_ll_exc_39)
CPU_LL_INTR_HANDLER(40, cpu_ll_exc_40)
CPU_LL_INTR_HANDLER(41, cpu_ll_exc_41)
CPU_LL_INTR_HANDLER(42, cpu_ll_exc_42)
CPU_LL_INTR_HANDLER(43, cpu_ll_exc_43)
CPU_LL_INTR_HANDLER(44, cpu_ll_exc_44)
CPU_LL_INTR_HANDLER(45, cpu_ll_exc_45)
CPU_LL_INTR_HANDLER(46, cpu_ll_exc_46)
CPU_LL_INTR_HANDLER(47, cpu_ll_exc_47)
CPU_LL_INTR_HANDLER(48, cpu_ll_exc_48)
CPU_LL_INTR_HANDLER(49, cpu_ll_exc_49)
CPU_LL_INTR_HANDLER(50, cpu_ll_exc_50)
CPU_LL_INTR_HANDLER(51, cpu_ll_exc_51)
CPU_LL_INTR_HANDLER(52, cpu_ll_exc_52)
CPU_LL_INTR_HANDLER(53, cpu_ll_exc_53)
CPU_LL_INTR_HANDLER(54, cpu_ll_exc_54)
CPU_LL_INTR_HANDLER(55, cpu_ll_exc_55)
CPU_LL_INTR_HANDLER(56, cpu_ll_exc_56)
CPU_LL_INTR_HANDLER(57, cpu_ll_exc_57)
CPU_LL_INTR_HANDLER(58, cpu_ll_exc_58)
CPU_LL_INTR_HANDLER(59, cpu_ll_exc_59)
CPU_LL_INTR_HANDLER(60, cpu_ll_exc_60)
CPU_LL_INTR_HANDLER(61, cpu_ll_exc_61)
CPU_LL_INTR_HANDLER(62, cpu_ll_exc_62)
CPU_LL_INTR_HANDLER(63, cpu_ll_exc_63)
CPU_LL_INTR_HANDLER(64, cpu_ll_exc_64)
CPU_LL_INTR_HANDLER(65, cpu_ll_exc_65)
CPU_LL_INTR_HANDLER(66, cpu_ll_exc_66)
CPU_LL_INTR_HANDLER(67, cpu_ll_exc_67)
CPU_LL_INTR_HANDLER(68, cpu_ll_exc_68)
CPU_LL_INTR_HANDLER(69, cpu_ll_exc_69)
CPU_LL_INTR_HANDLER(70, cpu_ll_exc_70)
CPU_LL_INTR_HANDLER(71, cpu_ll_exc_71)
CPU_LL_INTR_HANDLER(72, cpu_ll_exc_72)
CPU_LL_INTR_HANDLER(73, cpu_ll_exc_73)
CPU_LL_INTR_HANDLER(74, cpu_ll_exc_74)
CPU_LL_INTR_HANDLER(75, cpu_ll_exc_75)
CPU_LL_INTR_HANDLER(76, cpu_ll_exc_76)
CPU_LL_INTR_HANDLER(77, cpu_ll_exc_77)
CPU_LL_INTR_HANDLER(78, cpu_ll_exc_78)
CPU_LL_INTR_HANDLER(79, cpu_ll_exc_79)
CPU_LL_INTR_HANDLER(80, cpu_ll_exc_80)
CPU_LL_INTR_HANDLER(81, cpu_ll_exc_81)
CPU_LL_INTR_HANDLER(82, cpu_ll_exc_82)
CPU_LL_INTR_HANDLER(83, cpu_ll_exc_83)
CPU_LL_INTR_HANDLER(84, cpu_ll_exc_84)
CPU_LL_INTR_HANDLER(85, cpu_ll_exc_85)
CPU_LL_INTR_HANDLER(86, cpu_ll_exc_86)
CPU_LL_INTR_HANDLER(87, cpu_ll_exc_87)
CPU_LL_INTR_HANDLER(88, cpu_ll_exc_88)
CPU_LL_INTR_HANDLER(89, cpu_ll_exc_89)
CPU_LL_INTR_HANDLER(90, cpu_ll_exc_90)
CPU_LL_INTR_HANDLER(91, cpu_ll_exc_91)
CPU_LL_INTR_HANDLER(92, cpu_ll_exc_92)
CPU_LL_INTR_HANDLER(93, cpu_ll_exc_93)
CPU_LL_INTR_HANDLER(94, cpu_ll_exc_94)
CPU_LL_INTR_HANDLER(95, cpu_ll_exc_95)
CPU_LL_INTR_HANDLER(96, cpu_ll_exc_96)
CPU_LL_INTR_HANDLER(97, cpu_ll_exc_97)
CPU_LL_INTR_HANDLER(98, cpu_ll_exc_98)
CPU_LL_INTR_HANDLER(99, cpu_ll_exc_99)
CPU_LL_INTR_HANDLER(100, cpu_ll_exc_100)
CPU_LL_INTR_HANDLER(101, cpu_ll_exc_101)
CPU_LL_INTR_HANDLER(102, cpu_ll_exc_102)
CPU_LL_INTR_HANDLER(103, cpu_ll_exc_103)
CPU_LL_INTR_HANDLER(104, cpu_ll_exc_104)
CPU_LL_INTR_HANDLER(105, cpu_ll_exc_105)
CPU_LL_INTR_HANDLER(106, cpu_ll_exc_106)
CPU_LL_INTR_HANDLER(107, cpu_ll_exc_107)
CPU_LL_INTR_HANDLER(108, cpu_ll_exc_108)
CPU_LL_INTR_HANDLER(109, cpu_ll_exc_109)
CPU_LL_INTR_HANDLER(110, cpu_ll_exc_110)
CPU_LL_INTR_HANDLER(111, cpu_ll_exc_111)
CPU_LL_INTR_HANDLER(112, cpu_ll_exc_112)
CPU_LL_INTR_HANDLER(113, cpu_ll_exc_113)
CPU_LL_INTR_HANDLER(114, cpu_ll_exc_114)
CPU_LL_INTR_HANDLER(115, cpu_ll_exc_115)
CPU_LL_INTR_HANDLER(116, cpu_ll_exc_116)
CPU_LL_INTR_HANDLER(117, cpu_ll_exc_117)
CPU_LL_INTR_HANDLER(118, cpu_ll_exc_118)
CPU_LL_INTR_HANDLER(119, cpu_ll_exc_119)
CPU_LL_INTR_HANDLER(120, cpu_ll_exc_120)
CPU_LL_INTR_HANDLER(121, cpu_ll_exc_121)
CPU_LL_INTR_HANDLER(122, cpu_ll_exc_122)
CPU_LL_INTR_HANDLER(123, cpu_ll_exc_123)
CPU_LL_INTR_HANDLER(124, cpu_ll_exc_124)
CPU_LL_INTR_HANDLER(125, cpu_ll_exc_125)
CPU_LL_INTR_HANDLER(126, cpu_ll_exc_126)
CPU_LL_INTR_HANDLER(127, cpu_ll_exc_127)
CPU_LL_INTR_HANDLER(128, cpu_ll_exc_128)
CPU_LL_INTR_HANDLER(129, cpu_ll_exc_129)
CPU_LL_INTR_HANDLER(130, cpu_ll_exc_130)
CPU_LL_INTR_HANDLER(131, cpu_ll_exc_131)
CPU_LL_INTR_HANDLER(132, cpu_ll_exc_132)
CPU_LL_INTR_HANDLER(133, cpu_ll_exc_133)
CPU_LL_INTR_HANDLER(134, cpu_ll_exc_134)
CPU_LL_INTR_HANDLER(135, cpu_ll_exc_135)
CPU_LL_INTR_HANDLER(136, cpu_ll_exc_136)
CPU_LL_INTR_HANDLER(137, cpu_ll_exc_137)
CPU_LL_INTR_HANDLER(138, cpu_ll_exc_138)
CPU_LL_INTR_HANDLER(139, cpu_ll_exc_139)
CPU_LL_INTR_HANDLER(140, cpu_ll_exc_140)
CPU_LL_INTR_HANDLER(141, cpu_ll_exc_141)
CPU_LL_INTR_HANDLER(142, cpu_ll_exc_142)
CPU_LL_INTR_HANDLER(143, cpu_ll_exc_143)
CPU_LL_INTR_HANDLER(144, cpu_ll_exc_144)
CPU_LL_INTR_HANDLER(145, cpu_ll_exc_145)
CPU_LL_INTR_HANDLER(146, cpu_ll_exc_146)
CPU_LL_INTR_HANDLER(147, cpu_ll_exc_147)
CPU_LL_INTR_HANDLER(148, cpu_ll_exc_148)
CPU_LL_INTR_HANDLER(149, cpu_ll_exc_149)
CPU_LL_INTR_HANDLER(150, cpu_ll_exc_150)
CPU_LL_INTR_HANDLER(151, cpu_ll_exc_151)
CPU_LL_INTR_HANDLER(152, cpu_ll_exc_152)
CPU_LL_INTR_HANDLER(153, cpu_ll_exc_153)
CPU_LL_INTR_HANDLER(154, cpu_ll_exc_154)
CPU_LL_INTR_HANDLER(155, cpu_ll_exc_155)
CPU_LL_INTR_HANDLER(156, cpu_ll_exc_156)
CPU_LL_INTR_HANDLER(157, cpu_ll_exc_157)
CPU_LL_INTR_HANDLER(158, cpu_ll_exc_158)
CPU_LL_INTR_HANDLER(159, cpu_ll_exc_159)
CPU_LL_INTR_HANDLER(160, cpu_ll_exc_160)
CPU_LL_INTR_HANDLER(161, cpu_ll_exc_161)
CPU_LL_INTR_HANDLER(162, cpu_ll_exc_162)
CPU_LL_INTR_HANDLER(163, cpu_ll_exc_163)
CPU_LL_INTR_HANDLER(164, cpu_ll_exc_164)
CPU_LL_INTR_HANDLER(165, cpu_ll_exc_165)
CPU_LL_INTR_HANDLER(166, cpu_ll_exc_166)
CPU_LL_INTR_HANDLER(167, cpu_ll_exc_167)
CPU_LL_INTR_HANDLER(168, cpu_ll_exc_168)
CPU_LL_INTR_HANDLER(169, cpu_ll_exc_169)
CPU_LL_INTR_HANDLER(170, cpu_ll_exc_170)
CPU_LL_INTR_HANDLER(171, cpu_ll_exc_171)
CPU_LL_INTR_HANDLER(172, cpu_ll_exc_172)
CPU_LL_INTR_HANDLER(173, cpu_ll_exc_173)
CPU_LL_INTR_HANDLER(174, cpu_ll_exc_174)
CPU_LL_INTR_HANDLER(175, cpu_ll_exc_175)
CPU_LL_INTR_HANDLER(176, cpu_ll_exc_176)
CPU_LL_INTR_HANDLER(177, cpu_ll_exc_177)
CPU_LL_INTR_HANDLER(178, cpu_ll_exc_178)
CPU_LL_INTR_HANDLER(179, cpu_ll_exc_179)
CPU_LL_INTR_HANDLER(180, cpu_ll_exc_180)
CPU_LL_INTR_HANDLER(181, cpu_ll_exc_181)
CPU_LL_INTR_HANDLER(182, cpu_ll_exc_182)
CPU_LL_INTR_HANDLER(183, cpu_ll_exc_183)
CPU_LL_INTR_HANDLER(184, cpu_ll_exc_184)
CPU_LL_INTR_HANDLER(185, cpu_ll_exc_185)
CPU_LL_INTR_HANDLER(186, cpu_ll_exc_186)
CPU_LL_INTR_HANDLER(187, cpu_ll_exc_187)
CPU_LL_INTR_HANDLER(188, cpu_ll_exc_188)
CPU_LL_INTR_HANDLER(189, cpu_ll_exc_189)
CPU_LL_INTR_HANDLER(190, cpu_ll_exc_190)
CPU_LL_INTR_HANDLER(191, cpu_ll_exc_191)
CPU_LL_INTR_HANDLER(192, cpu_ll_exc_192)
CPU_LL_INTR_HANDLER(193, cpu_ll_exc_193)
CPU_LL_INTR_HANDLER(194, cpu_ll_exc_194)
CPU_LL_INTR_HANDLER(195, cpu_ll_exc_195)
CPU_LL_INTR_HANDLER(196, cpu_ll_exc_196)
CPU_LL_INTR_HANDLER(197, cpu_ll_exc_197)
CPU_LL_INTR_HANDLER(198, cpu_ll_exc_198)
CPU_LL_INTR_HANDLER(199, cpu_ll_exc_199)
CPU_LL_INTR_HANDLER(200, cpu_ll_exc_200)
CPU_LL_INTR_HANDLER(201, cpu_ll_exc_201)
CPU_LL_INTR_HANDLER(202, cpu_ll_exc_202)
CPU_LL_INTR_HANDLER(203, cpu_ll_exc_203)
CPU_LL_INTR_HANDLER(204, cpu_ll_exc_204)
CPU_LL_INTR_HANDLER(205, cpu_ll_exc_205)
CPU_LL_INTR_HANDLER(206, cpu_ll_exc_206)
CPU_LL_INTR_HANDLER(207, cpu_ll_exc_207)
CPU_LL_INTR_HANDLER(208, cpu_ll_exc_208)
CPU_LL_INTR_HANDLER(209, cpu_ll_exc_209)
CPU_LL_INTR_HANDLER(210, cpu_ll_exc_210)
CPU_LL_INTR_HANDLER(211, cpu_ll_exc_211)
CPU_LL_INTR_HANDLER(212, cpu_ll_exc_212)
CPU_LL_INTR_HANDLER(213, cpu_ll_exc_213)
CPU_LL_INTR_HANDLER(214, cpu_ll_exc_214)
CPU_LL_INTR_HANDLER(215, cpu_ll_exc_215)
CPU_LL_INTR_HANDLER(216, cpu_ll_exc_216)
CPU_LL_INTR_HANDLER(217, cpu_ll_exc_217)
CPU_LL_INTR_HANDLER(218, cpu_ll_exc_218)
CPU_LL_INTR_HANDLER(219, cpu_ll_exc_219)
CPU_LL_INTR_HANDLER(220, cpu_ll_exc_220)
CPU_LL_INTR_HANDLER(221, cpu_ll_exc_221)
CPU_LL_INTR_HANDLER(222, cpu_ll_exc_222)
CPU_LL_INTR_HANDLER(223, cpu_ll_exc_223)
CPU_LL_INTR_HANDLER(224, cpu_ll_exc_224)
CPU_LL_INTR_HANDLER(225, cpu_ll_exc_225)
CPU_LL_INTR_HANDLER(226, cpu_ll_exc_226)
CPU_LL_INTR_HANDLER(227, cpu_ll_exc_227)
CPU_LL_INTR_HANDLER(228, cpu_ll_exc_228)
CPU_LL_INTR_HANDLER(229, cpu_ll_exc_229)
CPU_LL_INTR_HANDLER(230, cpu_ll_exc_230)
CPU_LL_INTR_HANDLER(231, cpu_ll_exc_231)
CPU_LL_INTR_HANDLER(232, cpu_ll_exc_232)
CPU_LL_INTR_HANDLER(233, cpu_ll_exc_233)
CPU_LL_INTR_HANDLER(234, cpu_ll_exc_234)
CPU_LL_INTR_HANDLER(235, cpu_ll_exc_235)
CPU_LL_INTR_HANDLER(236, cpu_ll_exc_236)
CPU_LL_INTR_HANDLER(237, cpu_ll_exc_237)
CPU_LL_INTR_HANDLER(238, cpu_ll_exc_238)
CPU_LL_INTR_HANDLER(239, cpu_ll_exc_239)
CPU_LL_INTR_HANDLER(240, cpu_ll_exc_240)
CPU_LL_INTR_HANDLER(241, cpu_ll_exc_241)
CPU_LL_INTR_HANDLER(242, cpu_ll_exc_242)
CPU_LL_INTR_HANDLER(243, cpu_ll_exc_243)
CPU_LL_INTR_HANDLER(244, cpu_ll_exc_244)
CPU_LL_INTR_HANDLER(245, cpu_ll_exc_245)
CPU_LL_INTR_HANDLER(246, cpu_ll_exc_246)
CPU_LL_INTR_HANDLER(247, cpu_ll_exc_247)
CPU_LL_INTR_HANDLER(248, cpu_ll_exc_248)
CPU_LL_INTR_HANDLER(249, cpu_ll_exc_249)
CPU_LL_INTR_HANDLER(250, cpu_ll_exc_250)
CPU_LL_INTR_HANDLER(251, cpu_ll_exc_251)
CPU_LL_INTR_HANDLER(252, cpu_ll_exc_252)
CPU_LL_INTR_HANDLER(253, cpu_ll_exc_253)
CPU_LL_INTR_HANDLER(254, cpu_ll_exc_254)
CPU_LL_INTR_HANDLER(255, cpu_ll_exc_255)

#ifdef __LP64__
#define CPU_LL_EXC_HANDLER_ADDR(name) .quad name
#else /* __LP64__ */
#define CPU_LL_EXC_HANDLER_ADDR(name) .long name
#endif /* __LP64__ */

.section INIT_DATA_SECTION

/* See the C declaration */
ASM_DATA(cpu_ll_exc_handler_addrs)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_divide_error)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_debug)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_nmi)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_breakpoint)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_overflow)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_bound_range)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_undefined_opcode)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_no_math_coprocessor)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_double_fault)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_9)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_invalid_tss)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_segment_not_present)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_stack_segment_fault)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_general_protection)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_page_fault)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_15)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_math_fault)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_alignment_check)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_machine_check)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_simd_fp_exception)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_20)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_21)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_22)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_23)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_24)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_25)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_26)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_27)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_28)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_29)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_30)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_31)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_32)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_33)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_34)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_35)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_36)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_37)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_38)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_39)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_40)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_41)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_42)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_43)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_44)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_45)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_46)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_47)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_48)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_49)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_50)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_51)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_52)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_53)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_54)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_55)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_56)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_57)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_58)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_59)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_60)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_61)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_62)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_63)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_64)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_65)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_66)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_67)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_68)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_69)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_70)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_71)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_72)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_73)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_74)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_75)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_76)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_77)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_78)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_79)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_80)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_81)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_82)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_83)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_84)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_85)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_86)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_87)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_88)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_89)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_90)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_91)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_92)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_93)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_94)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_95)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_96)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_97)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_98)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_99)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_100)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_101)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_102)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_103)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_104)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_105)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_106)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_107)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_108)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_109)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_110)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_111)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_112)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_113)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_114)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_115)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_116)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_117)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_118)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_119)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_120)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_121)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_122)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_123)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_124)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_125)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_126)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_127)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_128)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_129)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_130)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_131)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_132)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_133)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_134)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_135)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_136)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_137)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_138)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_139)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_140)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_141)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_142)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_143)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_144)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_145)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_146)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_147)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_148)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_149)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_150)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_151)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_152)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_153)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_154)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_155)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_156)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_157)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_158)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_159)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_160)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_161)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_162)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_163)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_164)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_165)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_166)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_167)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_168)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_169)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_170)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_171)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_172)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_173)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_174)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_175)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_176)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_177)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_178)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_179)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_180)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_181)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_182)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_183)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_184)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_185)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_186)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_187)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_188)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_189)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_190)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_191)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_192)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_193)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_194)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_195)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_196)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_197)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_198)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_199)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_200)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_201)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_202)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_203)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_204)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_205)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_206)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_207)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_208)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_209)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_210)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_211)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_212)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_213)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_214)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_215)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_216)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_217)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_218)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_219)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_220)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_221)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_222)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_223)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_224)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_225)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_226)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_227)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_228)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_229)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_230)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_231)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_232)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_233)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_234)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_235)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_236)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_237)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_238)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_239)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_240)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_241)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_242)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_243)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_244)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_245)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_246)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_247)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_248)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_249)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_250)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_251)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_252)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_253)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_254)
    CPU_LL_EXC_HANDLER_ADDR(cpu_ll_exc_255)
ASM_END(cpu_ll_exc_handler_addrs)

ASM_ENTRY(cpu_load_gdt)
#ifdef __LP64__
    lgdt (%rdi)
#else /* __LP64__ */
    movl 4(%esp), %eax
    lgdt (%eax)
#endif /* __LP64__ */

    movl $CPU_GDT_SEL_DATA, %eax
    movl %eax, %ds
    movl %eax, %es
    movl %eax, %ss

    /* Alter the stack to reload the code segment using a far return */
#ifdef __LP64__
    popq %rax
    pushq $CPU_GDT_SEL_CODE
    pushq %rax
    lretq
#else /* __LP64__ */
    popl %eax
    pushl $CPU_GDT_SEL_CODE
    pushl %eax
    lret
#endif /* __LP64__ */
ASM_END(cpu_load_gdt)
