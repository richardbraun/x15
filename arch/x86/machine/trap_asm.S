/*
 * Copyright (c) 2012-2017 Richard Braun.
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
#include <machine/boot.h>
#include <machine/trap.h>

.text

#ifdef __LP64__

.macro TRAP_STORE_REGISTERS
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

.macro TRAP_LOAD_REGISTERS
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
 addq $16, %rsp /* skip vector and error */
.endm

#define TRAP(vector, name)  \
ASM_ENTRY(name)             \
 pushq $0;                  \
 pushq $(vector);           \
 jmp trap_common;           \
ASM_END(name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(name)                     \
 pushq $(vector);                   \
 jmp trap_common;                   \
ASM_END(name)

ASM_ENTRY(trap_common)
 TRAP_STORE_REGISTERS
 movq %rsp, %rbx        /* save frame */
 movq %rbx, %rdi
 call trap_get_interrupt_stack
 testq %rax, %rax       /* switch stack ? */
 jz 1f
 movq %rax, %rsp        /* switch to interrupt stack ? */
1:
 xorq %rbp, %rbp        /* block stack tracing */
 movq %rbx, %rdi
 call trap_main
 movq %rbx, %rsp        /* restore stack */
 call thread_schedule   /* schedule threads */
 TRAP_LOAD_REGISTERS
 iretq
ASM_END(trap_common)

#else /* __LP64__ */

.macro TRAP_STORE_REGISTERS
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
.macro TRAP_LOAD_REGISTERS
 popl %eax
 popl %ebx
 popl %ecx
 popl %edx
 popl %ebp
 popl %esi
 popl %edi
 addl $16, %esp /* skip segment registers, vector and error */
.endm

#define TRAP(vector, name)  \
ASM_ENTRY(name)             \
 pushl $0;                  \
 pushl $(vector);           \
 jmp trap_common;           \
ASM_END(name)

#define TRAP_ERROR(vector, name)    \
ASM_ENTRY(name)                     \
 pushl $(vector);                   \
 jmp trap_common;                   \
ASM_END(name)

ASM_ENTRY(trap_common)
 TRAP_STORE_REGISTERS
 movl %esp, %ebx        /* save frame */
 pushl %ebx
 call trap_get_interrupt_stack
 addl $4, %esp
 testl %eax, %eax       /* switch stack ? */
 jz 1f
 movl %eax, %esp        /* switch to interrupt stack */
1:
 xorl %ebp, %ebp        /* block stack tracing */
 pushl %ebx
 call trap_main
 movl %ebx, %esp        /* restore stack */
 call thread_schedule   /* schedule threads */
 TRAP_LOAD_REGISTERS
 iret
ASM_END(trap_common)

#endif /* __LP64__ */

/* Architecture defined traps */
TRAP(TRAP_DE, trap_isr_divide_error)
TRAP(TRAP_DB, trap_isr_debug)
TRAP(TRAP_NMI, trap_isr_nmi)
TRAP(TRAP_BP, trap_isr_breakpoint)
TRAP(TRAP_OF, trap_isr_overflow)
TRAP(TRAP_BR, trap_isr_bound_range)
TRAP(TRAP_UD, trap_isr_invalid_opcode)
TRAP(TRAP_NM, trap_isr_device_not_available)
TRAP_ERROR(TRAP_DF, trap_isr_double_fault)
TRAP_ERROR(TRAP_TS, trap_isr_invalid_tss)
TRAP_ERROR(TRAP_NP, trap_isr_segment_not_present)
TRAP_ERROR(TRAP_SS, trap_isr_stack_segment_fault)
TRAP_ERROR(TRAP_GP, trap_isr_general_protection)
TRAP_ERROR(TRAP_PF, trap_isr_page_fault)
TRAP(TRAP_MF, trap_isr_math_fault)
TRAP_ERROR(TRAP_AC, trap_isr_alignment_check)
TRAP(TRAP_MC, trap_isr_machine_check)
TRAP(TRAP_XM, trap_isr_simd_fp_exception)

/*
 * Handlers for reserved exceptions.
 *
 * These exceptions should normally never occur, but have handlers ready just
 * in case.
 */
TRAP(9, trap_isr_9)
TRAP(15, trap_isr_15)
TRAP(20, trap_isr_20)
TRAP(21, trap_isr_21)
TRAP(22, trap_isr_22)
TRAP(23, trap_isr_23)
TRAP(24, trap_isr_24)
TRAP(25, trap_isr_25)
TRAP(26, trap_isr_26)
TRAP(27, trap_isr_27)
TRAP(28, trap_isr_28)
TRAP(29, trap_isr_29)
TRAP(31, trap_isr_31)

/* Generic trap handlers */
TRAP(30, trap_isr_30)
TRAP(32, trap_isr_32)
TRAP(33, trap_isr_33)
TRAP(34, trap_isr_34)
TRAP(35, trap_isr_35)
TRAP(36, trap_isr_36)
TRAP(37, trap_isr_37)
TRAP(38, trap_isr_38)
TRAP(39, trap_isr_39)
TRAP(40, trap_isr_40)
TRAP(41, trap_isr_41)
TRAP(42, trap_isr_42)
TRAP(43, trap_isr_43)
TRAP(44, trap_isr_44)
TRAP(45, trap_isr_45)
TRAP(46, trap_isr_46)
TRAP(47, trap_isr_47)
TRAP(48, trap_isr_48)
TRAP(49, trap_isr_49)
TRAP(50, trap_isr_50)
TRAP(51, trap_isr_51)
TRAP(52, trap_isr_52)
TRAP(53, trap_isr_53)
TRAP(54, trap_isr_54)
TRAP(55, trap_isr_55)
TRAP(56, trap_isr_56)
TRAP(57, trap_isr_57)
TRAP(58, trap_isr_58)
TRAP(59, trap_isr_59)
TRAP(60, trap_isr_60)
TRAP(61, trap_isr_61)
TRAP(62, trap_isr_62)
TRAP(63, trap_isr_63)
TRAP(64, trap_isr_64)
TRAP(65, trap_isr_65)
TRAP(66, trap_isr_66)
TRAP(67, trap_isr_67)
TRAP(68, trap_isr_68)
TRAP(69, trap_isr_69)
TRAP(70, trap_isr_70)
TRAP(71, trap_isr_71)
TRAP(72, trap_isr_72)
TRAP(73, trap_isr_73)
TRAP(74, trap_isr_74)
TRAP(75, trap_isr_75)
TRAP(76, trap_isr_76)
TRAP(77, trap_isr_77)
TRAP(78, trap_isr_78)
TRAP(79, trap_isr_79)
TRAP(80, trap_isr_80)
TRAP(81, trap_isr_81)
TRAP(82, trap_isr_82)
TRAP(83, trap_isr_83)
TRAP(84, trap_isr_84)
TRAP(85, trap_isr_85)
TRAP(86, trap_isr_86)
TRAP(87, trap_isr_87)
TRAP(88, trap_isr_88)
TRAP(89, trap_isr_89)
TRAP(90, trap_isr_90)
TRAP(91, trap_isr_91)
TRAP(92, trap_isr_92)
TRAP(93, trap_isr_93)
TRAP(94, trap_isr_94)
TRAP(95, trap_isr_95)
TRAP(96, trap_isr_96)
TRAP(97, trap_isr_97)
TRAP(98, trap_isr_98)
TRAP(99, trap_isr_99)
TRAP(100, trap_isr_100)
TRAP(101, trap_isr_101)
TRAP(102, trap_isr_102)
TRAP(103, trap_isr_103)
TRAP(104, trap_isr_104)
TRAP(105, trap_isr_105)
TRAP(106, trap_isr_106)
TRAP(107, trap_isr_107)
TRAP(108, trap_isr_108)
TRAP(109, trap_isr_109)
TRAP(110, trap_isr_110)
TRAP(111, trap_isr_111)
TRAP(112, trap_isr_112)
TRAP(113, trap_isr_113)
TRAP(114, trap_isr_114)
TRAP(115, trap_isr_115)
TRAP(116, trap_isr_116)
TRAP(117, trap_isr_117)
TRAP(118, trap_isr_118)
TRAP(119, trap_isr_119)
TRAP(120, trap_isr_120)
TRAP(121, trap_isr_121)
TRAP(122, trap_isr_122)
TRAP(123, trap_isr_123)
TRAP(124, trap_isr_124)
TRAP(125, trap_isr_125)
TRAP(126, trap_isr_126)
TRAP(127, trap_isr_127)
TRAP(128, trap_isr_128)
TRAP(129, trap_isr_129)
TRAP(130, trap_isr_130)
TRAP(131, trap_isr_131)
TRAP(132, trap_isr_132)
TRAP(133, trap_isr_133)
TRAP(134, trap_isr_134)
TRAP(135, trap_isr_135)
TRAP(136, trap_isr_136)
TRAP(137, trap_isr_137)
TRAP(138, trap_isr_138)
TRAP(139, trap_isr_139)
TRAP(140, trap_isr_140)
TRAP(141, trap_isr_141)
TRAP(142, trap_isr_142)
TRAP(143, trap_isr_143)
TRAP(144, trap_isr_144)
TRAP(145, trap_isr_145)
TRAP(146, trap_isr_146)
TRAP(147, trap_isr_147)
TRAP(148, trap_isr_148)
TRAP(149, trap_isr_149)
TRAP(150, trap_isr_150)
TRAP(151, trap_isr_151)
TRAP(152, trap_isr_152)
TRAP(153, trap_isr_153)
TRAP(154, trap_isr_154)
TRAP(155, trap_isr_155)
TRAP(156, trap_isr_156)
TRAP(157, trap_isr_157)
TRAP(158, trap_isr_158)
TRAP(159, trap_isr_159)
TRAP(160, trap_isr_160)
TRAP(161, trap_isr_161)
TRAP(162, trap_isr_162)
TRAP(163, trap_isr_163)
TRAP(164, trap_isr_164)
TRAP(165, trap_isr_165)
TRAP(166, trap_isr_166)
TRAP(167, trap_isr_167)
TRAP(168, trap_isr_168)
TRAP(169, trap_isr_169)
TRAP(170, trap_isr_170)
TRAP(171, trap_isr_171)
TRAP(172, trap_isr_172)
TRAP(173, trap_isr_173)
TRAP(174, trap_isr_174)
TRAP(175, trap_isr_175)
TRAP(176, trap_isr_176)
TRAP(177, trap_isr_177)
TRAP(178, trap_isr_178)
TRAP(179, trap_isr_179)
TRAP(180, trap_isr_180)
TRAP(181, trap_isr_181)
TRAP(182, trap_isr_182)
TRAP(183, trap_isr_183)
TRAP(184, trap_isr_184)
TRAP(185, trap_isr_185)
TRAP(186, trap_isr_186)
TRAP(187, trap_isr_187)
TRAP(188, trap_isr_188)
TRAP(189, trap_isr_189)
TRAP(190, trap_isr_190)
TRAP(191, trap_isr_191)
TRAP(192, trap_isr_192)
TRAP(193, trap_isr_193)
TRAP(194, trap_isr_194)
TRAP(195, trap_isr_195)
TRAP(196, trap_isr_196)
TRAP(197, trap_isr_197)
TRAP(198, trap_isr_198)
TRAP(199, trap_isr_199)
TRAP(200, trap_isr_200)
TRAP(201, trap_isr_201)
TRAP(202, trap_isr_202)
TRAP(203, trap_isr_203)
TRAP(204, trap_isr_204)
TRAP(205, trap_isr_205)
TRAP(206, trap_isr_206)
TRAP(207, trap_isr_207)
TRAP(208, trap_isr_208)
TRAP(209, trap_isr_209)
TRAP(210, trap_isr_210)
TRAP(211, trap_isr_211)
TRAP(212, trap_isr_212)
TRAP(213, trap_isr_213)
TRAP(214, trap_isr_214)
TRAP(215, trap_isr_215)
TRAP(216, trap_isr_216)
TRAP(217, trap_isr_217)
TRAP(218, trap_isr_218)
TRAP(219, trap_isr_219)
TRAP(220, trap_isr_220)
TRAP(221, trap_isr_221)
TRAP(222, trap_isr_222)
TRAP(223, trap_isr_223)
TRAP(224, trap_isr_224)
TRAP(225, trap_isr_225)
TRAP(226, trap_isr_226)
TRAP(227, trap_isr_227)
TRAP(228, trap_isr_228)
TRAP(229, trap_isr_229)
TRAP(230, trap_isr_230)
TRAP(231, trap_isr_231)
TRAP(232, trap_isr_232)
TRAP(233, trap_isr_233)
TRAP(234, trap_isr_234)
TRAP(235, trap_isr_235)
TRAP(236, trap_isr_236)
TRAP(237, trap_isr_237)
TRAP(238, trap_isr_238)
TRAP(239, trap_isr_239)
TRAP(240, trap_isr_240)
TRAP(241, trap_isr_241)
TRAP(242, trap_isr_242)
TRAP(243, trap_isr_243)
TRAP(244, trap_isr_244)
TRAP(245, trap_isr_245)
TRAP(246, trap_isr_246)
TRAP(247, trap_isr_247)
TRAP(248, trap_isr_248)
TRAP(249, trap_isr_249)
TRAP(250, trap_isr_250)
TRAP(251, trap_isr_251)
TRAP(252, trap_isr_252)
TRAP(253, trap_isr_253)
TRAP(254, trap_isr_254)
TRAP(255, trap_isr_255)

#ifdef __LP64__
#define TRAP_TABLE_ENTRY(name) .quad name
#else /* __LP64__ */
#define TRAP_TABLE_ENTRY(name) .long name
#endif /* __LP64__ */

.section INIT_DATA_SECTION

/*
 * This table lists all interrupt service routines as installed in the
 * IDT.
 */
ASM_DATA(trap_isr_table)
TRAP_TABLE_ENTRY(trap_isr_divide_error)
TRAP_TABLE_ENTRY(trap_isr_debug)
TRAP_TABLE_ENTRY(trap_isr_nmi)
TRAP_TABLE_ENTRY(trap_isr_breakpoint)
TRAP_TABLE_ENTRY(trap_isr_overflow)
TRAP_TABLE_ENTRY(trap_isr_bound_range)
TRAP_TABLE_ENTRY(trap_isr_invalid_opcode)
TRAP_TABLE_ENTRY(trap_isr_device_not_available)
TRAP_TABLE_ENTRY(trap_isr_double_fault)
TRAP_TABLE_ENTRY(trap_isr_9)
TRAP_TABLE_ENTRY(trap_isr_invalid_tss)
TRAP_TABLE_ENTRY(trap_isr_segment_not_present)
TRAP_TABLE_ENTRY(trap_isr_stack_segment_fault)
TRAP_TABLE_ENTRY(trap_isr_general_protection)
TRAP_TABLE_ENTRY(trap_isr_page_fault)
TRAP_TABLE_ENTRY(trap_isr_15)
TRAP_TABLE_ENTRY(trap_isr_math_fault)
TRAP_TABLE_ENTRY(trap_isr_alignment_check)
TRAP_TABLE_ENTRY(trap_isr_machine_check)
TRAP_TABLE_ENTRY(trap_isr_simd_fp_exception)
TRAP_TABLE_ENTRY(trap_isr_20)
TRAP_TABLE_ENTRY(trap_isr_21)
TRAP_TABLE_ENTRY(trap_isr_22)
TRAP_TABLE_ENTRY(trap_isr_23)
TRAP_TABLE_ENTRY(trap_isr_24)
TRAP_TABLE_ENTRY(trap_isr_25)
TRAP_TABLE_ENTRY(trap_isr_26)
TRAP_TABLE_ENTRY(trap_isr_27)
TRAP_TABLE_ENTRY(trap_isr_28)
TRAP_TABLE_ENTRY(trap_isr_29)
TRAP_TABLE_ENTRY(trap_isr_30)
TRAP_TABLE_ENTRY(trap_isr_31)
TRAP_TABLE_ENTRY(trap_isr_32)
TRAP_TABLE_ENTRY(trap_isr_33)
TRAP_TABLE_ENTRY(trap_isr_34)
TRAP_TABLE_ENTRY(trap_isr_35)
TRAP_TABLE_ENTRY(trap_isr_36)
TRAP_TABLE_ENTRY(trap_isr_37)
TRAP_TABLE_ENTRY(trap_isr_38)
TRAP_TABLE_ENTRY(trap_isr_39)
TRAP_TABLE_ENTRY(trap_isr_40)
TRAP_TABLE_ENTRY(trap_isr_41)
TRAP_TABLE_ENTRY(trap_isr_42)
TRAP_TABLE_ENTRY(trap_isr_43)
TRAP_TABLE_ENTRY(trap_isr_44)
TRAP_TABLE_ENTRY(trap_isr_45)
TRAP_TABLE_ENTRY(trap_isr_46)
TRAP_TABLE_ENTRY(trap_isr_47)
TRAP_TABLE_ENTRY(trap_isr_48)
TRAP_TABLE_ENTRY(trap_isr_49)
TRAP_TABLE_ENTRY(trap_isr_50)
TRAP_TABLE_ENTRY(trap_isr_51)
TRAP_TABLE_ENTRY(trap_isr_52)
TRAP_TABLE_ENTRY(trap_isr_53)
TRAP_TABLE_ENTRY(trap_isr_54)
TRAP_TABLE_ENTRY(trap_isr_55)
TRAP_TABLE_ENTRY(trap_isr_56)
TRAP_TABLE_ENTRY(trap_isr_57)
TRAP_TABLE_ENTRY(trap_isr_58)
TRAP_TABLE_ENTRY(trap_isr_59)
TRAP_TABLE_ENTRY(trap_isr_60)
TRAP_TABLE_ENTRY(trap_isr_61)
TRAP_TABLE_ENTRY(trap_isr_62)
TRAP_TABLE_ENTRY(trap_isr_63)
TRAP_TABLE_ENTRY(trap_isr_64)
TRAP_TABLE_ENTRY(trap_isr_65)
TRAP_TABLE_ENTRY(trap_isr_66)
TRAP_TABLE_ENTRY(trap_isr_67)
TRAP_TABLE_ENTRY(trap_isr_68)
TRAP_TABLE_ENTRY(trap_isr_69)
TRAP_TABLE_ENTRY(trap_isr_70)
TRAP_TABLE_ENTRY(trap_isr_71)
TRAP_TABLE_ENTRY(trap_isr_72)
TRAP_TABLE_ENTRY(trap_isr_73)
TRAP_TABLE_ENTRY(trap_isr_74)
TRAP_TABLE_ENTRY(trap_isr_75)
TRAP_TABLE_ENTRY(trap_isr_76)
TRAP_TABLE_ENTRY(trap_isr_77)
TRAP_TABLE_ENTRY(trap_isr_78)
TRAP_TABLE_ENTRY(trap_isr_79)
TRAP_TABLE_ENTRY(trap_isr_80)
TRAP_TABLE_ENTRY(trap_isr_81)
TRAP_TABLE_ENTRY(trap_isr_82)
TRAP_TABLE_ENTRY(trap_isr_83)
TRAP_TABLE_ENTRY(trap_isr_84)
TRAP_TABLE_ENTRY(trap_isr_85)
TRAP_TABLE_ENTRY(trap_isr_86)
TRAP_TABLE_ENTRY(trap_isr_87)
TRAP_TABLE_ENTRY(trap_isr_88)
TRAP_TABLE_ENTRY(trap_isr_89)
TRAP_TABLE_ENTRY(trap_isr_90)
TRAP_TABLE_ENTRY(trap_isr_91)
TRAP_TABLE_ENTRY(trap_isr_92)
TRAP_TABLE_ENTRY(trap_isr_93)
TRAP_TABLE_ENTRY(trap_isr_94)
TRAP_TABLE_ENTRY(trap_isr_95)
TRAP_TABLE_ENTRY(trap_isr_96)
TRAP_TABLE_ENTRY(trap_isr_97)
TRAP_TABLE_ENTRY(trap_isr_98)
TRAP_TABLE_ENTRY(trap_isr_99)
TRAP_TABLE_ENTRY(trap_isr_100)
TRAP_TABLE_ENTRY(trap_isr_101)
TRAP_TABLE_ENTRY(trap_isr_102)
TRAP_TABLE_ENTRY(trap_isr_103)
TRAP_TABLE_ENTRY(trap_isr_104)
TRAP_TABLE_ENTRY(trap_isr_105)
TRAP_TABLE_ENTRY(trap_isr_106)
TRAP_TABLE_ENTRY(trap_isr_107)
TRAP_TABLE_ENTRY(trap_isr_108)
TRAP_TABLE_ENTRY(trap_isr_109)
TRAP_TABLE_ENTRY(trap_isr_110)
TRAP_TABLE_ENTRY(trap_isr_111)
TRAP_TABLE_ENTRY(trap_isr_112)
TRAP_TABLE_ENTRY(trap_isr_113)
TRAP_TABLE_ENTRY(trap_isr_114)
TRAP_TABLE_ENTRY(trap_isr_115)
TRAP_TABLE_ENTRY(trap_isr_116)
TRAP_TABLE_ENTRY(trap_isr_117)
TRAP_TABLE_ENTRY(trap_isr_118)
TRAP_TABLE_ENTRY(trap_isr_119)
TRAP_TABLE_ENTRY(trap_isr_120)
TRAP_TABLE_ENTRY(trap_isr_121)
TRAP_TABLE_ENTRY(trap_isr_122)
TRAP_TABLE_ENTRY(trap_isr_123)
TRAP_TABLE_ENTRY(trap_isr_124)
TRAP_TABLE_ENTRY(trap_isr_125)
TRAP_TABLE_ENTRY(trap_isr_126)
TRAP_TABLE_ENTRY(trap_isr_127)
TRAP_TABLE_ENTRY(trap_isr_128)
TRAP_TABLE_ENTRY(trap_isr_129)
TRAP_TABLE_ENTRY(trap_isr_130)
TRAP_TABLE_ENTRY(trap_isr_131)
TRAP_TABLE_ENTRY(trap_isr_132)
TRAP_TABLE_ENTRY(trap_isr_133)
TRAP_TABLE_ENTRY(trap_isr_134)
TRAP_TABLE_ENTRY(trap_isr_135)
TRAP_TABLE_ENTRY(trap_isr_136)
TRAP_TABLE_ENTRY(trap_isr_137)
TRAP_TABLE_ENTRY(trap_isr_138)
TRAP_TABLE_ENTRY(trap_isr_139)
TRAP_TABLE_ENTRY(trap_isr_140)
TRAP_TABLE_ENTRY(trap_isr_141)
TRAP_TABLE_ENTRY(trap_isr_142)
TRAP_TABLE_ENTRY(trap_isr_143)
TRAP_TABLE_ENTRY(trap_isr_144)
TRAP_TABLE_ENTRY(trap_isr_145)
TRAP_TABLE_ENTRY(trap_isr_146)
TRAP_TABLE_ENTRY(trap_isr_147)
TRAP_TABLE_ENTRY(trap_isr_148)
TRAP_TABLE_ENTRY(trap_isr_149)
TRAP_TABLE_ENTRY(trap_isr_150)
TRAP_TABLE_ENTRY(trap_isr_151)
TRAP_TABLE_ENTRY(trap_isr_152)
TRAP_TABLE_ENTRY(trap_isr_153)
TRAP_TABLE_ENTRY(trap_isr_154)
TRAP_TABLE_ENTRY(trap_isr_155)
TRAP_TABLE_ENTRY(trap_isr_156)
TRAP_TABLE_ENTRY(trap_isr_157)
TRAP_TABLE_ENTRY(trap_isr_158)
TRAP_TABLE_ENTRY(trap_isr_159)
TRAP_TABLE_ENTRY(trap_isr_160)
TRAP_TABLE_ENTRY(trap_isr_161)
TRAP_TABLE_ENTRY(trap_isr_162)
TRAP_TABLE_ENTRY(trap_isr_163)
TRAP_TABLE_ENTRY(trap_isr_164)
TRAP_TABLE_ENTRY(trap_isr_165)
TRAP_TABLE_ENTRY(trap_isr_166)
TRAP_TABLE_ENTRY(trap_isr_167)
TRAP_TABLE_ENTRY(trap_isr_168)
TRAP_TABLE_ENTRY(trap_isr_169)
TRAP_TABLE_ENTRY(trap_isr_170)
TRAP_TABLE_ENTRY(trap_isr_171)
TRAP_TABLE_ENTRY(trap_isr_172)
TRAP_TABLE_ENTRY(trap_isr_173)
TRAP_TABLE_ENTRY(trap_isr_174)
TRAP_TABLE_ENTRY(trap_isr_175)
TRAP_TABLE_ENTRY(trap_isr_176)
TRAP_TABLE_ENTRY(trap_isr_177)
TRAP_TABLE_ENTRY(trap_isr_178)
TRAP_TABLE_ENTRY(trap_isr_179)
TRAP_TABLE_ENTRY(trap_isr_180)
TRAP_TABLE_ENTRY(trap_isr_181)
TRAP_TABLE_ENTRY(trap_isr_182)
TRAP_TABLE_ENTRY(trap_isr_183)
TRAP_TABLE_ENTRY(trap_isr_184)
TRAP_TABLE_ENTRY(trap_isr_185)
TRAP_TABLE_ENTRY(trap_isr_186)
TRAP_TABLE_ENTRY(trap_isr_187)
TRAP_TABLE_ENTRY(trap_isr_188)
TRAP_TABLE_ENTRY(trap_isr_189)
TRAP_TABLE_ENTRY(trap_isr_190)
TRAP_TABLE_ENTRY(trap_isr_191)
TRAP_TABLE_ENTRY(trap_isr_192)
TRAP_TABLE_ENTRY(trap_isr_193)
TRAP_TABLE_ENTRY(trap_isr_194)
TRAP_TABLE_ENTRY(trap_isr_195)
TRAP_TABLE_ENTRY(trap_isr_196)
TRAP_TABLE_ENTRY(trap_isr_197)
TRAP_TABLE_ENTRY(trap_isr_198)
TRAP_TABLE_ENTRY(trap_isr_199)
TRAP_TABLE_ENTRY(trap_isr_200)
TRAP_TABLE_ENTRY(trap_isr_201)
TRAP_TABLE_ENTRY(trap_isr_202)
TRAP_TABLE_ENTRY(trap_isr_203)
TRAP_TABLE_ENTRY(trap_isr_204)
TRAP_TABLE_ENTRY(trap_isr_205)
TRAP_TABLE_ENTRY(trap_isr_206)
TRAP_TABLE_ENTRY(trap_isr_207)
TRAP_TABLE_ENTRY(trap_isr_208)
TRAP_TABLE_ENTRY(trap_isr_209)
TRAP_TABLE_ENTRY(trap_isr_210)
TRAP_TABLE_ENTRY(trap_isr_211)
TRAP_TABLE_ENTRY(trap_isr_212)
TRAP_TABLE_ENTRY(trap_isr_213)
TRAP_TABLE_ENTRY(trap_isr_214)
TRAP_TABLE_ENTRY(trap_isr_215)
TRAP_TABLE_ENTRY(trap_isr_216)
TRAP_TABLE_ENTRY(trap_isr_217)
TRAP_TABLE_ENTRY(trap_isr_218)
TRAP_TABLE_ENTRY(trap_isr_219)
TRAP_TABLE_ENTRY(trap_isr_220)
TRAP_TABLE_ENTRY(trap_isr_221)
TRAP_TABLE_ENTRY(trap_isr_222)
TRAP_TABLE_ENTRY(trap_isr_223)
TRAP_TABLE_ENTRY(trap_isr_224)
TRAP_TABLE_ENTRY(trap_isr_225)
TRAP_TABLE_ENTRY(trap_isr_226)
TRAP_TABLE_ENTRY(trap_isr_227)
TRAP_TABLE_ENTRY(trap_isr_228)
TRAP_TABLE_ENTRY(trap_isr_229)
TRAP_TABLE_ENTRY(trap_isr_230)
TRAP_TABLE_ENTRY(trap_isr_231)
TRAP_TABLE_ENTRY(trap_isr_232)
TRAP_TABLE_ENTRY(trap_isr_233)
TRAP_TABLE_ENTRY(trap_isr_234)
TRAP_TABLE_ENTRY(trap_isr_235)
TRAP_TABLE_ENTRY(trap_isr_236)
TRAP_TABLE_ENTRY(trap_isr_237)
TRAP_TABLE_ENTRY(trap_isr_238)
TRAP_TABLE_ENTRY(trap_isr_239)
TRAP_TABLE_ENTRY(trap_isr_240)
TRAP_TABLE_ENTRY(trap_isr_241)
TRAP_TABLE_ENTRY(trap_isr_242)
TRAP_TABLE_ENTRY(trap_isr_243)
TRAP_TABLE_ENTRY(trap_isr_244)
TRAP_TABLE_ENTRY(trap_isr_245)
TRAP_TABLE_ENTRY(trap_isr_246)
TRAP_TABLE_ENTRY(trap_isr_247)
TRAP_TABLE_ENTRY(trap_isr_248)
TRAP_TABLE_ENTRY(trap_isr_249)
TRAP_TABLE_ENTRY(trap_isr_250)
TRAP_TABLE_ENTRY(trap_isr_251)
TRAP_TABLE_ENTRY(trap_isr_252)
TRAP_TABLE_ENTRY(trap_isr_253)
TRAP_TABLE_ENTRY(trap_isr_254)
TRAP_TABLE_ENTRY(trap_isr_255)
ASM_END(trap_isr_table)
