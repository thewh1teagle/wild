        .text
        .globl mainCRTStartup
        .p2align 4
mainCRTStartup:
        movl $41, %eax
        retq
