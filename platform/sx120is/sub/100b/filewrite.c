/*
 * filewrite.c - auto-generated by CHDK code_gen.
 */
#include "lolevel.h"
#include "platform.h"

typedef struct {
    unsigned int address;
    unsigned int length;
} cam_ptp_data_chunk; //camera specific structure

#define MAX_CHUNKS_FOR_JPEG 4 //model specific
/*
 * fwt_data_struct: defined here as it's camera dependent
 * unneeded members are designated with unkn
 * file_offset, full_size, seek_flag only needs to be defined for DryOS>=r50 generation cameras
 * pdc is always required
 * name is not currently used
 */
typedef struct
{
    int unkn1[5];
    cam_ptp_data_chunk pdc[MAX_CHUNKS_FOR_JPEG];
    int unkn6;
    char name[32];
} fwt_data_struct;

#include "../../../generic/filewrite.c"

/*************************************************************/
//** filewritetask @ 0xFFDFA744 - 0xFFDFA828, length=58
void __attribute__((naked,noinline)) filewritetask() {
asm volatile (
"    STMFD   SP!, {R1-R5,LR} \n"
"    LDR     R4, =0x9138 \n"

"loc_FFDFA74C:\n"
"    LDR     R0, [R4, #0x10] \n"
"    MOV     R2, #0 \n"
"    ADD     R1, SP, #8 \n"
"    BL      sub_FFC1659C /*_ReceiveMessageQueue*/ \n"
"    CMP     R0, #0 \n"
"    BNE     loc_FFDFA77C \n"
"    LDR     R0, [SP, #8] \n"
"    LDR     R1, [R0] \n"
"    CMP     R1, #1 \n"
"    BNE     loc_FFDFA784 \n"
"    LDR     R0, [R4, #8] \n"
"    BL      _GiveSemaphore \n"

"loc_FFDFA77C:\n"
"    BL      _ExitTask \n"
"    LDMFD   SP!, {R1-R5,PC} \n"

"loc_FFDFA784:\n"
"    SUB     R1, R1, #2 \n"
"    CMP     R1, #6 \n"
"    ADDLS   PC, PC, R1, LSL#2 \n"
"    B       loc_FFDFA74C \n"
"    B       loc_FFDFA7B0 \n"
"    B       loc_FFDFA814 \n"
"    B       loc_FFDFA81C \n"
"    B       loc_FFDFA81C \n"
"    B       loc_FFDFA81C \n"
"    B       loc_FFDFA81C \n"
"    B       loc_FFDFA824 \n"

"loc_FFDFA7B0:\n"
"    MOV     R0, #0 \n"
"    STR     R0, [SP] \n"

"loc_FFDFA7B8:\n"
"    LDR     R0, [R4, #0x10] \n"
"    MOV     R1, SP \n"
"    BL      sub_FFC167E0 /*_GetNumberOfPostedMessages*/ \n"
"    LDR     R0, [SP] \n"
"    CMP     R0, #0 \n"
"    BEQ     loc_FFDFA7E4 \n"
"    LDR     R0, [R4, #0x10] \n"
"    MOV     R2, #0 \n"
"    ADD     R1, SP, #4 \n"
"    BL      sub_FFC1659C /*_ReceiveMessageQueue*/ \n"
"    B       loc_FFDFA7B8 \n"

"loc_FFDFA7E4:\n"
"    LDR     R0, [R4] \n"
"    CMN     R0, #1 \n"
"    BEQ     loc_FFDFA808 \n"
"    BL      fwt_close \n"  // --> Patched. Old value = _Close.
"    MVN     R0, #0 \n"
"    STR     R0, [R4] \n"
"    LDR     R0, =0x92978 \n"
"    BL      sub_FFC45A08 \n"
"    BL      sub_FFC43E50 \n"

"loc_FFDFA808:\n"
"    LDR     R0, [R4, #0xC] \n"
"    BL      _GiveSemaphore \n"
"    B       loc_FFDFA74C \n"

"loc_FFDFA814:\n"
"    BL      sub_FFDFAA2C_my \n"  // --> Patched. Old value = 0xFFDFAA2C. Open stage
"    B       loc_FFDFA74C \n"

"loc_FFDFA81C:\n"
"    BL      sub_FFDFAB60_my \n"  // --> Patched. Old value = 0xFFDFAB60. Write stage
"    B       loc_FFDFA74C \n"

"loc_FFDFA824:\n"
"    BL      sub_FFDFAC6C_my \n"  // --> Patched. Old value = 0xFFDFAC6C. Close stage
"    B       loc_FFDFA74C \n"
);
}

/*************************************************************/
//** sub_FFDFAA2C_my @ 0xFFDFAA2C - 0xFFDFAA6C, length=17
void __attribute__((naked,noinline)) sub_FFDFAA2C_my() {
asm volatile (
"    STMFD   SP!, {R4-R8,LR} \n"
"    MOV     R4, R0 \n"
"    ADD     R0, R0, #0x38 \n"
"    SUB     SP, SP, #0x38 \n"
"    BL      sub_FFC45A08 \n"
"    MOV     R1, #0 \n"
"    BL      sub_FFC43E00 \n"
"    LDR     R0, [R4, #0xC] \n"
"    BL      sub_FFC42AFC \n"
"    LDR     R7, [R4, #8] \n"
"    LDR     R8, =0x1B6 \n"
"    ADD     R6, R4, #0x38 \n"
"    LDR     R5, [R4, #0xC] \n"
//hook start
"    MOV     R0, R4\n"
"    BL      filewrite_main_hook\n"
//hook end
"    MOV     R0, R6 \n"
"    MOV     R1, R7 \n"
"    MOV     R2, R8 \n"
"    BL      fwt_open \n"  // --> Patched. Old value = _Open.
"    LDR     PC, =0xFFDFAA70 \n"  // Continue in firmware
);
}

/*************************************************************/
//** sub_FFDFAB60_my @ 0xFFDFAB60 - 0xFFDFAC68, length=67
void __attribute__((naked,noinline)) sub_FFDFAB60_my() {
asm volatile (
"    STMFD   SP!, {R4-R10,LR} \n"
"    MOV     R4, R0 \n"
"    LDR     R0, [R0] \n"
"    CMP     R0, #4 \n"
"    LDREQ   R6, [R4, #0x18] \n"
"    LDREQ   R7, [R4, #0x14] \n"
"    BEQ     loc_FFDFABAC \n"
"    CMP     R0, #5 \n"
"    LDREQ   R6, [R4, #0x20] \n"
"    LDREQ   R7, [R4, #0x1C] \n"
"    BEQ     loc_FFDFABAC \n"
"    CMP     R0, #6 \n"
"    LDREQ   R6, [R4, #0x28] \n"
"    LDREQ   R7, [R4, #0x24] \n"
"    BEQ     loc_FFDFABAC \n"
"    CMP     R0, #7 \n"
"    BNE     loc_FFDFABC0 \n"
"    LDR     R6, [R4, #0x30] \n"
"    LDR     R7, [R4, #0x2C] \n"

"loc_FFDFABAC:\n"
"    CMP     R6, #0 \n"
"    BNE     loc_FFDFABD0 \n"

"loc_FFDFABB4:\n"
"    MOV     R1, R4 \n"
"    MOV     R0, #8 \n"
"    B       loc_FFDFAC64 \n"

"loc_FFDFABC0:\n"
"    LDR     R1, =0x297 \n"
"    LDR     R0, =0xFFDFA83C \n"
"    BL      _DebugAssert \n"
"    B       loc_FFDFABB4 \n"

"loc_FFDFABD0:\n"
"    LDR     R9, =0x9138 \n"
"    MOV     R5, R6 \n"

"loc_FFDFABD8:\n"
"    LDR     R0, [R4, #4] \n"
"    CMP     R5, #0x1000000 \n"
"    MOVLS   R8, R5 \n"
"    MOVHI   R8, #0x1000000 \n"
"    BIC     R1, R0, #0xFF000000 \n"
"    CMP     R1, #0 \n"
"    BICNE   R0, R0, #0xFF000000 \n"
"    RSBNE   R0, R0, #0x1000000 \n"
"    CMPNE   R8, R0 \n"
"    MOVHI   R8, R0 \n"
"    LDR     R0, [R9] \n"
"    MOV     R2, R8 \n"
"    MOV     R1, R7 \n"
"    BL      fwt_write \n"  // --> Patched. Old value = _Write.
"    LDR     R1, [R4, #4] \n"
"    CMP     R8, R0 \n"
"    ADD     R1, R1, R0 \n"
"    STR     R1, [R4, #4] \n"
"    BEQ     loc_FFDFAC38 \n"
"    CMN     R0, #1 \n"
"    LDRNE   R0, =0x9200015 \n"
"    LDREQ   R0, =0x9200005 \n"
"    STR     R0, [R4, #0x10] \n"
"    B       loc_FFDFABB4 \n"

"loc_FFDFAC38:\n"
"    SUB     R5, R5, R0 \n"
"    CMP     R5, R6 \n"
"    ADD     R7, R7, R0 \n"
"    LDRCS   R0, =0xFFDFA83C \n"
"    LDRCS   R1, =0x2C2 \n"
"    BLCS    _DebugAssert \n"
"    CMP     R5, #0 \n"
"    BNE     loc_FFDFABD8 \n"
"    LDR     R0, [R4] \n"
"    MOV     R1, R4 \n"
"    ADD     R0, R0, #1 \n"

"loc_FFDFAC64:\n"
"    LDMFD   SP!, {R4-R10,LR} \n"
"    B       sub_FFDFA498 \n"
);
}

/*************************************************************/
//** sub_FFDFAC6C_my @ 0xFFDFAC6C - 0xFFDFAC88, length=8
void __attribute__((naked,noinline)) sub_FFDFAC6C_my() {
asm volatile (
"    STMFD   SP!, {R4,R5,LR} \n"
"    LDR     R5, =0x9138 \n"
"    MOV     R4, R0 \n"
"    LDR     R0, [R5] \n"
"    SUB     SP, SP, #0x1C \n"
"    CMN     R0, #1 \n"
//"  BEQ     _sub_FFDFACA0 \n"
"    LDREQ	 PC, =0xFFDFACA0\n"
"    BL      fwt_close \n"  // --> Patched. Old value = _Close.
"    LDR     PC, =0xFFDFAC8C \n"  // Continue in firmware
);
}
