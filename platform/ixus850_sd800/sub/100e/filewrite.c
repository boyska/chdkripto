/*
 * filewrite.c - auto-generated by CHDK code_gen.
 */
#include "lolevel.h"
#include "platform.h"

typedef struct {
    unsigned int address;
    unsigned int length;
} cam_ptp_data_chunk; //camera specific structure

#define MAX_CHUNKS_FOR_JPEG 3 //model specific
/*
 * fwt_data_struct: defined here as it's camera dependent
 * unneeded members are designated with unkn
 * file_offset, full_size, seek_flag only needs to be defined for DryOS>=r50 generation cameras
 * pdc is always required
 * name is not currently used
 */
typedef struct
{
    int unkn1;
    cam_ptp_data_chunk pdc[MAX_CHUNKS_FOR_JPEG];
    char name[32];
} fwt_data_struct;
#define CAM_HAS_COMPLETEFILEWRITE_REPLACEMENT 1

#include "../../../generic/filewrite.c"

/*************************************************************/
//** filewritetask @ 0xFF872104 - 0xFF872194, length=37
void __attribute__((naked,noinline)) filewritetask() {
asm volatile (
"    STMFD   SP!, {R4,LR} \n"
"    LDR     R4, =0x1C1EC \n"
"    SUB     SP, SP, #4 \n"
"    B       loc_FF872138 \n"

"loc_FF872114:\n"
"    TST     R3, #4 \n"
"    BEQ     loc_FF872134 \n"
"    LDR     R0, [R4] \n"
"    BL      sub_FF820FC8 /*_ClearEventFlag*/ \n"
"    LDR     R0, [R4] \n"
"    MOV     R1, #8 \n"
"    BL      sub_FF820E2C /*_SetEventFlag*/ \n"
"    B       loc_FF872138 \n"

"loc_FF872134:\n"
"    BL      sub_FF87204C_my \n"  // --> Patched. Old value = 0xFF87204C.

"loc_FF872138:\n"
"    MOV     R1, #7 \n"
"    LDR     R0, [R4] \n"
"    MOV     R2, #0 \n"
"    BL      sub_FF820E0C /*_WaitForAnyEventFlag*/ \n"
"    CMP     R0, #0 \n"
"    MOV     R1, SP \n"
"    BEQ     loc_FF872168 \n"
"    MOV     R1, #0x2B0 \n"
"    LDR     R0, =0xFF871FA0 \n"
"    ADD     R1, R1, #1 \n"
"    BL      _DebugAssert \n"
"    B       loc_FF872180 \n"

"loc_FF872168:\n"
"    LDR     R0, [R4] \n"
"    BL      sub_FF821018 /*_GetEventFlagValue*/ \n"
"    LDR     R3, [SP] \n"
"    TST     R3, #2 \n"
"    MOV     R1, #5 \n"
"    BEQ     loc_FF872114 \n"

"loc_FF872180:\n"
"    LDR     R3, =0x1C1F0 \n"
"    LDR     R0, [R3] \n"
"    BL      _GiveSemaphore \n"
"    BL      _ExitTask \n"
"    ADD     SP, SP, #4 \n"
"    LDMFD   SP!, {R4,PC} \n"
);
}

/*************************************************************/
//** sub_FF87204C_my @ 0xFF87204C - 0xFF8720E8, length=40
void __attribute__((naked,noinline)) sub_FF87204C_my() {
asm volatile (
"    STMFD   SP!, {R4,R5,LR} \n"
"    LDR     R2, =0x1C1D0 \n"
"    LDRH    R3, [R2] \n"
"    SUB     R3, R3, #1 \n"
"    CMP     R3, #3 \n"
"    LDRLS   PC, [PC, R3, LSL#2] \n"
"    B       loc_FF872098 \n"
"    .long   loc_FF872078 \n"
"    .long   loc_FF872088 \n"
"    .long   loc_FF872088 \n"
"    .long   loc_FF872088 \n"

"loc_FF872078:\n"
"    LDR     R0, =0x1C190 \n"
"    BL      sub_FF871EF8_my \n"  // --> Patched. Old value = 0xFF871EF8.
"    MOV     R4, R0 \n"
"    B       loc_FF87209C \n"

"loc_FF872088:\n"
"    LDR     R0, =0x1C190 \n"
"    BL      sub_FF871FAC \n"
"    MOV     R4, R0 \n"
"    B       loc_FF87209C \n"

"loc_FF872098:\n"
"    MOV     R4, #1 \n"

"loc_FF87209C:\n"
"    CMP     R4, #0 \n"
"    MOV     R1, #1 \n"
"    LDMEQFD SP!, {R4,R5,PC} \n"
"    LDR     R3, =0x1C1EC \n"
"    LDR     R0, [R3] \n"
"    BL      sub_FF820FC8 /*_ClearEventFlag*/ \n"
"    LDR     R3, =0x1C1F8 \n"
"    LDR     R5, [R3] \n"
"    LDR     R1, =0x1C1F4 \n"
"    LDR     R12, =0x2734 \n"
"    MOV     R3, #1 \n"
"    MOV     R2, #0 \n"
"    CMP     R5, #0 \n"
"    STR     R3, [R1] \n"
"    MOV     R0, R4 \n"
"    STR     R2, [R12] \n"
"    LDMEQFD SP!, {R4,R5,PC} \n"
"    MOV     LR, PC \n"
"    MOV     PC, R5 \n"
"    BL      fwt_after_close\n" //+
"    LDMFD   SP!, {R4,R5,PC} \n"
);
}

/*************************************************************/
//** sub_FF871EF8_my @ 0xFF871EF8 - 0xFF871F90, length=39
void __attribute__((naked,noinline)) sub_FF871EF8_my() {
asm volatile (
"    STMFD   SP!, {R4-R6,LR} \n"
"    MOV     R4, R0 \n"
"    ADD     R5, R4, #0x1C \n"
"    MOV     R0, R5 \n"
"    BL      sub_FF871BD0 \n"
"    LDR     R0, [R4, #0x3C] \n"
"    BL      sub_FF87B084 \n"
"    LDR     R3, [R4] \n"
"    MOV     R1, #0x600 \n"
"    TST     R3, #0x10000 \n"
"    ADD     R1, R1, #1 \n"
"    MOV     R2, #0x1B4 \n"
"    ORRNE   R1, R1, #0x8000 \n"
"    LDR     R3, [R4, #0x3C] \n"
"    ADD     R2, R2, #2 \n"
//place hook here
//the task's data block is at [r4] at this point, filename starts at [r4+0x1c]
//the block can be captured here for a (new) camera with unknown data block structure
//for ptp remote capture, pass '/null' as filename
//if writing does not need to be prevented, just continue
"    STMFD   SP!, {R1-R12,LR}\n"
"    MOV     R0, R4\n"
"    BL      filewrite_main_hook\n"
"    BL      filewrite_jpeg_complete\n"
"    CMP     R0, #0\n"
"    LDRNE   R0, =loc_mynull\n" // /null as file name (works only on VxWorks)
"    LDMFD   SP!, {R1-R12,LR}\n"
"    MOVEQ   R0, R5\n" //canon file name
//hook end
//"  MOV     R0, R5 \n"  // - file name
"    BL      sub_FF871CD4 \n"
"    MOV     R1, R4 \n"
"    MOV     R2, R0 \n"
"    MOV     R4, #0 \n"
"    LDR     R3, =0x1C1D4 \n"
"    CMP     R2, R4 \n"
"    LDR     R6, =0x1C1D0 \n"
"    MOV     R0, R5 \n"
"    STR     R2, [R3] \n"
"    BGT     loc_FF871F78 \n"
"    BL      sub_FF871BE4 \n"
"    MOV     R0, #0x8000001 \n"
"    ADD     R0, R0, #0x1200000 \n"
"    BL      sub_FF86F880 \n"
"    MOV     R0, #2 \n"
"    LDMFD   SP!, {R4-R6,PC} \n"

"loc_FF871F78:\n"
"    LDR     R3, =0x1C1D8 \n"
"    LDRH    R0, [R6] \n"
"    STR     R4, [R3] \n"
"    BL      sub_FF871E48 \n"
"    STRH    R0, [R6] \n"
"    MOV     R0, R4 \n"
"    LDMFD   SP!, {R4-R6,PC} \n"
//mod start
"loc_mynull:\n"
".long   0x6c756e2f\n" // "/null"
".long   0x0000006c\n"
//mod end
);
}
