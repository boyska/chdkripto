#include "lolevel.h"
#include "platform.h"
#include "core.h"
#include "keyboard.h"
extern long link_bss_start;
extern long link_bss_end;
extern void boot();
long get_sensor_width()
{
return 5760;
}
void startup()
{
long *bss = &link_bss_start;
 
if ((long)&link_bss_end > (MEMISOSTART + MEMISOSIZE)){
started();
shutdown();
}
 
while (bss<&link_bss_end)
*bss++ = 0;
boot();
}

// Focus length table in firmware @0xfffe296c
#define NUM_FL      8   // 0 - 7, entries in firmware
#define NUM_DATA    3   // 3 words each entry, first is FL
extern int focus_len_table[NUM_FL*NUM_DATA];

// Conversion factor lens FL --> 35mm equiv
// lens      35mm     CF
// ----      ----     --
// 7.7       36       ( 36/ 7.7) * 77 = 360  (min FL)
// 28.5      133      (133/28.5) * 77 = 359.3  (max FL)
#define CF_EFL      360
#define	CF_EFL_DIV  77

const int zoom_points = NUM_FL;

int get_effective_focal_length(int zp) {
    return (CF_EFL*get_focal_length(zp))/CF_EFL_DIV;
}

int get_focal_length(int zp) {
    if (zp < 0) zp = 0;
    else if (zp >= NUM_FL) zp = NUM_FL-1;
    return focus_len_table[zp*NUM_DATA];
}

int get_zoom_x(int zp) {
    return get_focal_length(zp)*10/focus_len_table[0];
}

#if 0
int rec_switch_state(void) {
// both were in the original mode_get() function, status unknown
//	mode  = (physw_status[1] & 0x08000000)?MODE_PLAY:MODE_REC;
//	mode  = (physw_status[0] & 0x00000040)?MODE_REC:MODE_PLAY;
	return (physw_status[0] & 0x00000040);
}
#endif

long get_vbatt_min()
{
return 3500;
}
long get_vbatt_max()
{
return 4100;
}
