#include <assert.h>
#include <stdio.h>
#include "display_layout.h"
int main(void) {
    struct probe_display d,other;
    assert(probe_display_make(1024,576,2,&d));assert(d.width==2048 && d.height==1152 && d.desktop_scale==200 && d.device_scale==180);
    assert(probe_display_make(1280,800,2,&d));assert(d.width==2560 && d.height==1600);
    assert(probe_display_make(1440,900,2,&d));assert(d.width==2880 && d.height==1800 && d.desktop_scale==200);
    probe_display_limit(&d,4096,2048,4096ull*2048);assert(d.width==2880 && d.height==1800 && d.desktop_scale==200);
    assert(probe_display_make(1512,982,2,&d));assert(d.width==3024 && d.height==1964);
    assert(probe_display_make(1728,1117,2,&d));assert(d.width==3456 && d.height==2234);
    probe_display_limit(&d,4096,2048,4096ull*2048);assert(d.height==2048 && d.width<=4096 && d.desktop_scale>=100);
    assert(probe_display_make(1080,720,1,&d));assert(d.width==1080 && d.height==720 && d.desktop_scale==100 && d.device_scale==100);
    assert(probe_display_make(1000,700,1.4,&d));assert(d.width==1400 && d.height==980 && d.desktop_scale==140 && d.device_scale==140);
    assert(probe_display_make(1024,576,1,&d));assert(probe_display_make(512,288,2,&other));
    assert(d.width==other.width && !probe_display_equal(&d,&other)); // DPI-only changes matter
    assert(probe_display_make(1920,1080,1,&d));
    probe_display_limit_pixels(&d,PROBE_WORKSPACE_MAX_SIDE,PROBE_WORKSPACE_MAX_SIDE,PROBE_DISPLAY_MAX_PIXELS);
    assert(d.width==1920 && d.height==1080 && d.desktop_scale==100 && d.device_scale==100);
    assert(probe_display_make(2560,1440,2,&d));
    probe_display_limit_pixels(&d,PROBE_WORKSPACE_MAX_SIDE,PROBE_WORKSPACE_MAX_SIDE,PROBE_DISPLAY_MAX_PIXELS);
    assert(d.width==4096 && d.height==2304 && d.desktop_scale==200);
    assert(!probe_display_make(NAN,576,2,&d));assert(!probe_display_make(1024,0,2,&d));assert(!probe_display_make(1024,576,0,&d));
    for(unsigned w=200;w<20000;w+=317)for(unsigned h=200;h<12000;h+=503){
        assert(probe_display_make(w,h,2,&d));
        assert(d.width>=200 && d.height>=200 && d.width<=8192 && d.height<=8192 && !(d.width%2));
        assert((uint64_t)d.width*d.height<=PROBE_DISPLAY_MAX_PIXELS && d.desktop_scale>=100 && d.desktop_scale<=500);
        probe_display_limit(&d,8192,8192,40000);assert(d.width==200 && d.height==200);
    }
    puts("Display layout tests passed: Retina, window/fullscreen ratios, DPI-only changes, limits, invalid input.");
    return 0;
}
