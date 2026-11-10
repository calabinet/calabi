#pragma once
#include <stdint.h>
#include <math.h>
#include <string.h>

#define PROBE_DISPLAY_MAX_SIDE 8192u
#define PROBE_DISPLAY_MAX_PIXELS (32ull*1024*1024)
#define PROBE_WORKSPACE_MAX_SIDE 4096u
struct probe_display {
    uint32_t width,height,desktop_scale,device_scale,physical_width,physical_height;
};
static inline void probe_display_metrics(struct probe_display *d) {
    d->device_scale=d->desktop_scale>=180?180:d->desktop_scale>=140?140:100;
    // Physical dimensions describe the virtual viewport at the requested DPI.
    d->physical_width=(uint32_t)((uint64_t)d->width*2540/(96*d->desktop_scale));
    d->physical_height=(uint32_t)((uint64_t)d->height*2540/(96*d->desktop_scale));
    if(d->physical_width<10)d->physical_width=10;
    if(d->physical_height<10)d->physical_height=10;
}
static inline void probe_display_limit(struct probe_display *d,uint32_t maxw,uint32_t maxh,uint64_t area) {
    double factor=1.0;
    if(d->width>maxw)factor=(double)maxw/d->width;
    if(d->height*factor>maxh)factor=(double)maxh/d->height;
    if((double)d->width*d->height*factor*factor>area)factor=sqrt((double)area/((double)d->width*d->height));
    d->width=(uint32_t)floor(d->width*factor);d->width-=d->width%2;
    d->height=(uint32_t)floor(d->height*factor);
    if(d->width<200)d->width=200;
    if(d->height<200)d->height=200;
    if((uint64_t)d->width*d->height>area){
        if(d->height>area/200)d->height=(uint32_t)(area/200);
        if(d->width>area/d->height)d->width=(uint32_t)(area/d->height);
        d->width-=d->width%2;
    }
    uint32_t scale=(uint32_t)floor(d->desktop_scale*factor+0.5);
    d->desktop_scale=scale<100?100:scale>500?500:scale;
    probe_display_metrics(d);
}
static inline int probe_display_make(double width,double height,double backing,struct probe_display *out) {
    if(!out || !isfinite(width) || !isfinite(height) || !isfinite(backing) || width<1 || height<1 || backing<1 || backing>5 || width>65536 || height>65536)return 0;
    memset(out,0,sizeof(*out));
    out->width=(uint32_t)floor(width*backing+0.5);out->height=(uint32_t)floor(height*backing+0.5);
    out->desktop_scale=(uint32_t)floor(100*backing+0.5);
    probe_display_limit(out,PROBE_DISPLAY_MAX_SIDE,PROBE_DISPLAY_MAX_SIDE,PROBE_DISPLAY_MAX_PIXELS);
    return 1;
}
static inline void probe_display_limit_pixels(struct probe_display *d,uint32_t maxw,uint32_t maxh,uint64_t area) {
    uint32_t scale=d->desktop_scale;
    probe_display_limit(d,maxw,maxh,area);
    d->desktop_scale=scale;
    probe_display_metrics(d);
}
static inline int probe_display_equal(const struct probe_display *a,const struct probe_display *b) {
    return a->width==b->width && a->height==b->height && a->desktop_scale==b->desktop_scale &&
        a->device_scale==b->device_scale && a->physical_width==b->physical_width && a->physical_height==b->physical_height;
}
