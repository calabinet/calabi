param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
# Generate an isolated resource-only UI from the NSIS installation. Never patch
# the shared NSIS files. Dialog units preserve the installer's DPI scaling.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class CompactInstallerUI {
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryEx(string p, IntPtr f, uint flags);
    [DllImport("kernel32", SetLastError=true)] static extern bool FreeLibrary(IntPtr h);
    [DllImport("kernel32", CharSet=CharSet.Unicode)] static extern IntPtr FindResource(IntPtr h, IntPtr n, IntPtr t);
    [DllImport("kernel32")] static extern IntPtr LoadResource(IntPtr h, IntPtr r);
    [DllImport("kernel32")] static extern IntPtr LockResource(IntPtr r);
    [DllImport("kernel32")] static extern uint SizeofResource(IntPtr h, IntPtr r);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr BeginUpdateResource(string p, bool delete);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool UpdateResource(IntPtr h, IntPtr t, IntPtr n, ushort lang, byte[] b, uint length);
    [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool EndUpdateResource(IntPtr h, bool discard);
    static int Word(byte[] b, int p) { return BitConverter.ToUInt16(b,p); }
    static int Skip(byte[] b, int p) {
        if (Word(b,p)==65535) return p+4;
        while(Word(b,p)!=0) p+=2;
        return p+2;
    }
    static void Scale(byte[] b,int p,double scale) {
        short v=BitConverter.ToInt16(b,p);
        byte[] s=BitConverter.GetBytes((short)Math.Round(v*scale)); b[p]=s[0]; b[p+1]=s[1];
    }
    static byte[] Compact(byte[] b) {
        if(Word(b,0)!=1 || Word(b,2)!=65535) throw new Exception("Expected NSIS extended dialog template");
        int count=Word(b,16);
        Scale(b,22,.9); Scale(b,24,.88);
        int p=Skip(b,Skip(b,Skip(b,26)));
        if((BitConverter.ToUInt32(b,12)&64)!=0) p=Skip(b,p+6);
        for(int i=0;i<count;i++) {
            p=(p+3)&~3;
            Scale(b,p+12,.9); Scale(b,p+14,.88); Scale(b,p+16,.9);
            // Preserve single-line text and button heights. Only large content
            // areas shrink vertically, leaving readable labels at 9pt.
            if(Word(b,p+18)>24) Scale(b,p+18,.88);
            p=Skip(b,Skip(b,p+24)); int extra=Word(b,p); p+=2+extra;
        }
        return b;
    }
    public static void Generate(string source,string destination) {
        if(Path.GetFullPath(source)==Path.GetFullPath(destination)) throw new Exception("Source must not be overwritten");
        File.Copy(source,destination,true);
        IntPtr lib=LoadLibraryEx(source,IntPtr.Zero,2);
        if(lib==IntPtr.Zero) throw new Exception("Cannot load NSIS UI");
        IntPtr update=BeginUpdateResource(destination,false);
        if(update==IntPtr.Zero) { FreeLibrary(lib); throw new Exception("Cannot update isolated UI"); }
        bool success=false;
        try {
            foreach(int id in new[]{102,103,104,105,106,107,108,109,111}) {
                IntPtr r=FindResource(lib,(IntPtr)id,(IntPtr)5);
                if(r==IntPtr.Zero) throw new Exception("Missing NSIS dialog "+id);
                byte[] b=new byte[SizeofResource(lib,r)];
                Marshal.Copy(LockResource(LoadResource(lib,r)),b,0,b.Length);
                b=Compact(b);
                if(!UpdateResource(update,(IntPtr)5,(IntPtr)id,1033,b,(uint)b.Length)) throw new Exception("Cannot write dialog "+id);
            }
            success=true;
        } finally { FreeLibrary(lib); if(!EndUpdateResource(update,!success)) throw new Exception("Cannot finish compact UI"); }
    }
}
'@
[CompactInstallerUI]::Generate([IO.Path]::GetFullPath($Source), [IO.Path]::GetFullPath($Destination))
