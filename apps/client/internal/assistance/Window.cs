using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

public sealed class CalabiConsent : Form {
    public sealed class Command {
        public string op {get;set;}
        public string input {get;set;}
        public string text {get;set;}
        public int wheel {get;set;}
        public int baseline {get;set;}
        public uint seq {get;set;}
        public int epoch {get;set;}
        public int x {get;set;}
        public int y {get;set;}
    }
    [StructLayout(LayoutKind.Sequential)] struct Mouse {public int x,y; public uint data,flags,time; public UIntPtr extra;}
    [StructLayout(LayoutKind.Sequential)] struct Key {public ushort vk,scan; public uint flags,time; public UIntPtr extra;}
    [StructLayout(LayoutKind.Explicit)] struct Payload {
        [FieldOffset(0)] public Mouse mouse;
        [FieldOffset(0)] public Key key;
    }
    [StructLayout(LayoutKind.Sequential)] struct Input {public uint type;public Payload payload;}
    [DllImport("user32.dll")] static extern uint SendInput(uint n,Input[] inputs,int size);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern short GetAsyncKeyState(int key);
    [DllImport("user32.dll")] static extern bool RegisterHotKey(IntPtr h,int id,uint mods,uint vk);
    [DllImport("user32.dll")] static extern bool UnregisterHotKey(IntPtr h,int id);
    bool hotkey;
    protected override void WndProc(ref Message m){
        if(m.Msg==0x312 && m.WParam.ToInt32()==1 && state=="control"){Revoke();return;}
        base.WndProc(ref m);
    }
    void Revoke(string reason="local_revoke"){
        state="view";leaseArmed=false;ReleaseAll();
        TraceTransition(reason);
        if(hotkey){UnregisterHotKey(Handle,1);hotkey=false;}
        RefreshState();
    }
    readonly HashSet<int> keys=new HashSet<int>();
    bool left, right;
    int epoch;
    uint lastTextSeq;
    string state="pending";
    // Process exit status is separate from the frame pipe, including when idle.
    public static int Outcome {get; private set;}
    bool automatic;
    void CloseAutomatically(){CloseWithReason(46);}
    void CloseWithReason(int reason){if(state=="ended")return;Outcome=reason;automatic=true;Close();}
    readonly Stopwatch clock=Stopwatch.StartNew();
    long last, lastLease, pulseUtcMs;
    readonly string tracePath=Environment.GetEnvironmentVariable("CALABI_ASSIST_TEST_LEASE_TRACE");
    static long UtcMs(){return (DateTime.UtcNow.Ticks-621355968000000000L)/10000;}
    void TraceTransition(string reason){
        if(String.IsNullOrEmpty(tracePath))return;
        try{File.AppendAllText(tracePath,String.Format("{0} reason={1} epoch={2} last_pulse_ms={3} lease_age_ms={4} activity_age_ms={5}\n",UtcMs(),reason,epoch,pulseUtcMs,clock.ElapsedMilliseconds-lastLease,clock.ElapsedMilliseconds-last));}
        catch(IOException){}catch(UnauthorizedAccessException){}
    }
    bool leaseArmed;
    void CheckLease(){
        if(state=="control" && leaseArmed && clock.ElapsedMilliseconds-lastLease>=750)Revoke("lease_timeout");
    }
    readonly Button share=new Button(),control=new Button(),end=new Button(),hide=new Button();
    readonly Label heading=new Label(),badge=new Label();
    readonly NotifyIcon tray=new NotifyIcon();
    readonly ContextMenuStrip trayMenu=new ContextMenuStrip();
    readonly ToolStripMenuItem revokeItem=new ToolStripMenuItem("收回控制");
    readonly ToolTip hint=new ToolTip();
    readonly Color ink=Color.FromArgb(25,39,55), muted=Color.FromArgb(81,99,112);
    readonly Color accent=Color.FromArgb(0,104,105);
    readonly Font headingFont=new Font("Microsoft YaHei UI",15,FontStyle.Bold);
    [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr icon);

    static Icon SharingIcon(){
        using(var image=new Bitmap(32,32))
        using(var g=Graphics.FromImage(image))
        using(var fill=new SolidBrush(Color.FromArgb(0,104,105)))
        using(var pen=new Pen(Color.White,2)){
            g.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            g.FillEllipse(fill,1,1,30,30);
            g.DrawRectangle(pen,7,9,18,12);g.DrawLine(pen,16,21,16,24);g.DrawLine(pen,11,24,21,24);
            var h=image.GetHicon();
            try{return (Icon)Icon.FromHandle(h).Clone();}finally{DestroyIcon(h);}
        }
    }
    void StyleButton(Button b,bool primary){
        b.FlatStyle=FlatStyle.Flat;b.FlatAppearance.BorderSize=primary?0:1;
        b.FlatAppearance.BorderColor=Color.FromArgb(199,211,215);
        b.BackColor=primary?accent:Color.White;b.ForeColor=primary?Color.White:ink;
        b.UseVisualStyleBackColor=false;b.Cursor=Cursors.Hand;
    }
    protected override void OnLoad(EventArgs e){
        base.OnLoad(e);
        // Use the final outer size (including scaled controls and the title bar).
        var area=Screen.FromPoint(Cursor.Position).WorkingArea;
        Location=new Point(Math.Max(area.Left,area.Right-Width-24),
                           Math.Max(area.Top,area.Bottom-Height-24));
    }
    void RestorePanel(){Show();WindowState=FormWindowState.Normal;Activate();}
    void HidePanel(){if((state=="view" || state=="control") && tray.Visible)Hide();}

    readonly Label status=new Label();
    readonly System.Windows.Forms.Timer watchdog=new System.Windows.Forms.Timer();
    readonly JavaScriptSerializer json=new JavaScriptSerializer{MaxJsonLength=4000000};

    CalabiConsent(string peer){
        Text="Calabi · 远程协助";TopMost=true;FormBorderStyle=FormBorderStyle.FixedDialog;
        MaximizeBox=false;MinimizeBox=false;StartPosition=FormStartPosition.Manual;
        AutoScaleDimensions=new SizeF(96,96);AutoScaleMode=AutoScaleMode.Dpi;
        ClientSize=new Size(410,214);Font=new Font("Microsoft YaHei UI",9);BackColor=Color.White;ForeColor=ink;
        Icon=SharingIcon();
        var accentLine=new Panel{BackColor=accent,Dock=DockStyle.Top,Height=3};
        var brand=new Label{Text="CALABI  /  远程协助",ForeColor=muted,TextAlign=ContentAlignment.MiddleLeft};
        brand.SetBounds(20,12,200,23);
        badge.TextAlign=ContentAlignment.MiddleCenter;badge.SetBounds(310,12,80,24);
        heading.Font=headingFont;heading.SetBounds(18,42,372,34);
        var who=new Label{Text=peer,ForeColor=ink,AutoEllipsis=true,TextAlign=ContentAlignment.MiddleLeft,UseMnemonic=false};
        who.SetBounds(20,80,370,22);hint.SetToolTip(who,peer);
        status.ForeColor=muted;status.SetBounds(20,109,370,36);
        var rule=new Panel{BackColor=Color.FromArgb(224,232,234)};rule.SetBounds(0,155,410,1);
        hide.Text="收起到托盘";hide.SetBounds(20,167,100,34);StyleButton(hide,false);
        share.SetBounds(262,167,128,34);share.Text="同意查看桌面";StyleButton(share,true);
        control.SetBounds(262,167,128,34);StyleButton(control,true);
        end.SetBounds(148,167,104,34);StyleButton(end,false);
        Controls.AddRange(new Control[]{accentLine,brand,badge,heading,who,status,rule,hide,share,control,end});
        tray.Icon=Icon;tray.ContextMenuStrip=trayMenu;
        trayMenu.Items.Add("显示协助面板",null,delegate{RestorePanel();});
        trayMenu.Items.Add(revokeItem);
        revokeItem.Click+=delegate{if(state=="control")Revoke();};
        trayMenu.Items.Add(new ToolStripSeparator());
        trayMenu.Items.Add("结束共享",null,delegate{Close();});
        tray.MouseClick+=delegate(object sender,MouseEventArgs e){if(e.Button==MouseButtons.Left)RestorePanel();};
        hide.Click+=delegate{HidePanel();};
        hint.SetToolTip(hide,"点击通知区域的 Calabi 远程协助图标可恢复面板");
        share.Click+=delegate{if(state=="pending"){state="view";last=clock.ElapsedMilliseconds;RefreshState();}};
        control.Click+=delegate{
            if(state=="control"){Revoke();return;}
            else if(state=="view"){epoch++;lastTextSeq=0;state="control";hotkey=RegisterHotKey(Handle,1,4,0x77);last=clock.ElapsedMilliseconds;}
            RefreshState();
        };
        end.Click+=delegate{Close();};CancelButton=end;ActiveControl=end;
        watchdog.Interval=25;watchdog.Tick+=delegate{
            CheckLease();
            if(clock.ElapsedMilliseconds-last>(state=="pending"?30000:3500) || (state=="pending" && clock.ElapsedMilliseconds>30000))CloseWithReason(state=="pending"?44:43);
        };
        FormClosing+=delegate(object sender,FormClosingEventArgs e){if(!automatic && e.CloseReason==CloseReason.UserClosing)Outcome=state=="pending"?41:42;state="ended";ReleaseAll();watchdog.Stop();};
        SystemEvents.SessionSwitch+=SessionChanged;
        FormClosed+=delegate{
            SystemEvents.SessionSwitch-=SessionChanged;
            tray.Visible=false;tray.Dispose();trayMenu.Dispose();hint.Dispose();
            headingFont.Dispose();Icon.Dispose();
        };
        Shown+=delegate{watchdog.Start();Console.WriteLine("ready");var reader=new Thread(Pump){IsBackground=true};reader.Start();};
        RefreshState();
    }
    void SessionChanged(object sender,SessionSwitchEventArgs e){
        if(e.Reason==SessionSwitchReason.SessionLock || e.Reason==SessionSwitchReason.ConsoleDisconnect || e.Reason==SessionSwitchReason.RemoteDisconnect || e.Reason==SessionSwitchReason.SessionLogoff)
            if(IsHandleCreated && !IsDisposed)BeginInvoke(new Action(delegate{CloseWithReason(45);}));
    }
    void RefreshState(){
        bool pending=state=="pending", controlled=state=="control";
        share.Visible=pending;control.Visible=!pending;hide.Visible=!pending;
        badge.Text=pending?"等待确认":controlled?"可操作":"仅查看";
        badge.BackColor=controlled?Color.FromArgb(253,236,210):Color.FromArgb(225,243,241);
        badge.ForeColor=controlled?Color.FromArgb(114,68,12):accent;
        heading.Text=pending?"允许对方查看桌面？":controlled?"对方正在操作桌面":"正在共享桌面";
        control.Text=controlled?"收回控制":"允许控制";end.Text=pending?"拒绝":"结束共享";
        status.Text=pending?"同意后，对方可以查看主屏幕。键鼠控制需另行允许。":
            controlled?(hotkey?"按 Shift + F8 可立即收回键鼠控制。":"点击「收回控制」即可恢复为仅查看。"):
            "对方可以查看画面。键盘和鼠标由你控制。";
        revokeItem.Enabled=controlled;
        control.Enabled=!capturePaused;
        if(capturePaused)status.Text="桌面画面已暂停。请恢复远程桌面窗口以继续共享。";
        tray.Text=controlled?"Calabi 远程协助 · 对方可操作":"Calabi 远程协助 · 仅查看";
        tray.Visible=!pending;

    }
    static bool Emit(Input input){return SendInput(1,new[]{input},Marshal.SizeOf(typeof(Input)))==1;}
    static bool KeyEvent(int vk,bool up){var i=new Input{type=1};i.payload.key.vk=(ushort)vk;i.payload.key.flags=up?2u:0u;return Emit(i);}
    static bool MouseEvent(uint flags,int x,int y,int data=0){var i=new Input();i.payload.mouse.data=unchecked((uint)data);i.payload.mouse.flags=flags;i.payload.mouse.x=x;i.payload.mouse.y=y;return Emit(i);}
    void ReleaseAll(){
        foreach(int k in new List<int>(keys))if(KeyEvent(k,true))keys.Remove(k);
        if(left && MouseEvent(4,0,0))left=false;
        if(right && MouseEvent(16,0,0))right=false;
    }
    bool CommitText(Command c){
        if(c.seq<=lastTextSeq || GetForegroundWindow()==Handle || String.IsNullOrEmpty(c.text) || c.text.Length>256)return false;
        var events=new Input[c.text.Length*2];
        for(int n=0;n<c.text.Length;n++){
            char unit=c.text[n];
            if(Char.IsControl(unit))return false;
            var down=new Input{type=1};
            down.payload.key.scan=unit;
            down.payload.key.flags=4; // KEYEVENTF_UNICODE takes one UTF-16 unit.
            events[n*2]=down;
            down.payload.key.flags|=2;
            events[n*2+1]=down;
        }
        lastTextSeq=c.seq;
        return SendInput((uint)events.Length,events,Marshal.SizeOf(typeof(Input)))==events.Length;
    }
    bool Apply(Command c){
        if(c.input=="text")return CommitText(c);
        if(c.input=="keyup") {
            if(!keys.Contains(c.x))return false;
            if(!KeyEvent(c.x,true))return false;keys.Remove(c.x);return true;
        }
        if(c.input=="rightup"){if(!right || !MouseEvent(16,0,0))return false;right=false;return true;}
        if(c.input=="up"){if(!left || !MouseEvent(4,0,0))return false;left=false;return true;}
        if(c.input=="keydown"){
            bool punctuation=(c.x>=0xba && c.x<=0xc0) || (c.x>=0xdb && c.x<=0xde) || c.x==0xe2;
            if(GetForegroundWindow()==Handle || !(punctuation || (c.x>=48 && c.x<=90) || c.x==16 || c.x==17 || c.x==8 || c.x==13 || c.x==32 || (c.x>=37 && c.x<=40)))return false;
            if(!keys.Contains(c.x) && GetAsyncKeyState(c.x)<0)return false;
            if(!KeyEvent(c.x,false))return false;keys.Add(c.x);return true;
        }
        bool scroll=c.input=="wheel" || c.input=="hwheel";
        if(c.input!="move" && c.input!="down" && c.input!="rightdown" && !scroll)return false;
        if(scroll && (c.wheel==0 || c.wheel < -1200 || c.wheel > 1200))return false;
        if(c.x<0 || c.x>65535 || c.y<0 || c.y>65535)return false;
        var b=Screen.PrimaryScreen.Bounds;
        Point p=new Point(b.Left+(int)((long)c.x*(b.Width-1)/65535),b.Top+(int)((long)c.y*(b.Height-1)/65535));
        if(Visible && Bounds.Contains(p))return false;
        var v=SystemInformation.VirtualScreen;
        if(!MouseEvent(0xc001,(int)((long)(p.X-v.Left)*65535/(v.Width-1)),(int)((long)(p.Y-v.Top)*65535/(v.Height-1))))return false;
        if(c.input=="move")return true;
        if(scroll)return MouseEvent(c.input=="wheel"?0x0800u:0x1000u,0,0,c.wheel);
        if(c.input=="rightdown"){
            if(right || GetAsyncKeyState(2)<0 || !MouseEvent(8,0,0))return false;
            right=true;return true;
        }
        if(left || GetAsyncKeyState(1)<0 || !MouseEvent(2,0,0))return false;left=true;return true;
    }
    int[] previousPixels, scratch;
    int previousWidth, previousHeight, revision;

    static string Encode(Bitmap image, ImageFormat format){
        using(var output=new MemoryStream()){
            image.Save(output,format);
            return Convert.ToBase64String(output.ToArray());
        }
    }

    // Leave room for JSON inside the oldest viewer's 3 MiB response limit.
    const int MaxImageChars = 3*1024*1024-4096;
    static readonly ImageCodecInfo jpegCodec=Array.Find(ImageCodecInfo.GetImageEncoders(),
        delegate(ImageCodecInfo codec){return codec.FormatID==ImageFormat.Jpeg.Guid;});

    static string EncodeDesktopJpeg(Bitmap bitmap){
        foreach(long quality in new long[]{90,75,55,32,12}){
            using(var output=new MemoryStream())
            using(var options=new EncoderParameters(1)){
                options.Param[0]=new EncoderParameter(System.Drawing.Imaging.Encoder.Quality,quality);
                bitmap.Save(output,jpegCodec,options);
                if(4*((output.Length+2)/3)<=MaxImageChars)return Convert.ToBase64String(output.ToArray());
            }
        }
        throw new InvalidDataException("Desktop frame exceeds transport limit");
    }

    // Each consent window owns its baseline. Only compare with a revision
    // that the viewer actually painted; an unknown baseline gets a full frame.
    void EncodeChanges(Bitmap small, int baseline, Dictionary<string,object> reply){
        int w=small.Width, h=small.Height;
        var bounds=new Rectangle(0,0,w,h);
        if(scratch==null || scratch.Length!=w*h)scratch=new int[w*h];
        var data=small.LockBits(bounds,ImageLockMode.ReadOnly,PixelFormat.Format32bppArgb);
        try{
            for(int y=0;y<h;y++)Marshal.Copy(IntPtr.Add(data.Scan0,y*data.Stride),scratch,y*w,w);
        }finally{small.UnlockBits(data);}
        bool compare=baseline!=0 && baseline==revision && previousWidth==w && previousHeight==h;
        var changed=bounds;
        if(compare){
            int left=w,top=h,right=-1,bottom=-1;
            for(int y=0;y<h;y++)for(int x=0;x<w;x++){
                int i=y*w+x;
                if(scratch[i]==previousPixels[i])continue;
                left=Math.Min(left,x);right=Math.Max(right,x);top=Math.Min(top,y);bottom=y;
            }
            if(right<0){reply["revision"]=revision;return;}
            changed=Rectangle.FromLTRB(left,top,right+1,bottom+1);
        }
        if(compare && (long)changed.Width*changed.Height<w*h/3){
            using(var patch=small.Clone(changed,PixelFormat.Format32bppArgb)){
                string encoded=Encode(patch,ImageFormat.Png);
                if(encoded.Length<=MaxImageChars){
                    reply["patch"]=encoded;
                    reply["x"]=changed.X;reply["y"]=changed.Y;
                }
            }
        }
        if(!reply.ContainsKey("patch"))reply["frame"]=EncodeDesktopJpeg(small);
        var swap=previousPixels;previousPixels=scratch;scratch=swap;
        previousWidth=w;previousHeight=h;reply["revision"]=++revision;
    }
    int captureFailures;
    bool capturePaused;
    long nextCapture;
    void CaptureDesktop(Command c, Dictionary<string,object> reply){
        if(capturePaused && clock.ElapsedMilliseconds<nextCapture){
            if(c.op=="frame_delta")reply["revision"]=c.baseline;
            return;
        }
        var r=Screen.PrimaryScreen.Bounds;
        using(var full=new Bitmap(r.Width,r.Height))
        using(var g=Graphics.FromImage(full)){
            try{
                g.CopyFromScreen(r.Location,Point.Empty,r.Size);
                captureFailures=0;
                if(capturePaused){
                    capturePaused=false;
                    previousWidth=0; // Force a full frame even if the viewer retained its baseline.
                    RefreshState();
                }
            }catch(System.ComponentModel.Win32Exception e){
                // A failed copy has no pixels to publish. Leave the viewer's baseline intact.
                if(e.NativeErrorCode==6 && SystemInformation.TerminalServerSession){
                    nextCapture=clock.ElapsedMilliseconds+500;
                    if(!capturePaused){
                        capturePaused=true;
                        if(state=="control")Revoke("capture_paused");
                        else RefreshState();
                    }
                    reply["state"]=state;
                    if(c.op=="frame_delta")reply["revision"]=c.baseline;
                }else if(e.NativeErrorCode==5 || ++captureFailures>=3){
                    CloseWithReason(0x10000 | (e.NativeErrorCode & 0xffff));
                    reply["state"]="ended";
                }else if(c.op=="frame_delta")reply["revision"]=c.baseline;
                return;
            }
            bool delta=c.op=="frame_delta";
            double scale=delta ? Math.Min(1,Math.Min(2560.0/r.Width,1600.0/r.Height))
                               : Math.Min(1,Math.Min(960.0/r.Width,640.0/r.Height));
            if(delta && scale==1){EncodeChanges(full,c.baseline,reply);return;}
            using(var small=new Bitmap(Math.Max(1,(int)(r.Width*scale)),Math.Max(1,(int)(r.Height*scale)))){
                using(var resize=Graphics.FromImage(small)){
                    resize.InterpolationMode=System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                    resize.PixelOffsetMode=System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
                    resize.DrawImage(full,new Rectangle(0,0,small.Width,small.Height),0,0,r.Width,r.Height,GraphicsUnit.Pixel);
                }
                if(c.op=="frame_delta")EncodeChanges(small,c.baseline,reply);
                else reply["frame"]=Encode(small,ImageFormat.Jpeg);
            }
        }
    }
    string Dispatch(Command c){
        if(clock.ElapsedMilliseconds-last>(state=="pending"?30000:3500) || (state=="pending" && clock.ElapsedMilliseconds>30000)){CloseWithReason(state=="pending"?44:43);return "{\"state\":\"ended\"}";}
        CheckLease();
        if(c.op!="pulse" && (c.op!="view_ping" || state=="view"))last=clock.ElapsedMilliseconds;
        bool applied=false;
        if(state=="control" && c.epoch==epoch){
            if(c.op=="pulse"){if(!String.IsNullOrEmpty(tracePath))pulseUtcMs=UtcMs();last=lastLease=clock.ElapsedMilliseconds;leaseArmed=true;}
            if(c.op=="release")ReleaseAll();
            if(c.op=="input"){
                if(!leaseArmed){lastLease=clock.ElapsedMilliseconds;leaseArmed=true;}
                applied=Apply(c);
            }
        }
        var reply=new Dictionary<string,object>{{"state",state},{"epoch",epoch},{"applied",applied}};
        bool frame=(c.op=="frame" || c.op=="frame_delta") && (state=="view" || state=="control");
        if(frame)CaptureDesktop(c,reply);
        string response=json.Serialize(reply);
        if(frame)last=clock.ElapsedMilliseconds;
        return response;
    }
    void Pump(){
        try{string line;while((line=Console.ReadLine())!=null){
            var c=json.Deserialize<Command>(Encoding.UTF8.GetString(Convert.FromBase64String(line)));
            Console.WriteLine((string)Invoke(new Func<string>(()=>Dispatch(c))));
        }}catch(InvalidOperationException){}finally{if(IsHandleCreated && !IsDisposed)BeginInvoke(new Action(CloseAutomatically));}
    }
    public static void Run(){
        SetProcessDPIAware();Application.EnableVisualStyles();
        string peer=Encoding.UTF8.GetString(Convert.FromBase64String(Console.ReadLine()));
        Application.Run(new CalabiConsent(peer));
    }
}
