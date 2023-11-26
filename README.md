# Sega Ferie Loader

Memory maps and some I/O registers are defined.

This system's CPU is Toshiba T6A84. Although opcode-compatible with Z80, it requires a distinct data address space for RAM accesses. On directory `./T6A84` you can find an adapted Z80 processor module, which needs to be copied to your Ghidra installation under `$GHIDRA_DIR/Ghidra/Processors/T6A84`.

Most relevant differences is the inclusion of a new RAM space, which is used on instructions with memory accesses:

```diff
--- Z80/data/languages/z80.cspec        2023-12-09 11:10:40.619694000 +0000
+++ T6A84/data/languages/t6a84.cspec    2023-12-16 09:51:07.258411000 +0000
@@ -7,6 +7,7 @@
   <global>
     <range space="ram"/>
     <range space="io"/>
+    <range space="data"/>
   </global>
   <stackpointer register="SP" space="ram"/>
   <default_proto>
```

```diff
--- Z80/data/languages/z80.slaspec	2023-12-09 11:10:40.534378300 +0000
+++ T6A84/data/languages/t6a84.slaspec	2023-12-16 13:34:09.286215300 +0000
@@ -13,6 +13,7 @@
 @endif

 define space io      type=ram_space      size=2;
+define space data    type=ram_space      size=2;
 define space register type=register_space size=1;

 define register offset=0x00 size=1 [ F A C B E D L H I R ];
@@ -264,12 +265,12 @@

 macro MemRead(dest,off) {
    	ptr:$(PTRSIZE) = off;
-	dest = *:1 ptr;
+	dest = *[data]:1 ptr;
 }

 macro MemStore(off,val) {
    	ptr:$(PTRSIZE) = off;
-	*:1 ptr = val;
+	*[data]:1 ptr = val;
 }

 macro JumpToLoc(off) {
@@ -314,11 +315,11 @@
 hlMem8: (HL)  is HL      { ptr:$(PTRSIZE) = HL; export *:1 ptr; }
 @endif

-ixMem8: (IX+simm8)  is IX & simm8                                 { ptr:$(PTRSIZE) = IX + simm8; export *:1 ptr; }
-ixMem8: (IX-val)    is IX & simm8 & sign8=1	[ val = -simm8; ]      { ptr:$(PTRSIZE) = IX + simm8; export *:1 ptr; }
+ixMem8: (IX+simm8)  is IX & simm8                                 { ptr:$(PTRSIZE) = IX + simm8; export *[data]:1 ptr; }
+ixMem8: (IX-val)    is IX & simm8 & sign8=1	[ val = -simm8; ]      { ptr:$(PTRSIZE) = IX + simm8; export *[data]:1 ptr; }

-iyMem8: (IY+simm8)  is IY & simm8                                 { ptr:$(PTRSIZE) = IY + simm8; export *:1 ptr; }
-iyMem8: (IY-val)    is IY & simm8 & sign8=1	[ val = -simm8; ]      { ptr:$(PTRSIZE) = IY + simm8; export *:1 ptr; }
+iyMem8: (IY+simm8)  is IY & simm8                                 { ptr:$(PTRSIZE) = IY + simm8; export *[data]:1 ptr; }
+iyMem8: (IY-val)    is IY & simm8 & sign8=1	[ val = -simm8; ]      { ptr:$(PTRSIZE) = IY + simm8; export *[data]:1 ptr; }

 @endif # end !Z180_SEGMENTED
 @if defined(Z180)
@@ -333,9 +334,9 @@

 Addr16: imm16  is imm16      { export *:1 imm16; }

-Mem8: (imm16)  is imm16    { export *:1 imm16; }
+Mem8: (imm16)  is imm16    { export *[data]:1 imm16; }

-Mem16: (imm16)  is imm16     { export *:2 imm16; }
+Mem16: (imm16)  is imm16     { export *[data]:2 imm16; }

 @endif
```

