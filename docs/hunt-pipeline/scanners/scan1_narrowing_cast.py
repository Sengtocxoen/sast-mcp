import re, sys, os
# Shape A (paldither): malloc(X) then a copy to an OFFSET destination with length X.
alloc_re = re.compile(r'(\w+)\s*=\s*\(?[\w\s\*]*\)?\s*(?:\w*MALLOC|malloc|calloc|realloc)\s*\(\s*([^;]*?)\)\s*;')
copy_re  = re.compile(r'(?:memcpy|memmove)\s*\(\s*(&?[\w\->\.\[\]]+)\s*\+\s*([^,]+),([^;]*);|'
                      r'(?:memcpy|memmove)\s*\(\s*&\s*([\w\->\.]+)\s*->\s*(\w+)\s*,([^;]*);')
# Shape B (assetsys): narrowing cast of a parsed size, later used as a signed bound.
castbound_re = re.compile(r'(\w[\w\->\.]*)\s*=\s*\(\s*(?:int|short|signed)\s*\)\s*([\w\->\.\(\)]*(?:size|len|count|Size|Len|Count)[\w\->\.\(\)]*)')

hits=[]
for root,dirs,files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in ('.git','node_modules','artifacts','corpus','build')]
    for fn in files:
        if not fn.endswith(('.c','.h','.cc','.cpp')): continue
        p=os.path.join(root,fn)
        try: src=open(p,errors='ignore').read()
        except: continue
        lines=src.split('\n')
        # Shape B: cast then signed comparison on the same variable
        for m in castbound_re.finditer(src):
            var=m.group(1); ln=src[:m.start()].count('\n')+1
            tail='\n'.join(lines[ln:ln+60])
            cmp_m=re.search(re.escape(var)+r'\s*>\s*(\w*(?:capacity|cap|avail|max|size|buf|remaining|left)\w*)', tail)
            if cmp_m:
                hits.append(('B', p, ln, lines[ln-1].strip()[:110], cmp_m.group(0)[:50]))
print(f"=== Shape B: narrowing cast on a parsed size, later used as a SIGNED bound ({len([h for h in hits if h[0]=='B'])}) ===")
for h in hits:
    if h[0]=='B': print(f"  {h[1]}:{h[2]}\n      cast : {h[3]}\n      bound: {h[4]}")
