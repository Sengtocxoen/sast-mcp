import re, os, sys
roots = sys.argv[1:]
castbound = re.compile(r'([\w\->\.]+)\s*=\s*\(\s*(?:int|short|signed|int32_t|int16_t)\s*\)\s*([^;]{0,80}?(?:size|len|count|Size|Len|Count)[^;]{0,40})\s*;')
out=[]
for root in roots:
    for dp,dn,fns in os.walk(root):
        dn[:] = [d for d in dn if d not in ('.git','node_modules','test','tests','build','corpus')]
        for fn in fns:
            if not fn.endswith(('.c','.h','.cc','.cpp')): continue
            p=os.path.join(dp,fn)
            try: src=open(p,errors='ignore').read()
            except: continue
            if len(src) > 3_000_000: continue
            lines=src.split('\n')
            for m in castbound.finditer(src):
                var=m.group(1).strip(); ln=src[:m.start()].count('\n')+1
                window='\n'.join(lines[ln:ln+50])
                c=re.search(re.escape(var)+r'\s*(?:>|>=)\s*([A-Za-z_][\w\->\.]*)', window)
                if c:
                    name=c.group(1).lower()
                    if any(k in name for k in ('cap','avail','max','size','len','remain','left','buf','limit','end')):
                        out.append((p,ln,lines[ln-1].strip()[:100],c.group(0)[:48]))
print(f"=== narrowing cast on a parsed size, later used as a SIGNED bound: {len(out)} hits ===")
seen=set()
for p,ln,code,cmp in out:
    k=(p,code)
    if k in seen: continue
    seen.add(k)
    print(f"{p}:{ln}\n    cast : {code}\n    bound: {cmp}")
