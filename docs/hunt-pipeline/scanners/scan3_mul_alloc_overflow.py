import re, os, sys
# The shape behind videocodec, vox_loader and speech Criticals:
# an allocation size built from a MULTIPLICATION whose operands are int/short-typed,
# so the product wraps before it reaches malloc.
alloc = re.compile(r'(?:[A-Z_]*MALLOC|malloc|calloc|realloc)\s*\(\s*([^;]{4,160}?)\)\s*[;,)]')
mul   = re.compile(r'\*')
roots = sys.argv[1:]
hits = []
for root in roots:
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in ('.git','node_modules','test','tests','build','corpus','artifacts','artifacts2','findings','findings2','doc','docs')]
        for fn in fns:
            if not fn.endswith(('.c','.h','.cpp','.cc')): continue
            p = os.path.join(dp, fn)
            try: src = open(p, errors='ignore').read()
            except: continue
            if len(src) > 4_000_000: continue
            lines = src.split('\n')
            for m in alloc.finditer(src):
                expr = m.group(1)
                if expr.count('*') < 2: continue          # need >=2 multiplications
                if 'sizeof' in expr and expr.count('*') < 2: continue
                ln = src[:m.start()].count('\n') + 1
                # look back for int-typed declarations of the operands
                names = set(re.findall(r'[A-Za-z_]\w*', expr)) - {'sizeof','char','int','unsigned','long','size_t','void'}
                window = '\n'.join(lines[max(0,ln-40):ln])
                narrow = [n for n in names
                          if re.search(r'\b(?:int|short|int32_t|int16_t|uint32_t|unsigned int)\s+(?:\w+\s*,\s*)*'+re.escape(n)+r'\b', window)]
                if narrow:
                    hits.append((p, ln, expr.strip()[:95], ','.join(sorted(narrow)[:4])))
print(f"=== allocation size from a multiplication with narrow (int-width) operands: {len(hits)} hits ===")
seen=set()
for p,ln,expr,nar in hits:
    k=(p,expr)
    if k in seen: continue
    seen.add(k)
    print(f"{p}:{ln}\n    size : {expr}\n    int-typed operands: {nar}")
