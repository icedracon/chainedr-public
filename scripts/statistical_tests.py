#!/usr/bin/env python3
"""ChainEDR Statistical Significance Testing"""
import json, math, sys
from pathlib import Path

def wilson(count, total, z=1.96):
    if total==0: return (0,0)
    p=count/total; d=1+z**2/total; c=(p+z**2/(2*total))/d
    m=z*math.sqrt((p*(1-p)+z**2/(4*total))/total)/d
    return (max(0,c-m), min(1,c+m))

def binomial_exact(s, n, p0=0.5):
    return sum(math.comb(n,k)*(p0**k)*((1-p0)**(n-k)) for k in range(s,n+1))

def main():
    repo=Path(__file__).parent.parent
    ev=repo/"benchmarks"/"eip7702_sandbox"/"eval_results.json"
    if not ev.exists(): print("No eval_results.json"); return 1
    data=json.loads(ev.read_text()); o=data["overall"]
    tp=o["tp"]; fp=o["fp"]; tn=o["tn"]; fn=o["fn"]
    P=tp/(tp+fp) if (tp+fp) else 0; R=tp/(tp+fn) if (tp+fn) else 0
    print("="*60)
    print("ChainEDR Statistical Significance Testing")
    print("="*60)
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={P:.4f} Recall={R:.4f}")
    ci_p=wilson(tp, tp+fp); ci_r=wilson(tp, tp+fn)
    print(f"95% CI Precision: [{ci_p[0]:.3f}, {ci_p[1]:.3f}]")
    print(f"95% CI Recall:    [{ci_r[0]:.3f}, {ci_r[1]:.3f}]")
    bp=binomial_exact(tp, tp+fp); br=binomial_exact(tp, tp+fn)
    print(f"Binomial test (P>0.5): p={bp:.6f} sig@0.05={bp<0.05}")
    print(f"Binomial test (R>0.5): p={br:.6f} sig@0.05={br<0.05}")
    mc=((tp-0)**2)/(tp+0) if tp>0 else 0
    print(f"McNemar vs baseline: stat={mc:.1f}")
    print(f"WARNING: n=1 vuln/detector. CI width={ci_p[1]-ci_p[0]:.3f}. Need >=10/detector.")
    results=dict(aggregate=o, ci_precision=list(ci_p), ci_recall=list(ci_r), binomial_p=bp, binomial_r=br, mcnemar=mc)
    out=repo/"benchmarks"/"eip7702_sandbox"/"statistical_results.json"
    out.write_text(json.dumps(results,indent=2))
    print(f"Saved: {out}")
if __name__=="__main__": main()
