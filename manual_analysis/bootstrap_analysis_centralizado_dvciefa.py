"""
Teste de Diferença via Bootstrap — Gemini vs GPT-4  (p-value CENTRALIZADO)
Artigo: Detecção de Vulnerabilidades em Smart Contracts com LLMs
Autores: Felipe Mello Fonseca, Pedro Henrique Gonzalez, Diogo Silveira Mendonça

O que mudou em relação à versão anterior:
─────────────────────────────────────────
VERSÃO ANTERIOR (não centralizada):
    p_val = (f1_g4 <= f1_g).mean()
    → Conta quantas reamostras o GPT-4 ficou abaixo do Gemini.
    → NÃO testa H0: diff = 0, porque a distribuição de diferenças
      não é deslocada para zero. O resultado depende do viés amostral
      e não tem a interpretação padrão de p-value.

ESTA VERSÃO (centralizada — forma padrão):
    diffs = f1_g4 - f1_g                     # diferença em cada reamostra
    diffs_centradas = diffs - diffs.mean()    # desloca para média zero (H0)
    diff_obs = obs_g4 - obs_g                 # diferença nos dados reais
    p_val = (diffs_centradas >= diff_obs).mean()
    → Pergunta: "sob H0 (diff=0), qual a prob. de ver uma diferença
      tão grande quanto a observada apenas por acaso?"
    → Interpretação padrão de p-value unilateral.

Por que centralizar?
    O bootstrap gera uma distribuição da diferença deslocada pelo valor
    amostral real. Para testar H0: diff = 0, precisamos referenciar essa
    distribuição em zero — isso é o que a centralização faz.
    Sem isso, o p-value reflete a posição relativa das distribuições
    brutas, não a probabilidade sob H0.

Requisitos:
    pip install pandas numpy openpyxl

Arquivos necessários (mesmo diretório):
    gemini_TP.xlsx, gemini_FP.xlsx, gpt4_TP.xlsx, gpt4_FP.xlsx, gabarito.csv
"""

import pandas as pd
import numpy as np
import openpyxl

# ── Configuração ──────────────────────────────────────────────────────────────
np.random.seed(42)
N_BOOTSTRAP = 10_000
ALPHA       = 0.05

VULNS = [
    'REENTRANCY', 'ACCESS_CONTROL', 'ARITHMETIC', 'UNCHECKED_LL_CALLS',
    'DENIAL_OF_SERVICE', 'BAD_RANDOMNESS', 'FRONT_RUNNING',
    'TIME_MANIPULATION', 'SHORT_ADDRESSES'
]

# ── Funções auxiliares ────────────────────────────────────────────────────────
def load_sheet(path):
    wb = openpyxl.load_workbook(path, read_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    return pd.DataFrame(rows[1:], columns=rows[0])


def normalize(name):
    return str(name).replace('.txt', '').replace('.sol', '').strip()


def build_per_file(df_tp, df_fp, df_gab_raw, vuln):
    todos = df_tp['Arquivos'].dropna().unique()

    tp_map = {}
    if vuln in df_tp.columns:
        for _, row in df_tp.iterrows():
            val = pd.to_numeric(row[vuln], errors='coerce')
            if pd.notna(val) and val > 0:
                k = normalize(row['Arquivos'])
                tp_map[k] = tp_map.get(k, 0) + int(val)

    fp_map = {}
    if vuln in df_fp.columns:
        for _, row in df_fp.iterrows():
            val = pd.to_numeric(row[vuln], errors='coerce')
            if pd.notna(val) and val > 0:
                k = normalize(row['Arquivos'])
                fp_map[k] = fp_map.get(k, 0) + int(val)

    gab_map = (df_gab_raw[df_gab_raw['Vulnerabilidade'] == vuln]
               .assign(key=lambda d: d['Arquivo'].apply(normalize))
               .groupby('key').size().to_dict())

    registros = []
    for arq in todos:
        k = normalize(arq)
        registros.append({
            'arquivo': k,
            'tp':  tp_map.get(k, 0),
            'fp':  fp_map.get(k, 0),
            'gab': gab_map.get(k, 0),
        })

    return pd.DataFrame(registros)


def f1_from_arrays(tp_arr, fp_arr, gab_arr):
    tp  = tp_arr.sum()
    fp  = fp_arr.sum()
    gab = gab_arr.sum()
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / gab       if gab > 0       else 0.0
    return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0


def bootstrap_paired(df_gemini, df_gpt4, n=N_BOOTSTRAP):
    """
    Bootstrap PAREADO com p-value CENTRALIZADO sob H0.

    Diferença da versão anterior
    ────────────────────────────
    Antes:  p_val = (f1_g4 <= f1_g).mean()
            → compara distribuições brutas, sem referenciar H0: diff = 0

    Agora:  diffs_centradas = (f1_g4 - f1_g) - mean(f1_g4 - f1_g)
            p_val = (diffs_centradas >= diff_obs).mean()
            → distribui a diferença em torno de zero (H0) e mede
              qual proporção supera a diferença observada nos dados reais
    """
    todos   = sorted(set(df_gemini['arquivo']) | set(df_gpt4['arquivo']))
    idx_map = {a: i for i, a in enumerate(todos)}
    N       = len(todos)

    def to_arrays(df):
        tp  = np.zeros(N)
        fp  = np.zeros(N)
        gab = np.zeros(N)
        for _, row in df.iterrows():
            i = idx_map.get(row['arquivo'])
            if i is not None:
                tp[i]  = row['tp']
                fp[i]  = row['fp']
                gab[i] = row['gab']
        return tp, fp, gab

    tp_g,  fp_g,  gab_g  = to_arrays(df_gemini)
    tp_g4, fp_g4, gab_g4 = to_arrays(df_gpt4)

    # F1 observado nos dados reais
    obs_g  = f1_from_arrays(tp_g,  fp_g,  gab_g)
    obs_g4 = f1_from_arrays(tp_g4, fp_g4, gab_g4)

    # Reamostras pareadas
    f1_g  = np.zeros(n)
    f1_g4 = np.zeros(n)
    for b in range(n):
        idx       = np.random.choice(N, N, replace=True)
        f1_g[b]  = f1_from_arrays(tp_g[idx],  fp_g[idx],  gab_g[idx])
        f1_g4[b] = f1_from_arrays(tp_g4[idx], fp_g4[idx], gab_g4[idx])

    # ── p-value CENTRALIZADO (forma padrão) ──────────────────────────────────
    # 1. Distribuição das diferenças nas reamostras
    diffs = f1_g4 - f1_g

    # 2. Centraliza sob H0: diff = 0
    diffs_centradas = diffs - diffs.mean()

    # 3. Diferença observada nos dados reais
    diff_obs = obs_g4 - obs_g

    # 4. p-value unilateral: P(diff >= diff_obs | H0)
    p_val = float((diffs_centradas >= diff_obs).mean())

    return obs_g, obs_g4, f1_g, f1_g4, p_val


# ── Carregamento ──────────────────────────────────────────────────────────────
df_gab_raw = pd.read_csv('gabarito.csv')
df_gab_raw['Vulnerabilidade'] = (
    df_gab_raw['Vulnerabilidade'].str.strip().str.replace(' ', '_').str.upper()
)

gemini_tp = load_sheet('gemini_TP.xlsx')
gemini_fp = load_sheet('gemini_FP.xlsx')
gpt4_tp   = load_sheet('gpt4_TP.xlsx')
gpt4_fp   = load_sheet('gpt4_FP.xlsx')

# ── Cálculo ───────────────────────────────────────────────────────────────────
print(f"\nBootstrap pareado — p-value CENTRALIZADO — {N_BOOTSTRAP} reamostras (seed=42)")
print("=" * 90)
print(f"{'Vulnerabilidade':<22} "
      f"{'Gemini F1':>10} {'IC95% Gem':>18}  "
      f"{'GPT-4 F1':>10} {'IC95% GPT4':>18}  "
      f"{'p-val':>7}  {'sig':>4}")
print("-" * 90)

resultados = []

for v in VULNS:
    df_gem_files = build_per_file(gemini_tp, gemini_fp, df_gab_raw, v)
    df_g4_files  = build_per_file(gpt4_tp,   gpt4_fp,  df_gab_raw, v)

    obs_g, obs_g4, f1_g, f1_g4, p_val = bootstrap_paired(df_gem_files, df_g4_files)

    obs_g  *= 100
    obs_g4 *= 100

    lo_g,  hi_g  = np.percentile(f1_g,  [2.5, 97.5]) * 100
    lo_g4, hi_g4 = np.percentile(f1_g4, [2.5, 97.5]) * 100

    sig = "*" if p_val < ALPHA else ""

    print(f"{v:<22} "
          f"{obs_g:>10.1f} [{lo_g:>5.1f}; {hi_g:>5.1f}]  "
          f"{obs_g4:>10.1f} [{lo_g4:>5.1f}; {hi_g4:>5.1f}]  "
          f"{p_val:>7.3f}  {sig:>4}")

    resultados.append({
        'vulnerabilidade':  v,
        'f1_gemini':        round(obs_g,  1),
        'ic95_gem_inf':     round(lo_g,   1),
        'ic95_gem_sup':     round(hi_g,   1),
        'f1_gpt4':          round(obs_g4, 1),
        'ic95_g4_inf':      round(lo_g4,  1),
        'ic95_g4_sup':      round(hi_g4,  1),
        'p_valor':          round(p_val,  3),
        'significativo':    p_val < ALPHA,
    })

print("-" * 90)
print(f"* p < {ALPHA} (H1: GPT-4 > Gemini, unilateral, p-value centralizado sob H0)\n")

# ── Exportar CSV ──────────────────────────────────────────────────────────────
df_res = pd.DataFrame(resultados)
df_res.to_csv('bootstrap_resultados_centralizado_DVCIEFA.csv', index=False)
print("Resultados salvos em: bootstrap_resultados_centralizado_DVCIEFA.csv")