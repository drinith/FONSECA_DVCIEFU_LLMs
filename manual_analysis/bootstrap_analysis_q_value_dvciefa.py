"""
Teste de Diferença via Bootstrap — Gemini vs GPT-4  (versão final)
Artigo: Detecção de Vulnerabilidades em Smart Contracts com LLMs
Autores: Felipe Mello Fonseca, Pedro Henrique Gonzalez, Diogo Silveira Mendonça

Correções em relação à versão centralizada anterior:
─────────────────────────────────────────────────────

1. build_per_file — cobertura de arquivos FP-only (BUG CORRIGIDO)
   ANTES:  todos = df_tp['Arquivos'].dropna().unique()
           → arquivos que geraram apenas FPs (sem nenhum TP) eram ignorados,
             subestimando os falsos positivos desses arquivos.
   AGORA:  todos = pd.concat([df_tp['Arquivos'], df_fp['Arquivos']]).dropna().unique()
           → todos os arquivos com qualquer ocorrência (TP ou FP) são incluídos.

2. Correção de múltiplos testes — Benjamini-Hochberg (ADICIONADO)
   Como o teste é aplicado a 9 vulnerabilidades simultaneamente, a taxa de
   falsos positivos acumulada pode ser elevada. Aplica-se o procedimento de
   Benjamini-Hochberg (BH) para controlar a False Discovery Rate (FDR) a 5%.
   Referência: Benjamini & Hochberg (1995), JRSS-B.
   A coluna 'sig_bh' indica significância após correção BH.
   A coluna 'sig_raw' indica significância sem correção (para comparação).
   A coluna 'q_valor' contém o p-value ajustado (q-value), permitindo ao
   leitor avaliar a "distância" de cada vulnerabilidade do limiar de FDR.

   Nota: optou-se por BH (FDR) em vez de Bonferroni (FWER) porque o objetivo
   é detectar diferenças reais entre modelos, não controlar erros tipo I de
   forma ultra-conservadora. Para 9 testes independentes, Bonferroni reduziria
   o limiar a α=0.0056, o que pode ser excessivamente restritivo.

p-value (mantido da versão anterior):
   Bootstrap PAREADO com p-value CENTRALIZADO sob H0.
   diffs_centradas = (f1_g4 - f1_g) - mean(f1_g4 - f1_g)
   p_val = (diffs_centradas >= diff_obs).mean()
   H1 unilateral: GPT-4 > Gemini

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
    """
    Constrói DataFrame com uma linha por arquivo contendo:
        tp  = verdadeiros positivos detectados nesse arquivo
        fp  = falsos positivos detectados nesse arquivo
        gab = total de ocorrências no gabarito para esse arquivo

    CORREÇÃO: inclui arquivos que aparecem APENAS no FP (sem nenhum TP).
    Na versão anterior, esses arquivos eram ignorados, subestimando FPs.
    """
    # ── CORREÇÃO: união de arquivos de TP e FP ────────────────────────────────
    todos = pd.concat([
        df_tp['Arquivos'],
        df_fp['Arquivos']
    ]).dropna().unique()

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
    """Calcula F1 a partir de arrays agregados."""
    tp  = tp_arr.sum()
    fp  = fp_arr.sum()
    gab = gab_arr.sum()
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / gab       if gab > 0       else 0.0
    return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0


def bootstrap_paired(df_gemini, df_gpt4, n=N_BOOTSTRAP):
    """
    Bootstrap PAREADO com p-value CENTRALIZADO sob H0.

    Em cada iteração, o MESMO conjunto de índices de arquivo é sorteado
    para ambos os modelos, isolando a diferença entre eles da variabilidade
    amostral (Koehn, 2004).

    p-value centralizado:
        diffs_centradas = (f1_g4 - f1_g) - mean(f1_g4 - f1_g)
        p_val = P(diffs_centradas >= diff_obs | H0)
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
        idx      = np.random.choice(N, N, replace=True)
        f1_g[b]  = f1_from_arrays(tp_g[idx],  fp_g[idx],  gab_g[idx])
        f1_g4[b] = f1_from_arrays(tp_g4[idx], fp_g4[idx], gab_g4[idx])

    # p-value centralizado sob H0: diff = 0
    diffs           = f1_g4 - f1_g
    diffs_centradas = diffs - diffs.mean()
    diff_obs        = obs_g4 - obs_g
    p_val           = float((diffs_centradas >= diff_obs).mean())

    return obs_g, obs_g4, f1_g, f1_g4, p_val


def benjamini_hochberg(p_values, alpha=ALPHA):
    """
    Correção de Benjamini-Hochberg para múltiplos testes (FDR).
    Referência: Benjamini & Hochberg (1995), JRSS-B 57(1):289-300.

    Retorna
    ───────
    rejeita  : array booleano — quais hipóteses são rejeitadas após BH.
    q_values : array de p-values ajustados (q-values).
               q = p * (m / rank), com enforçamento de monotonicidade.
               Permite ao leitor ver quão longe cada teste ficou do limiar.
    """
    p_values = np.array(p_values)
    n        = len(p_values)
    ordem    = np.argsort(p_values)
    p_sorted = p_values[ordem]

    # ── Rejeição ──────────────────────────────────────────────────────────────
    limiares   = (np.arange(1, n + 1) / n) * alpha
    rejeita    = np.zeros(n, dtype=bool)
    candidatos = np.where(p_sorted <= limiares)[0]
    if len(candidatos) > 0:
        k_max = candidatos[-1]
        rejeita[ordem[:k_max + 1]] = True

    # ── Q-values (p-values ajustados) ─────────────────────────────────────────
    # Fórmula: q_i = p_i * (m / rank_i)
    q_sorted = p_sorted * (n / np.arange(1, n + 1))

    # Enforça monotonicidade: q_i <= q_{i+1}
    for i in range(n - 2, -1, -1):
        q_sorted[i] = min(q_sorted[i], q_sorted[i + 1])

    q_sorted = np.clip(q_sorted, 0.0, 1.0)

    q_values        = np.zeros(n)
    q_values[ordem] = q_sorted

    return rejeita, q_values


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
resultados = []

for v in VULNS:
    df_gem_files = build_per_file(gemini_tp, gemini_fp, df_gab_raw, v)
    df_g4_files  = build_per_file(gpt4_tp,   gpt4_fp,  df_gab_raw, v)

    obs_g, obs_g4, f1_g, f1_g4, p_val = bootstrap_paired(df_gem_files, df_g4_files)

    lo_g,  hi_g  = np.percentile(f1_g,  [2.5, 97.5])
    lo_g4, hi_g4 = np.percentile(f1_g4, [2.5, 97.5])

    resultados.append({
        'vulnerabilidade': v,
        'f1_gemini':       obs_g,
        'ic95_gem_inf':    lo_g,
        'ic95_gem_sup':    hi_g,
        'f1_gpt4':         obs_g4,
        'ic95_g4_inf':     lo_g4,
        'ic95_g4_sup':     hi_g4,
        'p_valor':         p_val,
    })

# ── Correção de múltiplos testes (Benjamini-Hochberg) ────────────────────────
p_values             = [r['p_valor'] for r in resultados]
rejeita_bh, q_values = benjamini_hochberg(p_values, alpha=ALPHA)

for i, r in enumerate(resultados):
    r['sig_raw'] = r['p_valor'] < ALPHA
    r['sig_bh']  = bool(rejeita_bh[i])
    r['q_valor'] = round(float(q_values[i]), 3)

# ── Impressão ─────────────────────────────────────────────────────────────────
print(f"\nBootstrap pareado — p-value CENTRALIZADO — {N_BOOTSTRAP} reamostras (seed=42)")
print(f"Correção de múltiplos testes: Benjamini-Hochberg (FDR = {ALPHA})")
print("=" * 108)
COL = "{:<22} {:>10} {:>18}  {:>10} {:>18}  {:>7}  {:>7}  {:<3}  {:<3}"
print(COL.format(
    'Vulnerabilidade',
    'Gemini F1', 'IC95% Gem',
    'GPT-4 F1',  'IC95% GPT4',
    'p-val', 'q-val', 'raw', 'BH'
))
print("-" * 108)

for r in resultados:
    raw = '*' if r['sig_raw'] else ' '
    bh  = '*' if r['sig_bh']  else ' '
    ic_gem  = f"[{r['ic95_gem_inf']*100:5.1f}; {r['ic95_gem_sup']*100:5.1f}]"
    ic_gpt4 = f"[{r['ic95_g4_inf']*100:5.1f}; {r['ic95_g4_sup']*100:5.1f}]"
    print(COL.format(
        r['vulnerabilidade'],
        f"{r['f1_gemini']*100:.1f}", ic_gem,
        f"{r['f1_gpt4']*100:.1f}",  ic_gpt4,
        f"{r['p_valor']:.3f}",
        f"{r['q_valor']:.3f}",
        raw, bh
    ))

print("-" * 108)
print(f"p-val: bruto  |  q-val: p ajustado BH (q-value)  |  raw: p<{ALPHA}  |  BH: sig. após FDR")
print(f"H1: GPT-4 > Gemini (unilateral)\n")

# ── Exportar CSV ──────────────────────────────────────────────────────────────
df_res = pd.DataFrame(resultados)
df_res['f1_gemini']    = df_res['f1_gemini'].apply(lambda x: round(x * 100, 1))
df_res['ic95_gem_inf'] = df_res['ic95_gem_inf'].apply(lambda x: round(x * 100, 1))
df_res['ic95_gem_sup'] = df_res['ic95_gem_sup'].apply(lambda x: round(x * 100, 1))
df_res['f1_gpt4']      = df_res['f1_gpt4'].apply(lambda x: round(x * 100, 1))
df_res['ic95_g4_inf']  = df_res['ic95_g4_inf'].apply(lambda x: round(x * 100, 1))
df_res['ic95_g4_sup']  = df_res['ic95_g4_sup'].apply(lambda x: round(x * 100, 1))
df_res['p_valor']      = df_res['p_valor'].apply(lambda x: round(x, 3))
# q_valor já está arredondado em 3 casas na geração

df_res.to_csv('bootstrap_resultados_final_DVCIEFA.csv', index=False)
print("Resultados salvos em: bootstrap_resultados_final_DVCIEFA.csv")