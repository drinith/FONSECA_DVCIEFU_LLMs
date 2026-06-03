"""
Teste de Diferença via Bootstrap — Gemini vs GPT-4
Artigo: Detecção de Vulnerabilidades em Smart Contracts com LLMs
Autores: Felipe Mello Fonseca, Pedro Henrique Gonzalez, Diogo Silveira Mendonça

Método
──────
Bootstrap pareado com p-value centralizado sob H0.

Para cada vulnerabilidade:
  1. Constrói vetores de TP, FP e gabarito por arquivo para cada modelo.
  2. Roda 10.000 reamostras bootstrap PAREADAS: o MESMO conjunto de
     índices de arquivo é sorteado para os dois modelos em cada iteração,
     isolando a diferença entre eles da variabilidade amostral
     (Koehn, 2004; Dror et al., 2018).
  3. Calcula F1 agregado em cada reamostra (não a média de F1s por arquivo).
  4. p-value centralizado sob H0: diff = 0
       diffs           = F1_GPT4* − F1_Gemini*       (por reamostra)
       diffs_centradas = diffs − mean(diffs)          (impõe H0)
       diff_obs        = F1_GPT4_obs − F1_Gemini_obs  (dados reais)
       p = P(diffs_centradas ≥ diff_obs | H0)
     Centralizar é necessário porque o F1 agregado não é linear:
     a distribuição bootstrap das diferenças não é centrada em zero
     mesmo sob H0, e sem esse ajuste o p-value não tem a interpretação
     padrão de probabilidade sob a hipótese nula
     (Hall & Wilson, 1991; Efron & Tibshirani, 1993).
  5. IC 95% via percentis 2,5% e 97,5% das reamostras.

H0: F1(GPT-4) ≤ F1(Gemini)   (nenhuma diferença ou Gemini melhor)
H1: F1(GPT-4) > F1(Gemini)   (GPT-4 superior — unilateral)
α  = 0,05

Referências
───────────
Efron, B. & Tibshirani, R. J. (1993). An Introduction to the Bootstrap.
  CRC Press.
Hall, P. & Wilson, S. R. (1991). Two guidelines for bootstrap hypothesis
  testing. Biometrics, 47(2), 757–762.
Koehn, P. (2004). Statistical significance tests for machine translation
  evaluation. Proceedings of EMNLP.
Dror, R. et al. (2018). The hitchhiker's guide to testing statistical
  significance in NLP. Proceedings of ACL, 1383–1392.

Requisitos
──────────
    pip install pandas numpy openpyxl

Arquivos necessários (mesmo diretório)
───────────────────────────────────────
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

    Inclui arquivos que aparecem APENAS no FP (sem nenhum TP),
    evitando subestimação dos falsos positivos.
    """
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
    """F1 agregado a partir de arrays de TP, FP e gabarito."""
    tp  = tp_arr.sum()
    fp  = fp_arr.sum()
    gab = gab_arr.sum()
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / gab       if gab > 0       else 0.0
    return 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0


def bootstrap_paired(df_gemini, df_gpt4, n=N_BOOTSTRAP):
    """
    Bootstrap pareado com p-value centralizado sob H0.

    Retorna
    ───────
    obs_g   : F1 observado do Gemini (dados reais, sem reamostragem)
    obs_g4  : F1 observado do GPT-4
    f1_g    : array (n,) — F1 do Gemini em cada reamostra
    f1_g4   : array (n,) — F1 do GPT-4 em cada reamostra
    p_val   : p-value centralizado sob H0
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

    obs_g  = f1_from_arrays(tp_g,  fp_g,  gab_g)
    obs_g4 = f1_from_arrays(tp_g4, fp_g4, gab_g4)

    f1_g  = np.zeros(n)
    f1_g4 = np.zeros(n)
    for b in range(n):
        idx      = np.random.choice(N, N, replace=True)
        f1_g[b]  = f1_from_arrays(tp_g[idx],  fp_g[idx],  gab_g[idx])
        f1_g4[b] = f1_from_arrays(tp_g4[idx], fp_g4[idx], gab_g4[idx])

    diffs           = f1_g4 - f1_g
    diffs_centradas = diffs - diffs.mean()   # impõe H0: diff = 0
    diff_obs        = obs_g4 - obs_g
    p_val           = float((diffs_centradas >= diff_obs).mean())

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
print(f"\nBootstrap pareado — p-value centralizado — {N_BOOTSTRAP} reamostras (seed=42)")
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
        'vulnerabilidade': v,
        'f1_gemini':       round(obs_g,  1),
        'ic95_gem_inf':    round(lo_g,   1),
        'ic95_gem_sup':    round(hi_g,   1),
        'f1_gpt4':         round(obs_g4, 1),
        'ic95_g4_inf':     round(lo_g4,  1),
        'ic95_g4_sup':     round(hi_g4,  1),
        'p_valor':         round(p_val,  3),
        'significativo':   p_val < ALPHA,
    })

print("-" * 90)
print(f"* p < {ALPHA}  |  H1: F1(GPT-4) > F1(Gemini), unilateral\n")

# ── Exportar CSV ──────────────────────────────────────────────────────────────
df_res = pd.DataFrame(resultados)
df_res.to_csv('bootstrap_resultados_DVCIEFA.csv', index=False)
print("Resultados salvos em: bootstrap_resultados_DVCIEFA.csv")
