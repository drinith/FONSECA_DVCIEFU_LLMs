"""
Análise Estatística via Bootstrap por Arquivo
Artigo: Detecção de Vulnerabilidades em Smart Contracts com LLMs
Autores: Felipe Mello Fonseca, Pedro Henrique Gonzalez, Diogo Silveira Mendonça
"""

import pandas as pd
import numpy as np
import openpyxl

# ── Configuração ──────────────────────────────────────────────────────────────
np.random.seed(42)
N_BOOTSTRAP = 10000

VULNS = [
    'REENTRANCY', 'ACCESS_CONTROL', 'ARITHMETIC', 'UNCHECKED_LL_CALLS',
    'DENIAL_OF_SERVICE', 'BAD_RANDOMNESS', 'FRONT_RUNNING',
    'TIME_MANIPULATION', 'SHORT_ADDRESSES'
]

PATH_GEMINI_TP = 'gemini_TP.xlsx'
PATH_GEMINI_FP = 'gemini_FP.xlsx'
PATH_GPT4_TP   = 'gpt4_TP.xlsx'
PATH_GPT4_FP   = 'gpt4_FP.xlsx'
PATH_GABARITO  = 'gabarito.csv'

PATH_OUTPUT_CSV = 'bootstrap_resultados.csv'

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


def bootstrap_f1_por_arquivo(df_files, n=N_BOOTSTRAP):
    """
    Bootstrap por arquivo — denominador do recall recalculado a cada
    reamostra a partir dos arquivos sorteados (consistente com o numerador).
    """
    if len(df_files) == 0:
        return 0.0, 0.0, 0.0

    arr_tp  = df_files['tp'].values
    arr_fp  = df_files['fp'].values
    arr_gab = df_files['gab'].values
    n_arq   = len(arr_tp)

    f1s = []
    for _ in range(n):
        idx   = np.random.choice(n_arq, n_arq, replace=True)
        tp_b  = arr_tp[idx].sum()
        fp_b  = arr_fp[idx].sum()
        gab_b = arr_gab[idx].sum()

        prec = tp_b / (tp_b + fp_b) if (tp_b + fp_b) > 0 else 0
        rec  = tp_b / gab_b         if gab_b > 0          else 0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
        f1s.append(f1)

    f1s = np.array(f1s)
    return (float(np.mean(f1s) * 100),
            float(np.percentile(f1s, 2.5) * 100),
            float(np.percentile(f1s, 97.5) * 100))


# ── Carregamento dos dados ────────────────────────────────────────────────────
df_gab_raw = pd.read_csv(PATH_GABARITO)
df_gab_raw['Vulnerabilidade'] = (
    df_gab_raw['Vulnerabilidade'].str.strip().str.replace(' ', '_').str.upper()
)

gemini_tp = load_sheet(PATH_GEMINI_TP)
gemini_fp = load_sheet(PATH_GEMINI_FP)
gpt4_tp   = load_sheet(PATH_GPT4_TP)
gpt4_fp   = load_sheet(PATH_GPT4_FP)

# ── Cálculo ───────────────────────────────────────────────────────────────────
print(f"\nBootstrap por arquivo — {N_BOOTSTRAP} reamostras (seed=42)")
print("Calculando...")

linhas = []
for v in VULNS:
    for modelo, tp, fp in [('Gemini', gemini_tp, gemini_fp),
                            ('GPT-4',  gpt4_tp,   gpt4_fp)]:
        df_files = build_per_file(tp, fp, df_gab_raw, v)
        m, lo, hi = bootstrap_f1_por_arquivo(df_files)
        linhas.append({
            'vulnerabilidade': v,
            'modelo':          modelo,
            'f1_pct':          round(m, 1),
            'ic95_inf':        round(lo, 1),
            'ic95_sup':        round(hi, 1),
        })

# ── Salvar CSV ────────────────────────────────────────────────────────────────
df_resultado = pd.DataFrame(linhas)
df_resultado.to_csv(PATH_OUTPUT_CSV, index=False)

print(f"\nResultados salvos em: {PATH_OUTPUT_CSV}")
print(df_resultado.to_string(index=False))